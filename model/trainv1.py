"""
Two-stage ML NIDS training pipeline (NetFlow features, e.g. NF-UQ-NIDS-v2).

  Stage 1: binary classifier      -> benign vs attack
  Stage 2: multiclass classifier  -> which attack (trained on attack flows only)

Pipeline
  1. prepare_shards()   clean each raw CSV once, dedup, split train/val/test,
                        write Parquet + a manifest with global counts
  2. train_stage1()     one model over ALL shards (streamed via DataIter,
                        no shard-by-shard tree stacking), early stopping on val,
                        threshold picked for a target false-positive rate
  3. train_stage2()     attack-type model on attack rows only
  4. evaluate_*()       global test set across every shard, per-source breakdown,
                        and an end-to-end stage1 -> stage2 evaluation
  5. cross_dataset_eval() (optional) leave-one-source-dataset-out for stage 1

Usage
  python nids_train.py --csv /mnt/8tb_hdd/harish/ds2/splited/dataset*.csv \
      --work-dir /mnt/8tb_hdd/harish/ds2/nids_work --device cuda
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, average_precision_score, classification_report,
    confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    work_dir: str = "nids_work"

    # Columns
    label_col: str = "Label"
    attack_col: str = "Attack"
    source_col: str = "Dataset"
    id_cols: list = field(default_factory=lambda: ["IPV4_SRC_ADDR", "IPV4_DST_ADDR"])
    # Ports often leak testbed identity; drop by default, set [] to keep them.
    leaky_cols: list = field(default_factory=lambda: ["L4_SRC_PORT", "L4_DST_PORT"])

    # Splitting / cleaning
    val_frac: float = 0.1
    test_frac: float = 0.1
    seed: int = 42
    dedup: bool = True
    clip_value: float = 1e8

    # Hardware / data loading
    device: str = "cpu"            # "cuda" if you have a GPU
    nthread: int = -1
    external_memory: bool = False  # True -> ExtMemQuantileDMatrix (XGBoost >= 3.0)

    # Stage 1
    s1_params: dict = field(default_factory=lambda: dict(
        objective="binary:logistic", eval_metric=["aucpr", "auc"],
        max_depth=8, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
        reg_alpha=0.1, reg_lambda=1.0, max_bin=256, tree_method="hist",
    ))
    s1_rounds: int = 2000
    s1_early_stop: int = 50
    target_fpr: float = 0.001      # pick threshold so ~0.1% of benign flows alert

    # Stage 2
    s2_params: dict = field(default_factory=lambda: dict(
        objective="multi:softprob", eval_metric="mlogloss",
        max_depth=8, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
        reg_lambda=1.0, max_bin=256, tree_method="hist",
    ))
    s2_rounds: int = 2000
    s2_early_stop: int = 50
    min_class_count: int = 200     # rarer attack classes merged into "other"
    max_class_weight: float = 50.0 # cap on balanced class weights

    verbose_eval: int = 50


def _drop_cols(cfg: Config) -> list:
    return cfg.id_cols + cfg.leaky_cols + [cfg.label_col, cfg.attack_col, cfg.source_col]


def _xgb_params(base: dict, cfg: Config) -> dict:
    p = dict(base)
    p["device"] = cfg.device
    p["nthread"] = cfg.nthread
    p["seed"] = cfg.seed
    return p


# --------------------------------------------------------------------------- #
# 1. Data preparation
# --------------------------------------------------------------------------- #
def clean_features(X: pd.DataFrame, clip_value: float) -> pd.DataFrame:
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X.clip(lower=-clip_value, upper=clip_value)
    return X.astype(np.float32)


def normalise_attack(s: pd.Series) -> pd.Series:
    # Merged datasets spell the same class differently ("DoS" vs "dos ").
    return s.astype(str).str.strip().str.lower()


def _stratified_assign(groups: pd.Series, val_frac: float, test_frac: float,
                       rng: np.random.Generator) -> np.ndarray:
    """Return array of 0=train, 1=val, 2=test, stratified on `groups`."""
    split = np.zeros(len(groups), dtype=np.int8)
    for _, idx in groups.groupby(groups, sort=False).indices.items():
        idx = rng.permutation(idx)
        n = len(idx)
        n_test = int(round(n * test_frac))
        n_val = int(round(n * val_frac))
        split[idx[:n_test]] = 2
        split[idx[n_test:n_test + n_val]] = 1
    return split


def prepare_shards(csv_paths: list, cfg: Config) -> dict:
    """Clean + split each raw CSV once, write Parquet, and build a manifest."""
    rng = np.random.default_rng(cfg.seed)
    split_names = ["train", "val", "test"]
    for s in split_names:
        os.makedirs(os.path.join(cfg.work_dir, s), exist_ok=True)

    features = None
    manifest = {"features": None, "splits": {s: [] for s in split_names},
                "counts": {s: {"label": {}, "attack": {}, "source_label": {}} for s in split_names}}
    dup_removed = 0

    for i, path in enumerate(csv_paths):
        print(f"[prepare] {i + 1}/{len(csv_paths)}  {path}")
        df = pd.read_csv(path, low_memory=False)

        if features is None:
            drop = set(_drop_cols(cfg))
            features = [c for c in df.columns if c not in drop]
            manifest["features"] = features
        missing = [c for c in features if c not in df.columns]
        if missing:
            raise ValueError(f"{path} is missing feature columns: {missing}")

        X = clean_features(df[features], cfg.clip_value)
        out = X
        out[cfg.label_col] = df[cfg.label_col].astype(np.int8).values
        out[cfg.attack_col] = normalise_attack(df[cfg.attack_col]).values
        out[cfg.source_col] = (df[cfg.source_col].astype(str).values
                               if cfg.source_col in df.columns else "unknown")
        del df

        if cfg.dedup:
            # Exact duplicate flows inflate test scores when they land on both
            # sides of the split. Note: only removes duplicates within a shard.
            n0 = len(out)
            out = out.drop_duplicates(subset=features + [cfg.attack_col])
            dup_removed += n0 - len(out)

        split = _stratified_assign(out[cfg.attack_col].reset_index(drop=True),
                                   cfg.val_frac, cfg.test_frac, rng)
        out = out.reset_index(drop=True)

        for code, name in enumerate(split_names):
            part = out[split == code]
            if part.empty:
                continue
            p = os.path.join(cfg.work_dir, name, f"shard_{i:04d}.parquet")
            part.to_parquet(p, index=False)
            manifest["splits"][name].append(p)

            c = manifest["counts"][name]
            for k, v in part[cfg.label_col].value_counts().items():
                c["label"][str(k)] = c["label"].get(str(k), 0) + int(v)
            for k, v in part[cfg.attack_col].value_counts().items():
                c["attack"][k] = c["attack"].get(k, 0) + int(v)
            for (src, lab), v in part.groupby([cfg.source_col, cfg.label_col]).size().items():
                key = f"{src}|{lab}"
                c["source_label"][key] = c["source_label"].get(key, 0) + int(v)

    manifest["duplicates_removed"] = dup_removed
    with open(os.path.join(cfg.work_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[prepare] done. features={len(features)}  duplicates removed={dup_removed}")
    return manifest


# --------------------------------------------------------------------------- #
# Streaming over shards
# --------------------------------------------------------------------------- #
class ShardIter(xgb.DataIter):
    """Feeds Parquet shards to XGBoost one at a time.

    row_filter(df) -> bool mask    : which rows to keep
    label_fn(df)   -> np.ndarray   : target values
    weight_fn(y)   -> np.ndarray   : optional sample weights
    """

    def __init__(self, paths, features, label_fn, row_filter=None,
                 weight_fn=None, cache_prefix=None):
        self.paths = list(paths)
        self.features = features
        self.label_fn = label_fn
        self.row_filter = row_filter
        self.weight_fn = weight_fn
        self._i = 0
        super().__init__(cache_prefix=cache_prefix)

    def next(self, input_data):
        while self._i < len(self.paths):
            df = pd.read_parquet(self.paths[self._i])
            self._i += 1
            if self.row_filter is not None:
                df = df[self.row_filter(df)]
            if df.empty:
                continue
            y = self.label_fn(df)
            kw = dict(data=df[self.features], label=y)
            if self.weight_fn is not None:
                kw["weight"] = self.weight_fn(y)
            input_data(**kw)
            return True
        return False

    def reset(self):
        self._i = 0


def _build_dmatrix(it: ShardIter, cfg: Config, ref=None, tag="train"):
    if cfg.external_memory:
        if not hasattr(xgb, "ExtMemQuantileDMatrix"):
            raise RuntimeError("external_memory needs XGBoost >= 3.0")
        it.cache_prefix = os.path.join(cfg.work_dir, "cache", tag)
        os.makedirs(os.path.dirname(it.cache_prefix), exist_ok=True)
        return xgb.ExtMemQuantileDMatrix(it, ref=ref, max_bin=256)
    # QuantileDMatrix keeps only quantised bins in RAM (much smaller than raw floats)
    return xgb.QuantileDMatrix(it, ref=ref, max_bin=256)


def _predict_split(booster, paths, features, cols, row_filter=None):
    """Predict shard by shard; return (concatenated meta columns, predictions)."""
    metas, preds = [], []
    for p in paths:
        df = pd.read_parquet(p)
        if row_filter is not None:
            df = df[row_filter(df)]
        if df.empty:
            continue
        preds.append(booster.inplace_predict(df[features]))
        metas.append(df[cols].reset_index(drop=True))
    if not preds:
        return pd.DataFrame(columns=cols), np.empty(0)
    return pd.concat(metas, ignore_index=True), np.concatenate(preds)


# --------------------------------------------------------------------------- #
# 2. Stage 1: benign vs attack
# --------------------------------------------------------------------------- #
def _spw_from_counts(label_counts: dict) -> float:
    neg, pos = label_counts.get("0", 0), label_counts.get("1", 0)
    if neg == 0 or pos == 0:
        raise ValueError(f"Training data needs both classes, got {label_counts}")
    return neg / pos


def threshold_for_fpr(y_true, scores, target_fpr: float) -> float:
    benign = scores[y_true == 0]
    if len(benign) == 0:
        return 0.5
    return float(np.quantile(benign, 1.0 - target_fpr))


def train_stage1(manifest: dict, cfg: Config, row_filter=None,
                 scale_pos_weight=None, save=True):
    feats = manifest["features"]
    label_fn = lambda df: df[cfg.label_col].to_numpy()

    if scale_pos_weight is None:
        scale_pos_weight = _spw_from_counts(manifest["counts"]["train"]["label"])

    dtrain = _build_dmatrix(ShardIter(manifest["splits"]["train"], feats, label_fn,
                                      row_filter), cfg, tag="s1_train")
    dval = _build_dmatrix(ShardIter(manifest["splits"]["val"], feats, label_fn,
                                    row_filter), cfg, ref=dtrain, tag="s1_val")

    params = _xgb_params(cfg.s1_params, cfg)
    params["scale_pos_weight"] = scale_pos_weight
    print(f"\n===== Stage 1 training (scale_pos_weight={scale_pos_weight:.3f}) =====")
    booster = xgb.train(params, dtrain, num_boost_round=cfg.s1_rounds,
                        evals=[(dval, "val")],
                        early_stopping_rounds=cfg.s1_early_stop,
                        verbose_eval=cfg.verbose_eval)
    # Keep only the trees up to the best iteration
    booster = booster[: booster.best_iteration + 1]

    # Threshold chosen on validation, never on test
    meta, p_val = _predict_split(booster, manifest["splits"]["val"], feats,
                                 [cfg.label_col], row_filter)
    thr = threshold_for_fpr(meta[cfg.label_col].to_numpy(), p_val, cfg.target_fpr)
    print(f"Stage 1: {booster.num_boosted_rounds()} trees, "
          f"threshold @ FPR {cfg.target_fpr:g} = {thr:.6f}")

    if save:
        booster.save_model(os.path.join(cfg.work_dir, "stage1.json"))
        with open(os.path.join(cfg.work_dir, "stage1_meta.json"), "w") as f:
            json.dump({"features": feats, "threshold": thr,
                       "target_fpr": cfg.target_fpr,
                       "scale_pos_weight": scale_pos_weight,
                       "trees": booster.num_boosted_rounds()}, f, indent=2)
    return booster, thr


def _binary_report(y, p, thr, title):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    both = len(np.unique(y)) == 2
    r = {
        "n": int(len(y)),
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else float("nan"),
        "roc_auc": roc_auc_score(y, p) if both else float("nan"),
        "pr_auc": average_precision_score(y, p) if both else float("nan"),
        "confusion": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
    print(f"--- {title} (threshold={thr:.6f}) ---")
    for k in ["n", "accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]:
        v = r[k]
        print(f"  {k:9s}: {v}" if k == "n" else f"  {k:9s}: {v:.4f}")
    print(f"  confusion [[TN FP] [FN TP]]: {r['confusion']}")
    return r


def evaluate_stage1(booster, thr, manifest, cfg: Config, row_filter=None):
    meta, p = _predict_split(booster, manifest["splits"]["test"], manifest["features"],
                             [cfg.label_col, cfg.source_col], row_filter)
    y = meta[cfg.label_col].to_numpy()
    print("\n===== Stage 1 test (all shards) =====")
    results = {"tuned": _binary_report(y, p, thr, "tuned threshold"),
               "default": _binary_report(y, p, 0.5, "default 0.5"),
               "per_source": {}}
    print("\n--- per source dataset (tuned threshold) ---")
    for src, idx in meta.groupby(cfg.source_col).indices.items():
        ys, ps = y[idx], p[idx]
        pred = (ps >= thr).astype(int)
        neg = (ys == 0).sum()
        fpr = ((pred == 1) & (ys == 0)).sum() / neg if neg else float("nan")
        rec = recall_score(ys, pred, zero_division=0) if (ys == 1).any() else float("nan")
        results["per_source"][src] = {"n": int(len(ys)), "recall": rec, "fpr": fpr}
        print(f"  {src:25s} n={len(ys):>10d}  recall={rec:.4f}  fpr={fpr:.5f}")
    return results


# --------------------------------------------------------------------------- #
# 3. Stage 2: attack type (attack rows only)
# --------------------------------------------------------------------------- #
def build_class_map(manifest: dict, cfg: Config):
    """Map attack names -> class ids; rare classes collapse into 'other'."""
    counts = manifest["counts"]["train"]["attack"]
    benign_names = {"benign", "normal", "0"}
    classes, other = [], []
    for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        if name in benign_names:
            continue
        (classes if n >= cfg.min_class_count else other).append(name)
    if other:
        classes.append("other")
    cmap = {name: i for i, name in enumerate(classes)}
    for name in other:
        cmap[name] = cmap["other"]
    return classes, cmap, other


def train_stage2(manifest: dict, cfg: Config):
    feats = manifest["features"]
    classes, cmap, merged = build_class_map(manifest, cfg)
    if len(classes) < 2:
        raise ValueError(f"Stage 2 needs >= 2 attack classes, got {classes}")
    if merged:
        print(f"Stage 2: merged rare classes into 'other': {merged}")

    attack_only = lambda df: (df[cfg.label_col] == 1) & df[cfg.attack_col].isin(cmap)
    label_fn = lambda df: df[cfg.attack_col].map(cmap).to_numpy(dtype=np.int32)

    # Balanced class weights from global train counts, capped so tiny classes
    # don't dominate the loss.
    train_counts = np.zeros(len(classes))
    for name, n in manifest["counts"]["train"]["attack"].items():
        if name in cmap:
            train_counts[cmap[name]] += n
    w = train_counts.sum() / (len(classes) * np.maximum(train_counts, 1))
    w = np.minimum(w, cfg.max_class_weight)
    weight_fn = lambda y: w[y].astype(np.float32)

    dtrain = _build_dmatrix(ShardIter(manifest["splits"]["train"], feats, label_fn,
                                      attack_only, weight_fn), cfg, tag="s2_train")
    dval = _build_dmatrix(ShardIter(manifest["splits"]["val"], feats, label_fn,
                                    attack_only, weight_fn), cfg, ref=dtrain, tag="s2_val")

    params = _xgb_params(cfg.s2_params, cfg)
    params["num_class"] = len(classes)
    print(f"\n===== Stage 2 training ({len(classes)} classes) =====")
    booster = xgb.train(params, dtrain, num_boost_round=cfg.s2_rounds,
                        evals=[(dval, "val")],
                        early_stopping_rounds=cfg.s2_early_stop,
                        verbose_eval=cfg.verbose_eval)
    booster = booster[: booster.best_iteration + 1]

    booster.save_model(os.path.join(cfg.work_dir, "stage2.json"))
    with open(os.path.join(cfg.work_dir, "stage2_meta.json"), "w") as f:
        json.dump({"features": feats, "classes": classes, "class_map": cmap,
                   "class_weights": w.tolist(),
                   "trees_per_class": booster.num_boosted_rounds()}, f, indent=2)
    return booster, classes, cmap


def evaluate_stage2(booster, classes, cmap, manifest, cfg: Config):
    """Stage 2 alone, on true attack flows from the test set."""
    attack_only = lambda df: (df[cfg.label_col] == 1) & df[cfg.attack_col].isin(cmap)
    meta, proba = _predict_split(booster, manifest["splits"]["test"],
                                 manifest["features"], [cfg.attack_col], attack_only)
    y = meta[cfg.attack_col].map(cmap).to_numpy()
    pred = proba.argmax(axis=1)
    labels = list(range(len(classes)))
    print("\n===== Stage 2 test (true attacks only) =====")
    print(classification_report(y, pred, labels=labels, target_names=classes,
                                digits=4, zero_division=0))
    print("confusion (rows=true, cols=pred):")
    print(confusion_matrix(y, pred, labels=labels))
    return {"macro_f1": f1_score(y, pred, average="macro", labels=labels, zero_division=0)}


def evaluate_pipeline(s1, thr, s2, classes, cmap, manifest, cfg: Config):
    """End to end: stage 1 decides benign/attack, stage 2 names flagged flows."""
    names = ["benign"] + classes
    y_true, y_pred = [], []
    feats = manifest["features"]
    for p in manifest["splits"]["test"]:
        df = pd.read_parquet(p)
        X = df[feats]
        flagged = s1.inplace_predict(X) >= thr
        pred = np.zeros(len(df), dtype=np.int32)
        if flagged.any():
            pred[flagged] = s2.inplace_predict(X[flagged]).argmax(axis=1) + 1
        true = np.where(df[cfg.label_col].to_numpy() == 1,
                        df[cfg.attack_col].map(cmap).fillna(cmap.get("other", 0))
                        .to_numpy(dtype=np.int32) + 1, 0)
        y_true.append(true)
        y_pred.append(pred)
    y_true, y_pred = np.concatenate(y_true), np.concatenate(y_pred)
    labels = list(range(len(names)))
    print("\n===== End-to-end pipeline test =====")
    print(classification_report(y_true, y_pred, labels=labels, target_names=names,
                                digits=4, zero_division=0))
    return {"macro_f1": f1_score(y_true, y_pred, average="macro", labels=labels,
                                 zero_division=0)}


# --------------------------------------------------------------------------- #
# 4. Optional: leave-one-source-dataset-out (stage 1)
# --------------------------------------------------------------------------- #
def cross_dataset_eval(manifest: dict, cfg: Config):
    """Train on every source dataset except one, test on the held-out one.
    This is the realistic generalisation number; expect it to be far lower."""
    src_counts = {}
    for key, n in manifest["counts"]["train"]["source_label"].items():
        src, lab = key.rsplit("|", 1)
        src_counts.setdefault(src, {"0": 0, "1": 0})[lab] = n
    sources = sorted(src_counts)
    if len(sources) < 2:
        print("cross_dataset_eval: need >= 2 source datasets, skipping")
        return {}

    results = {}
    for held in sources:
        print(f"\n######## LODO: holding out '{held}' ########")
        neg = sum(c["0"] for s, c in src_counts.items() if s != held)
        pos = sum(c["1"] for s, c in src_counts.items() if s != held)
        if neg == 0 or pos == 0:
            print("  skipped: remaining sources lack one class")
            continue
        keep = lambda df, h=held: df[cfg.source_col] != h
        only = lambda df, h=held: df[cfg.source_col] == h
        booster, thr = train_stage1(manifest, cfg, row_filter=keep,
                                    scale_pos_weight=neg / pos, save=False)
        meta, p = _predict_split(booster, manifest["splits"]["test"],
                                 manifest["features"], [cfg.label_col], only)
        results[held] = _binary_report(meta[cfg.label_col].to_numpy(), p, thr,
                                       f"held-out {held}")
    with open(os.path.join(cfg.work_dir, "lodo_results.json"), "w") as f:
        json.dump(results, f, indent=2, default=float)
    return results


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Two-stage XGBoost NIDS trainer")
    ap.add_argument("--csv", nargs="+", required=True, help="raw CSV shards (globs ok)")
    ap.add_argument("--work-dir", default="nids_work")
    ap.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    ap.add_argument("--external-memory", action="store_true")
    ap.add_argument("--keep-ports", action="store_true", help="don't drop L4 ports")
    ap.add_argument("--no-dedup", action="store_true")
    ap.add_argument("--target-fpr", type=float, default=0.001)
    ap.add_argument("--skip-prepare", action="store_true",
                    help="reuse work-dir/manifest.json from a previous run")
    ap.add_argument("--skip-stage2", action="store_true")
    ap.add_argument("--lodo", action="store_true",
                    help="also run leave-one-source-dataset-out eval (slow)")
    args = ap.parse_args()

    cfg = Config(work_dir=args.work_dir, device=args.device,
                 external_memory=args.external_memory, dedup=not args.no_dedup,
                 target_fpr=args.target_fpr)
    if args.keep_ports:
        cfg.leaky_cols = []
    os.makedirs(cfg.work_dir, exist_ok=True)

    csvs = sorted(p for pat in args.csv for p in glob.glob(pat))
    if not csvs and not args.skip_prepare:
        raise SystemExit("No CSV files matched --csv")

    if args.skip_prepare:
        with open(os.path.join(cfg.work_dir, "manifest.json")) as f:
            manifest = json.load(f)
    else:
        manifest = prepare_shards(csvs, cfg)

    s1, thr = train_stage1(manifest, cfg)
    report = {"config": asdict(cfg), "stage1": evaluate_stage1(s1, thr, manifest, cfg)}

    if not args.skip_stage2:
        s2, classes, cmap = train_stage2(manifest, cfg)
        report["stage2"] = evaluate_stage2(s2, classes, cmap, manifest, cfg)
        report["pipeline"] = evaluate_pipeline(s1, thr, s2, classes, cmap, manifest, cfg)

    if args.lodo:
        report["lodo"] = cross_dataset_eval(manifest, cfg)

    with open(os.path.join(cfg.work_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2, default=float)
    print(f"\nModels and report saved in {cfg.work_dir}/")


if __name__ == "__main__":
    main()
