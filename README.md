# sniffy

`sniffy` captures NFStream flow features and trains a two-stage XGBoost detector:
stage one distinguishes benign from attack flows; stage two assigns an attack
type. The canonical implementation is the installable `sniffy` package.

For a file-by-file walkthrough and the stage-two training runbook, see the
[project guide](docs/sniffy_project_guide.pdf).

## Install

Create and activate a virtual environment, then install the project and its
dependencies:

```bash
python -m pip install -e .
```

Live capture requires the system `tshark`/capture permissions appropriate to the
host. Use `SNIFFY_HOME` to choose a project data root, or override individual
paths with `SNIFFY_DATASET`, `SNIFFY_SPLIT_DIR`, `SNIFFY_ATTACK_DIR`,
`SNIFFY_ARTIFACT_DIR`, and `SNIFFY_CAPTURE_CSV`.

## Pipeline

```bash
sniffy-split path/to/dataset.csv data/splitted --chunksize 500000
sniffy-train-stage1 data/splitted
sniffy-segregate data/splitted data/attacks
sniffy-train-stage2 data/attacks
sniffy-predict input.csv --output predictions.csv
```

Stage two requires nonempty `Attack` labels and at least two attack classes in
each training chunk. Check the generated files before training if the original
dataset groups attack types into separate files.

Stage artifacts are separate (`artifacts/stage1/xgb_v1.pkl` and
`artifacts/stage2/xgb_v1.pkl`). `sniffy-capture --interface IFACE --output
data/capture.csv` writes flow rows in the canonical schema order. Capture does
not infer ground truth: pass `--label` and `--attack` only when those labels are
known; otherwise label flows before using them for supervised training.

The canonical 46-column schema is in `sniffy/schema.py`. Superseded scripts,
duplicate capture plugins, and notebook checkpoints have been removed. The
original PCAPs, the old single-model pickle at `model/xgb_attack_model.pkl`,
and the proposal PDF are retained as data/reference; the old pickle is not the
new two-artifact stage-one/stage-two bundle format.