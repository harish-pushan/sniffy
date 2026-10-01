"""Exploratory plots for numeric features grouped by a dataset label."""

from pathlib import Path

import pandas as pd


class EDAVisualizer:
    def __init__(self, dataset_path: str | Path, label_col: str = "Label"):
        self.dataset_path = Path(dataset_path)
        self.label_col = label_col

    def plot(
        self, output_dir: str | Path | None = None, show: bool = True
    ) -> list[Path]:
        import matplotlib.pyplot as plt

        frame = pd.read_csv(self.dataset_path)
        if self.label_col not in frame:
            raise ValueError(f"Missing label column: {self.label_col}")
        destinations: list[Path] = []
        output = Path(output_dir) if output_dir else None
        if output:
            output.mkdir(parents=True, exist_ok=True)

        for column in frame.select_dtypes(include="number").columns:
            if column == self.label_col:
                continue
            figure, axis = plt.subplots()
            for label, group in frame.groupby(self.label_col, dropna=False):
                axis.hist(
                    group[column].dropna(), alpha=0.55, density=True, label=str(label)
                )
            axis.set(title=column, xlabel=column, ylabel="Density")
            axis.legend()
            if output:
                destination = output / f"{column}.png"
                figure.savefig(destination, bbox_inches="tight")
                destinations.append(destination)
            if show:
                plt.show()
            plt.close(figure)
        return destinations
