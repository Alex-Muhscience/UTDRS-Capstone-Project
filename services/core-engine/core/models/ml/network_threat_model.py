"""
The network threat model: one network flow in, the kind of traffic it is out.

A CNN-LSTM over 21 per-flow measurements, trained on UNSW-NB15 to tell normal traffic
from nine kinds of attack. It has the architecture of the capstone's
advanced_threat_detection_model.h5, retrained by
research/capstone/models/train_network_threat_model.py because nothing recorded what
the original's inputs and classes were. Its weights, feature list and scaling are
stored next to this module as plain arrays and JSON, and it runs with NumPy alone.
See network_threat/MODEL_CARD.md for how well it performs.
"""
import json
import os
from typing import Any, Dict, List, Mapping, Optional

import numpy as np

from utils.logger import get_logger

logger = get_logger(__name__)

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "network_threat")


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


def _conv1d(x: np.ndarray, kernel: np.ndarray, bias: np.ndarray) -> np.ndarray:
    """Keras Conv1D with 'valid' padding and ReLU. x: (steps, channels)."""
    width = kernel.shape[0]
    windows = np.stack([x[i : i + width] for i in range(x.shape[0] - width + 1)])
    return np.maximum(np.einsum("swc,wcf->sf", windows, kernel) + bias, 0.0)


def _max_pool(x: np.ndarray, size: int = 2) -> np.ndarray:
    steps = (x.shape[0] // size) * size
    return x[:steps].reshape(-1, size, x.shape[1]).max(axis=1)


def _lstm(x: np.ndarray, kernel: np.ndarray, recurrent: np.ndarray, bias: np.ndarray) -> np.ndarray:
    """Keras LSTM (gates in the order input, forget, cell, output). Returns every step's output."""
    units = recurrent.shape[0]
    h = np.zeros(units, dtype=np.float32)
    c = np.zeros(units, dtype=np.float32)
    outputs = []
    for step in x:
        z = step @ kernel + h @ recurrent + bias
        i, f, g, o = (z[k * units : (k + 1) * units] for k in range(4))
        c = _sigmoid(f) * c + _sigmoid(i) * np.tanh(g)
        h = _sigmoid(o) * np.tanh(c)
        outputs.append(h)
    return np.stack(outputs)


class NetworkThreatModel:
    def __init__(self, artifact_dir: str = ARTIFACT_DIR):
        with open(os.path.join(artifact_dir, "features.json"), encoding="utf-8") as f:
            spec = json.load(f)
        self.features: List[str] = spec["features"]
        self.classes: List[str] = spec["classes"]
        self.mean = np.asarray(spec["mean"], dtype=np.float64)
        self.std = np.asarray(spec["std"], dtype=np.float64)
        with np.load(os.path.join(artifact_dir, "weights.npz")) as weights:
            self.w = {name: weights[name] for name in weights.files}
        if self.w["dense_1_kernel"].shape[1] != len(self.classes) or len(self.mean) != len(self.features):
            raise ValueError("The network threat model's files do not match each other")

    def flow_values(self, flow: Mapping[str, Any]) -> Optional[np.ndarray]:
        """The model's inputs from a flow record, or None when any of them is missing."""
        values = []
        for name in self.features:
            value = flow.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    return None
            values.append(float(value))
        return np.asarray(values, dtype=np.float64)

    def predict(self, raw: np.ndarray) -> Dict[str, float]:
        """The probability of each class for one flow's 21 raw measurements."""
        x = ((np.log1p(np.clip(raw, 0, None)) - self.mean) / self.std).astype(np.float32)[:, None]
        x = _max_pool(_conv1d(x, self.w["conv_0_kernel"], self.w["conv_0_bias"]))
        x = _max_pool(_conv1d(x, self.w["conv_1_kernel"], self.w["conv_1_bias"]))
        x = _lstm(x, self.w["lstm_0_kernel"], self.w["lstm_0_recurrent"], self.w["lstm_0_bias"])
        h = _lstm(x, self.w["lstm_1_kernel"], self.w["lstm_1_recurrent"], self.w["lstm_1_bias"])[-1]
        h = np.maximum(h @ self.w["dense_0_kernel"] + self.w["dense_0_bias"], 0.0)
        logits = h @ self.w["dense_1_kernel"] + self.w["dense_1_bias"]
        probabilities = np.exp(logits - logits.max())
        probabilities /= probabilities.sum()
        return {name: float(p) for name, p in zip(self.classes, probabilities)}


_model: Optional[NetworkThreatModel] = None
_load_failed = False


def get_network_threat_model() -> Optional[NetworkThreatModel]:
    """The model, loaded once; None when its files are missing or unreadable."""
    global _model, _load_failed
    if _model is None and not _load_failed:
        try:
            _model = NetworkThreatModel(ARTIFACT_DIR)
            logger.info("Loaded the network threat model")
        except (OSError, KeyError, ValueError) as e:
            _load_failed = True
            logger.warning(f"Network threat model unavailable, using indicators instead: {e}")
    return _model
