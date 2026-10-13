"""
The capstone's phishing-email classifier, run with NumPy alone.

The model is the feed-forward network trained in research/capstone/models
(phishing_model.py): TF-IDF over an email's text, 5,000 terms, into three hidden
layers with batch normalisation and a sigmoid output. Its weights and the
vectoriser's vocabulary are stored next to this module as plain arrays and JSON, so
the engine needs neither TensorFlow nor pickle to use it. See
phishing_email/MODEL_CARD.md for where the files come from and how well it performs.
"""
import json
import os
import re
from typing import Dict, Optional

import numpy as np

from utils.logger import get_logger

logger = get_logger(__name__)

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "phishing_email")

# scikit-learn's default TfidfVectorizer analyser: lowercase, words of two or more
# word characters.
TOKEN = re.compile(r"(?u)\b\w\w+\b")
BATCH_NORM_EPSILON = 1e-3  # Keras' default


class PhishingEmailModel:
    def __init__(self, artifact_dir: str = ARTIFACT_DIR):
        with open(os.path.join(artifact_dir, "vocabulary.json"), encoding="utf-8") as f:
            vocabulary = json.load(f)
        self.index: Dict[str, int] = {term: i for i, term in enumerate(vocabulary["terms"])}
        self.idf = np.asarray(vocabulary["idf"], dtype=np.float32)

        with np.load(os.path.join(artifact_dir, "weights.npz")) as weights:
            self.layers = []
            for i in range(int(weights["dense_layers"])):
                layer = {"kernel": weights[f"dense_{i}_kernel"], "bias": weights[f"dense_{i}_bias"]}
                if f"norm_{i}_mean" in weights:
                    # Batch normalisation at inference is one scale and one shift.
                    scale = weights[f"norm_{i}_gamma"] / np.sqrt(
                        weights[f"norm_{i}_variance"] + BATCH_NORM_EPSILON
                    )
                    layer["scale"] = scale
                    layer["shift"] = weights[f"norm_{i}_beta"] - weights[f"norm_{i}_mean"] * scale
                self.layers.append(layer)

        if len(self.index) != self.layers[0]["kernel"].shape[0] or len(self.idf) != len(self.index):
            raise ValueError("The phishing model's vocabulary does not match its first layer")

    def vectorize(self, text: str) -> np.ndarray:
        """The email's TF-IDF vector, L2-normalised, as the vectoriser produced in training."""
        vector = np.zeros(len(self.index), dtype=np.float32)
        for token in TOKEN.findall(text.lower()):
            position = self.index.get(token)
            if position is not None:
                vector[position] += 1.0
        vector *= self.idf
        norm = float(np.linalg.norm(vector))
        return vector / norm if norm else vector

    def known_terms(self, text: str) -> int:
        """How many of the email's distinct words the model knows."""
        return len({t for t in TOKEN.findall(text.lower()) if t in self.index})

    def predict(self, text: str) -> float:
        """The probability, from 0 to 1, that the email is phishing."""
        hidden = self.vectorize(text)
        for layer in self.layers[:-1]:
            hidden = np.maximum(hidden @ layer["kernel"] + layer["bias"], 0.0)
            hidden = hidden * layer["scale"] + layer["shift"]
        output = self.layers[-1]
        logit = float((hidden @ output["kernel"] + output["bias"])[0])
        return float(1.0 / (1.0 + np.exp(-logit)))


_model: Optional[PhishingEmailModel] = None
_load_failed = False


def get_phishing_email_model() -> Optional[PhishingEmailModel]:
    """The model, loaded once; None when its files are missing or unreadable."""
    global _model, _load_failed
    if _model is None and not _load_failed:
        try:
            _model = PhishingEmailModel(ARTIFACT_DIR)
            logger.info("Loaded the phishing email model")
        except (OSError, KeyError, ValueError) as e:
            _load_failed = True
            logger.warning(f"Phishing email model unavailable, using indicators instead: {e}")
    return _model
