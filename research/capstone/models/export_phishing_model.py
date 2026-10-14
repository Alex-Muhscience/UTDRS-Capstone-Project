"""
Export phishing_model.h5 for the core engine: its weights as NumPy arrays and its TF-IDF
vocabulary as JSON, checked against the data it was trained on.

    pip install h5py numpy pandas scikit-learn
    python export_phishing_model.py phishing_email.csv ../../../services/core-engine/core/models/ml/phishing_email

phishing_email.csv is the Kaggle "Phishing Email Dataset" by Naser Abdullah Alam
(columns text_combined and label), the file phishing_model.py trains on.

Why the vocabulary is rebuilt here: phishing_model.py saved the fitted vectoriser as
tfidf_vectorizer.pkl, which was never committed, and the network is meaningless
without it, because each of its 5,000 inputs is one term. Refitting the vectoriser
the way the training script did comes close but not exactly: TfidfVectorizer keeps the
5,000 most frequent terms and numbers them alphabetically, so a training set that
differs by a few rows changes a few terms at the cut-off and shifts the index of every
term after them. With the refitted vocabulary the saved model scores 75% on the test
split. VOCABULARY_CORRECTIONS below are the differences that put the terms back in
step, found by searching for the stretches of the vocabulary that the model reads one
position off. With them it scores 98.2% on the test split and 99.4% on the training
split, the pattern a model has on its own training data.

What the corrections do and do not establish: they restore the alignment of the
vocabulary, which is what the model needs. The terms named are the best fit within a
few positions, so at the edges of each corrected stretch a handful of inputs may
carry a neighbouring term.
"""
import json
import os
import sys

import h5py
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

MODEL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_model.h5")

# Terms in the refitted vocabulary that the saved model does not have, and terms it has
# instead. See the module docstring.
VOCABULARY_CORRECTIONS = {
    "drop": ["001", "090909", "250", "accounting", "ben", "healthcare", "video", "voting", "worried"],
    "add": ["010", "0x0", "arab", "arbitrary", "oriented", "useless", "viewer", "vinoble", "workplace"],
}

DENSE = ["dense", "dense_1", "dense_2", "dense_3"]
NORMS = ["batch_normalization", "batch_normalization_1", "batch_normalization_2"]
BATCH_NORM_EPSILON = 1e-3  # Keras' default


def training_split(csv_path):
    """The train and test split, exactly as phishing_model.py makes it."""
    df = pd.read_csv(csv_path).dropna().drop_duplicates()
    phishing, legitimate = df[df["label"] == 1], df[df["label"] == 0]
    size = min(len(phishing), len(legitimate))
    balanced = pd.concat(
        [phishing.sample(n=size, random_state=42), legitimate.sample(n=size, random_state=42)]
    ).reset_index(drop=True)
    balanced = shuffle(balanced, random_state=42)
    return train_test_split(
        balanced["text_combined"], balanced["label"], test_size=0.3, random_state=42, stratify=balanced["label"]
    )


def load_weights(model_file):
    """The saved Keras model's weights, named for the engine."""
    weights = h5py.File(model_file, "r")["model_weights"]
    variable = lambda layer, name: weights[f"{layer}/sequential/{layer}/{name}"][()].astype(np.float32)
    arrays = {"dense_layers": np.array(len(DENSE))}
    for i, layer in enumerate(DENSE):
        arrays[f"dense_{i}_kernel"] = variable(layer, "kernel")
        arrays[f"dense_{i}_bias"] = variable(layer, "bias")
    for i, layer in enumerate(NORMS):
        arrays[f"norm_{i}_mean"] = variable(layer, "moving_mean")
        arrays[f"norm_{i}_variance"] = variable(layer, "moving_variance")
        arrays[f"norm_{i}_gamma"] = variable(layer, "gamma")
        arrays[f"norm_{i}_beta"] = variable(layer, "beta")
    return arrays


def predict(arrays, features):
    """The network at inference: dropout does nothing, batch normalisation uses its moving statistics."""
    hidden = features
    for i in range(len(DENSE)):
        hidden = hidden @ arrays[f"dense_{i}_kernel"] + arrays[f"dense_{i}_bias"]
        if i < len(NORMS):
            hidden = np.maximum(hidden, 0)
            hidden = (hidden - arrays[f"norm_{i}_mean"]) / np.sqrt(arrays[f"norm_{i}_variance"] + BATCH_NORM_EPSILON)
            hidden = hidden * arrays[f"norm_{i}_gamma"] + arrays[f"norm_{i}_beta"]
    return 1 / (1 + np.exp(-hidden[:, 0]))


def evaluate(arrays, vectorizer, texts, labels, threshold=0.5):
    probabilities = np.concatenate(
        [
            predict(arrays, vectorizer.transform(texts.iloc[i : i + 2000]).toarray().astype(np.float32))
            for i in range(0, len(texts), 2000)
        ]
    )
    predicted, actual = probabilities > threshold, labels.values.astype(bool)
    tp, fp = int((predicted & actual).sum()), int((predicted & ~actual).sum())
    fn, tn = int((~predicted & actual).sum()), int((~predicted & ~actual).sum())
    return {
        "emails": len(actual),
        "accuracy": round((tp + tn) / len(actual), 4),
        "precision": round(tp / (tp + fp), 4),
        "recall": round(tp / (tp + fn), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
    }


def main(csv_path, out_dir):
    x_train, x_test, y_train, y_test = training_split(csv_path)
    arrays = load_weights(MODEL_FILE)

    refitted = TfidfVectorizer(max_features=5000).fit(x_train)
    print("refitted vocabulary, test split:", evaluate(arrays, refitted, x_test, y_test))

    terms = set(refitted.get_feature_names_out())
    terms = sorted((terms - set(VOCABULARY_CORRECTIONS["drop"])) | set(VOCABULARY_CORRECTIONS["add"]))
    assert len(terms) == 5000, len(terms)
    vectorizer = TfidfVectorizer(vocabulary=terms).fit(x_train)

    metrics = {
        "test": evaluate(arrays, vectorizer, x_test, y_test),
        "train": evaluate(arrays, vectorizer, x_train, y_train),
        "test_at_0.7": evaluate(arrays, vectorizer, x_test, y_test, threshold=0.7),
    }
    for name, result in metrics.items():
        print(f"corrected vocabulary, {name}:", result)

    os.makedirs(out_dir, exist_ok=True)
    np.savez_compressed(os.path.join(out_dir, "weights.npz"), **arrays)
    with open(os.path.join(out_dir, "vocabulary.json"), "w", encoding="utf-8") as f:
        json.dump(
            {"terms": terms, "idf": [round(float(v), 6) for v in vectorizer.idf_]},
            f,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    print("wrote weights.npz and vocabulary.json to", out_dir)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
