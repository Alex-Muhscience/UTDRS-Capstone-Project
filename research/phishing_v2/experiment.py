"""
Does adding sender and link signals to the text improve the phishing verdict? A controlled
comparison: the same TF-IDF text model, with and without the signals, trained on the same
70% of the emails that have sender data, measured on the same held-out 30%.

    python -I experiment.py /path/to/phishing-email-dataset
"""
import json
import os
import re
import sys

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signals import NAMES, signals  # noqa: E402

SEED = 42
SOURCES = ["CEAS_08", "SpamAssasin", "Nazario", "Nigerian_Fraud"]
TOKEN = r"(?u)\b[a-z][a-z0-9]+\b"


def load(folder):
    frames = []
    for source in SOURCES:
        frame = pd.read_csv(os.path.join(folder, f"{source}.csv"))
        frame["source"] = source
        frames.append(frame)
    data = pd.concat(frames, ignore_index=True)
    data = data.dropna(subset=["body", "label"]).drop_duplicates(subset=["subject", "body"])
    data["text"] = (data["subject"].fillna("") + " " + data["body"].fillna("")).str.lower()
    data["label"] = data["label"].astype(int)
    data["has_links"] = pd.to_numeric(data["urls"], errors="coerce").fillna(0) > 0
    return data


def measure(y, p, threshold):
    flagged = p >= threshold
    negatives = (y == 0).sum()
    return {
        "precision": round(float(precision_score(y, flagged, zero_division=0)), 4),
        "recall": round(float(recall_score(y, flagged, zero_division=0)), 4),
        "false_positive_rate": round(float(((flagged) & (y == 0)).sum() / negatives), 4) if negatives else None,
        "n": int(len(y)),
    }


def main(folder):
    data = load(folder)
    train, test = train_test_split(data, test_size=0.3, random_state=SEED, stratify=data["source"] + data["label"].astype(str))
    vectoriser = TfidfVectorizer(max_features=5000, token_pattern=TOKEN, sublinear_tf=True)
    x_train_text, x_test_text = vectoriser.fit_transform(train["text"]), vectoriser.transform(test["text"])
    sig = lambda frame: csr_matrix(np.array([signals(s, l) for s, l in zip(frame["sender"], frame["has_links"])], dtype=float))  # noqa: E731
    x_train_both, x_test_both = hstack([x_train_text, sig(train)]).tocsr(), hstack([x_test_text, sig(test)]).tocsr()

    results = {}
    for name, (xa, xb) in {"text only": (x_train_text, x_test_text), "text and signals": (x_train_both, x_test_both)}.items():
        model = LogisticRegression(max_iter=2000, C=10.0)
        model.fit(xa, train["label"])
        p = model.predict_proba(xb)[:, 1]
        y = test["label"].to_numpy()
        entry = {"auc": round(float(roc_auc_score(y, p)), 4), "at_0.5": measure(y, p, 0.5), "at_0.7": measure(y, p, 0.7), "by_source": {}}
        for source in SOURCES:
            mask = (test["source"] == source).to_numpy()
            entry["by_source"][source] = measure(y[mask], p[mask], 0.7)
        if name == "text and signals":
            entry["signal_weights"] = {n: round(float(w), 3) for n, w in zip(NAMES, model.coef_[0][-len(NAMES):])}
        results[name] = entry
    results["data"] = {"train": int(len(train)), "test": int(len(test)), "by_source": data.groupby("source")["label"].agg(["count", "sum"]).to_dict()}
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
