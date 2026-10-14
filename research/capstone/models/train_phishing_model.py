"""
Train the phishing email model and export it, with its vectoriser, for the core engine.

    pip install tensorflow pandas numpy scikit-learn
    python train_phishing_model.py phishing_email.csv ../../../services/core-engine/core/models/ml/phishing_email

phishing_email.csv is the Kaggle "Phishing Email Dataset" by Naser Abdullah Alam
(columns text_combined and label), the data phishing_model.py was written for.

This is phishing_model.py's recipe, retrained from scratch so that the TF-IDF
vectoriser is saved with the network (the original run saved it to a file that was
never committed). The data handling, vectoriser and network are the same. One change:
the original used its test split to decide when to stop training, so its test score
was not fully independent. Here a tenth of the training split does that, and the test
split is only used to measure the finished model.
"""
import json
import os
import sys

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle
from tensorflow import keras
from tensorflow.keras import layers

SEED = 42


def training_split(csv_path):
    """Cleaned, balanced, and split 70/30, exactly as phishing_model.py does."""
    df = pd.read_csv(csv_path).dropna().drop_duplicates()
    phishing, legitimate = df[df["label"] == 1], df[df["label"] == 0]
    size = min(len(phishing), len(legitimate))
    balanced = pd.concat(
        [phishing.sample(n=size, random_state=SEED), legitimate.sample(n=size, random_state=SEED)]
    ).reset_index(drop=True)
    balanced = shuffle(balanced, random_state=SEED)
    return train_test_split(
        balanced["text_combined"], balanced["label"], test_size=0.3, random_state=SEED, stratify=balanced["label"]
    )


def build_model(inputs):
    """phishing_model.py's FFNNModel."""
    model = keras.Sequential([
        keras.Input(shape=(inputs,)),
        layers.Dense(256, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.4),
        layers.Dense(128, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.4),
        layers.Dense(64, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=0.0005), loss="binary_crossentropy", metrics=["accuracy"])
    return model


def metrics(probabilities, labels, threshold=0.5):
    predicted, actual = probabilities > threshold, labels.astype(bool)
    tp, fp = int((predicted & actual).sum()), int((predicted & ~actual).sum())
    fn, tn = int((~predicted & actual).sum()), int((~predicted & ~actual).sum())
    return {
        "emails": len(actual),
        "accuracy": round((tp + tn) / len(actual), 4),
        "precision": round(tp / (tp + fp), 4),
        "recall": round(tp / (tp + fn), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
    }


def export(model, vectorizer, out_dir):
    """Weights as plain arrays, named for the engine's NumPy implementation, and the vocabulary as JSON."""
    arrays = {}
    denses = [l for l in model.layers if isinstance(l, layers.Dense)]
    norms = [l for l in model.layers if isinstance(l, layers.BatchNormalization)]
    arrays["dense_layers"] = np.array(len(denses))
    for i, layer in enumerate(denses):
        arrays[f"dense_{i}_kernel"], arrays[f"dense_{i}_bias"] = layer.get_weights()
    for i, layer in enumerate(norms):
        gamma, beta, mean, variance = layer.get_weights()
        arrays.update({f"norm_{i}_gamma": gamma, f"norm_{i}_beta": beta, f"norm_{i}_mean": mean, f"norm_{i}_variance": variance})
    os.makedirs(out_dir, exist_ok=True)
    np.savez_compressed(os.path.join(out_dir, "weights.npz"), **{k: np.asarray(v, dtype=np.float32) if k != "dense_layers" else v for k, v in arrays.items()})
    with open(os.path.join(out_dir, "vocabulary.json"), "w", encoding="utf-8") as f:
        json.dump(
            {"terms": [str(t) for t in vectorizer.get_feature_names_out()], "idf": [round(float(v), 6) for v in vectorizer.idf_]},
            f,
            ensure_ascii=False,
            separators=(",", ":"),
        )


def main(csv_path, out_dir):
    tf.keras.utils.set_random_seed(SEED)
    x_train, x_test, y_train, y_test = training_split(csv_path)

    vectorizer = TfidfVectorizer(max_features=5000)
    train_features = vectorizer.fit_transform(x_train).toarray().astype(np.float32)
    test_features = vectorizer.transform(x_test).toarray().astype(np.float32)
    y_train, y_test = y_train.to_numpy(), y_test.to_numpy()

    rng = np.random.default_rng(SEED)
    order = rng.permutation(len(train_features))
    validation, fit = order[: len(order) // 10], order[len(order) // 10 :]

    model = build_model(train_features.shape[1])
    model.fit(
        train_features[fit], y_train[fit],
        validation_data=(train_features[validation], y_train[validation]),
        epochs=50, batch_size=128, verbose=2,
        callbacks=[keras.callbacks.EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)],
    )

    test_probabilities = model.predict(test_features, batch_size=4096, verbose=0)[:, 0]
    results = {
        "test": metrics(test_probabilities, y_test),
        "test_at_0.7": metrics(test_probabilities, y_test, threshold=0.7),
        "train": metrics(model.predict(train_features, batch_size=4096, verbose=0)[:, 0], y_train),
    }
    print(json.dumps(results, indent=1))
    export(model, vectorizer, out_dir)
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=1)
    print("wrote weights.npz, vocabulary.json and metrics.json to", out_dir)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
