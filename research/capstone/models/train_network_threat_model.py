"""
Train the network threat model and export it for the core engine.

    pip install tensorflow pandas numpy
    python train_network_threat_model.py <UNSW-NB15 directory> ../../../services/core-engine/core/models/ml/network_threat

The directory needs the UNSW-NB15 partitioned sets, UNSW_NB15_training-set.csv and
UNSW_NB15_testing-set.csv (Moustafa and Slay, 2015; UNSW Canberra). As commonly
noted, the files are named the wrong way round: the 175,341-flow file called
"testing-set" is the official training partition, and the 82,332-flow
"training-set" is the test partition. This script uses them as intended.

Why "afresh": advanced_threat_detection_model.h5 has this architecture (21 inputs, a
CNN-LSTM, 10 output classes), but its training script was empty and nothing records
its input features, their scaling or what its 10 classes mean, so its output cannot
be read. This rebuilds a model of the same shape on a dataset with 10 classes, and
writes down everything needed to use it.

Features: 21 per-flow measurements that a flow sensor (Argus, Zeek and the like)
reports for a single connection. Left out on purpose:
- sttl, dttl and ct_state_ttl: IP time-to-live values that separate attacks from
  normal traffic in this dataset because of how its test bed was built, not because
  of the attacks. Models that use them score well here and poorly elsewhere.
- the ct_* counters: they count earlier connections in a window, which the engine
  does not see when it judges one flow.
- proto, service and state: categories, not measurements.
"""
import json
import os
import sys

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean",
]
CLASSES = [
    "Normal", "Analysis", "Backdoor", "DoS", "Exploits", "Fuzzers", "Generic",
    "Reconnaissance", "Shellcode", "Worms",
]
SEED = 42


def load(directory):
    train = pd.read_csv(os.path.join(directory, "UNSW_NB15_testing-set.csv"))   # 175,341 flows
    test = pd.read_csv(os.path.join(directory, "UNSW_NB15_training-set.csv"))    # 82,332 flows
    assert len(train) > len(test), "expected the larger file to be the training partition"
    return train, test


def scaling(frame):
    """Flow sizes and rates span many orders of magnitude: log first, then standardise."""
    logged = np.log1p(frame[FEATURES].clip(lower=0).to_numpy(np.float64))
    return logged.mean(axis=0), logged.std(axis=0) + 1e-6


def prepare(frame, mean, std):
    logged = np.log1p(frame[FEATURES].clip(lower=0).to_numpy(np.float64))
    x = ((logged - mean) / std).astype(np.float32)[..., np.newaxis]
    y = frame["attack_cat"].str.strip().map({c: i for i, c in enumerate(CLASSES)}).to_numpy()
    assert not np.isnan(y.astype(float)).any(), "unknown attack category"
    return x, y.astype(np.int64)


def build_model():
    """The architecture of advanced_threat_detection_model.h5."""
    inputs = keras.Input(shape=(len(FEATURES), 1))
    x = layers.Conv1D(64, 3, activation="relu")(inputs)
    x = layers.MaxPooling1D(2)(x)
    x = layers.Conv1D(128, 3, activation="relu")(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.LSTM(128, return_sequences=True)(x)
    x = layers.LSTM(128)(x)
    x = layers.Dense(256, activation="relu")(x)
    x = layers.Dropout(0.5)(x)
    outputs = layers.Dense(len(CLASSES), activation="softmax")(x)
    model = keras.Model(inputs, outputs)
    model.compile(optimizer=keras.optimizers.Adam(1e-3), loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


def metrics(probabilities, y):
    predicted = probabilities.argmax(axis=1)
    per_class = {}
    for i, name in enumerate(CLASSES):
        tp = int(((predicted == i) & (y == i)).sum())
        support = int((y == i).sum())
        flagged = int((predicted == i).sum())
        per_class[name] = {
            "flows": support,
            "precision": round(tp / flagged, 4) if flagged else None,
            "recall": round(tp / support, 4) if support else None,
        }
    attack, said_attack = y != 0, predicted != 0
    return {
        "flows": len(y),
        "accuracy": round(float((predicted == y).mean()), 4),
        # The question the engine answers first: is this flow an attack at all?
        "attack_vs_normal": {
            "accuracy": round(float((attack == said_attack).mean()), 4),
            "precision": round(float((attack & said_attack).sum() / said_attack.sum()), 4),
            "recall": round(float((attack & said_attack).sum() / attack.sum()), 4),
            "false_positive_rate": round(float((~attack & said_attack).sum() / (~attack).sum()), 4),
        },
        "per_class": per_class,
    }


def export(model, mean, std, out_dir):
    """Weights as plain arrays, named for the engine's NumPy implementation."""
    arrays = {}
    convs = [l for l in model.layers if isinstance(l, layers.Conv1D)]
    lstms = [l for l in model.layers if isinstance(l, layers.LSTM)]
    denses = [l for l in model.layers if isinstance(l, layers.Dense)]
    for i, layer in enumerate(convs):
        arrays[f"conv_{i}_kernel"], arrays[f"conv_{i}_bias"] = layer.get_weights()
    for i, layer in enumerate(lstms):
        # Keras orders each LSTM's gates input, forget, cell, output.
        arrays[f"lstm_{i}_kernel"], arrays[f"lstm_{i}_recurrent"], arrays[f"lstm_{i}_bias"] = layer.get_weights()
    for i, layer in enumerate(denses):
        arrays[f"dense_{i}_kernel"], arrays[f"dense_{i}_bias"] = layer.get_weights()
    os.makedirs(out_dir, exist_ok=True)
    np.savez_compressed(os.path.join(out_dir, "weights.npz"), **{k: v.astype(np.float32) for k, v in arrays.items()})
    with open(os.path.join(out_dir, "features.json"), "w") as f:
        json.dump(
            {
                "features": FEATURES,
                "classes": CLASSES,
                "scaling": "log1p of each feature (negative values clipped to 0), then (x - mean) / std",
                "mean": [round(float(v), 8) for v in mean],
                "std": [round(float(v), 8) for v in std],
            },
            f,
            indent=1,
        )


def main(data_dir, out_dir):
    tf.keras.utils.set_random_seed(SEED)
    train, test = load(data_dir)
    mean, std = scaling(train)
    x_train, y_train = prepare(train, mean, std)
    x_test, y_test = prepare(test, mean, std)

    rng = np.random.default_rng(SEED)
    order = rng.permutation(len(x_train))
    validation = order[: len(order) // 10]
    fit = order[len(order) // 10 :]

    model = build_model()
    model.fit(
        x_train[fit], y_train[fit],
        validation_data=(x_train[validation], y_train[validation]),
        epochs=80, batch_size=512, verbose=2,
        callbacks=[
            keras.callbacks.ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=3, min_lr=1e-5),
            keras.callbacks.EarlyStopping(monitor="val_loss", patience=8, restore_best_weights=True),
        ],
    )

    results = {"test": metrics(model.predict(x_test, batch_size=4096, verbose=0), y_test),
               "train": metrics(model.predict(x_train, batch_size=4096, verbose=0), y_train)}
    print(json.dumps(results, indent=1))
    export(model, mean, std, out_dir)
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=1)
    # A reference the engine's tests can check their NumPy forward pass against.
    sample = x_test[:: max(len(x_test) // 50, 1)][:50]
    np.savez_compressed(
        os.path.join(out_dir, "reference.npz"),
        raw=test[FEATURES].to_numpy(np.float64)[:: max(len(x_test) // 50, 1)][:50],
        probabilities=model.predict(sample, verbose=0),
    )
    print("wrote weights.npz, features.json, metrics.json and reference.npz to", out_dir)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
