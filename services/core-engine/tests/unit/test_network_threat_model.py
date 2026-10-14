"""The network threat model, and the ML detector's use of it."""
import os

import numpy as np
import pytest

from core.detection.ml_detector import MLDetector
from core.models.ml import network_threat_model
from core.models.ml.network_threat_model import ARTIFACT_DIR, NetworkThreatModel, get_network_threat_model


@pytest.fixture(scope="module")
def model():
    return NetworkThreatModel()


@pytest.fixture(scope="module")
def reference():
    # Flows from the test partition, with the probabilities Keras gave them in training.
    with np.load(os.path.join(ARTIFACT_DIR, "reference.npz")) as data:
        return data["raw"], data["probabilities"]


def flow_event(model, raw):
    return {
        "source": "flow_sensor",
        "event_type": "network",
        "data": {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "flow": dict(zip(model.features, map(float, raw)))},
    }


def test_the_numpy_model_matches_the_trained_keras_model(model, reference):
    raw, expected = reference
    got = np.array([[model.predict(row)[c] for c in model.classes] for row in raw])
    assert np.abs(got - expected).max() < 1e-4


def test_its_files_describe_21_features_and_10_classes(model):
    assert len(model.features) == 21
    assert model.classes[0] == "Normal" and len(model.classes) == 10


@pytest.mark.asyncio
async def test_a_flow_the_model_is_sure_is_an_attack_raises_a_detection(model, reference):
    raw, expected = reference
    attack = raw[np.argmax(1 - expected[:, 0])]

    result = await MLDetector().detect(flow_event(model, attack))

    assert result is not None
    assert result["model"] == "network_threat_cnn_lstm"
    assert result["confidence"] > 0.95
    assert result["attack_category"] in model.classes[1:]
    assert result["mitre_techniques"]


@pytest.mark.asyncio
async def test_a_normal_flow_raises_nothing(model, reference):
    raw, expected = reference
    normal = raw[np.argmax(expected[:, 0])]
    assert await MLDetector().detect(flow_event(model, normal)) is None


def test_a_record_without_every_measurement_is_left_to_the_indicators(model, reference):
    raw, _ = reference
    flow = flow_event(model, raw[0])["data"]["flow"]
    del flow["sbytes"]
    assert MLDetector()._classify_flow_with_model({"flow": flow}) is None
    assert MLDetector()._classify_flow_with_model({"bytes_sent": 100}) is None


def test_the_detector_works_without_the_model_files(monkeypatch):
    monkeypatch.setattr(network_threat_model, "_model", None)
    monkeypatch.setattr(network_threat_model, "_load_failed", False)
    monkeypatch.setattr(network_threat_model, "ARTIFACT_DIR", "/nonexistent")
    assert get_network_threat_model() is None
