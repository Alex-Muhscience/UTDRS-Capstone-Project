"""The trained phishing-email model, and the ML detector's use of it."""
import pytest

from core.detection.ml_detector import MLDetector
from core.models.ml import phishing_email_model
from core.models.ml.phishing_email_model import PhishingEmailModel, get_phishing_email_model

PHISHING = (
    "Urgent: verify your account",
    "Dear customer, we detected unusual activity on your bank account. Your account will "
    "be suspended within 24 hours unless you confirm your password and security details. "
    "Click here to verify your identity immediately.",
)
LEGITIMATE = (
    "Project review meeting moved to Thursday",
    "Hi team, the quarterly project review is moved to Thursday at 10am in the main "
    "conference room. Please send me your status reports and the updated schedule by "
    "Wednesday. Thanks, Sarah",
)


def email_event(subject, body):
    return {
        "source": "email_gateway",
        "event_type": "email",
        "data": {"sender": "someone@example.com", "subject": subject, "body": body},
    }


@pytest.fixture(scope="module")
def model():
    return PhishingEmailModel()


def test_the_model_files_load_and_agree(model):
    assert len(model.index) == 5000
    assert model.layers[0]["kernel"].shape == (5000, 256)
    assert model.layers[-1]["kernel"].shape == (64, 1)


def test_an_email_becomes_a_normalised_tfidf_vector(model):
    vector = model.vectorize("Verify your ACCOUNT, verify your password!")
    assert vector.shape == (5000,)
    assert pytest.approx(float((vector**2).sum()), abs=1e-5) == 1.0
    # Case and punctuation do not matter, and a repeated word counts for more.
    assert vector[model.index["verify"]] > vector[model.index["password"]] > 0
    assert model.vectorize("zzzzqqqq").sum() == 0


def test_phishing_and_legitimate_emails_are_told_apart(model):
    assert model.predict(" ".join(PHISHING)) > 0.95
    assert model.predict(" ".join(LEGITIMATE)) < 0.05


@pytest.mark.asyncio
async def test_the_detector_raises_phishing_from_the_trained_model():
    result = await MLDetector().detect(email_event(*PHISHING))

    assert result is not None
    assert result["name"] == "Potential Phishing Attempt"
    assert result["model"] == "phishing_email_ffnn"
    assert result["confidence"] > 0.95
    assert result["severity"] == "high"
    assert result["mitre_techniques"] == ["T1566"]


@pytest.mark.asyncio
async def test_the_detector_passes_a_legitimate_email():
    assert await MLDetector().detect(email_event(*LEGITIMATE)) is None


@pytest.mark.asyncio
async def test_an_email_the_model_cannot_judge_falls_back_to_indicators():
    detector = MLDetector()
    # Too few words the model knows: it would be guessing.
    assert detector._score_email_with_model(email_event("hello", "")) is None


@pytest.mark.asyncio
async def test_the_detector_works_without_the_model_files(monkeypatch):
    monkeypatch.setattr(phishing_email_model, "_model", None)
    monkeypatch.setattr(phishing_email_model, "_load_failed", False)
    monkeypatch.setattr(phishing_email_model, "ARTIFACT_DIR", "/nonexistent")

    assert get_phishing_email_model() is None
    assert MLDetector()._score_email_with_model(email_event(*PHISHING)) is None
