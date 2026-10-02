import os
import joblib
from ml.text import build_text

MODEL_PATH = "models/phishing_model.joblib"
_model = None


def model_available():
    return os.path.exists(MODEL_PATH)


def predict_proba(sender, subject, body, attachment_name=""):
    """Return P(phishing) in [0,1], or None if no trained model exists. A probability is not certainty."""
    global _model
    if not model_available():
        return None
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return float(_model.predict_proba([build_text(sender, subject, body, attachment_name)])[0][1])
