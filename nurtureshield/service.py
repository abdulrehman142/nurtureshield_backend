"""Corrected-v1 local-only inference; never resolve or contact submitted hosts."""

import json
import math
import warnings
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from .features import FEATURE_NAMES, SCHEMA_VERSION, feature_frame
from .characteristics import explain_url_features

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


class ModelUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ModelBundle:
    model: object
    threshold: float
    feature_names: tuple[str, ...]
    malicious_index: int


def validate_config(config):
    threshold = config.get("threshold")
    if (
        config.get("model") != "HistGradientBoostingClassifier"
        or config.get("artifact_name") != "hist_gradient_boosting.joblib"
        or config.get("schema_version") != SCHEMA_VERSION
        or config.get("canonicalization_version") != SCHEMA_VERSION
        or config.get("scheme_canonicalization_enabled") is not True
        or config.get("uses_https_removed") is not True
        or config.get("feature_count") != 31
        or len(FEATURE_NAMES) != 31
        or "uses_https" in FEATURE_NAMES
        or config.get("feature_names") != list(FEATURE_NAMES)
        or type(threshold) not in (int, float)
        or not math.isfinite(threshold)
        or not 0 < threshold < 1
        or threshold != 0.30
        or config.get("label_mapping")
        != {"benign": 0, "phishing": 1, "defacement": 1, "malware": 1}
    ):
        raise ValueError("Corrected model configuration mismatch")


class Predictor:
    def __init__(self, directory=MODEL_DIR):
        self.directory = Path(directory)
        self._bundle = None
        self._lock = Lock()

    def _load(self):
        if self._bundle is not None:
            return self._bundle
        try:
            import joblib
            import sklearn
            from sklearn.ensemble import HistGradientBoostingClassifier
            from sklearn.exceptions import InconsistentVersionWarning

            config = json.loads((self.directory / "final_model_config.json").read_text())
            validate_config(config)
            if config.get("sklearn") != sklearn.__version__:
                raise ValueError("Model serialization runtime mismatch")
            with warnings.catch_warnings():
                warnings.simplefilter("error", InconsistentVersionWarning)
                model = joblib.load(self.directory / config["artifact_name"])
            classes = list(model.classes_)
            if (
                not isinstance(model, HistGradientBoostingClassifier)
                or model.n_features_in_ != 31
                or list(model.feature_names_in_) != config["feature_names"]
                or len(classes) != 2
                or set(classes) != {0, 1}
                or not callable(getattr(model, "predict_proba", None))
            ):
                raise ValueError("Corrected model schema mismatch")
            self._bundle = ModelBundle(
                model,
                float(config["threshold"]),
                tuple(config["feature_names"]),
                classes.index(config["label_mapping"]["phishing"]),
            )
            return self._bundle
        except Exception as exc:
            raise ModelUnavailable("NurtureShield model is unavailable.") from exc

    def predict(self, url):
        with self._lock:
            bundle = self._load()
            frame = feature_frame([url])
            if tuple(frame.columns) != bundle.feature_names or frame.shape != (1, 31):
                raise ValueError("Extractor schema mismatch")
            from threadpoolctl import threadpool_limits

            with threadpool_limits(limits=1):
                probabilities = bundle.model.predict_proba(frame)
            if probabilities.shape != (1, 2):
                raise ValueError("Invalid model response shape")
            probability = float(probabilities[0, bundle.malicious_index])
        return result_for(url, frame.iloc[0].to_dict(), probability, bundle.threshold)


def result_for(url, features, probability, threshold):
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError("Invalid model probability")
    return {
        "url": url,
        "prediction": "malicious" if probability >= threshold else "legitimate",
        "malicious_probability": probability,
        "risk_level": (
            "high"
            if probability >= 0.80
            else "elevated"
            if probability >= 0.50
            else "moderate"
            if probability >= 0.20
            else "low"
        ),
        "observed_characteristics": explain_url_features(features),
    }


predictor = Predictor()
