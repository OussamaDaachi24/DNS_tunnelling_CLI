from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
import warnings

import joblib

from feature_extraction import EXPECTED_FEATURES


@lru_cache(maxsize=4)
def load_model(model_path: str) -> tuple[Any, list[str]]:
    artifact = joblib.load(Path(model_path))
    if isinstance(artifact, dict):
        model = artifact.get("model")
        feature_names = artifact.get("features") or artifact.get("feature_names")
    else:
        model = artifact
        feature_names = getattr(model, "feature_names_in_", None)

    if model is None:
        raise ValueError("Model artifact did not contain a 'model' object.")

    if feature_names is None:
        feature_names = EXPECTED_FEATURES

    feature_names = [str(name) for name in feature_names]
    missing = [name for name in feature_names if name not in EXPECTED_FEATURES]
    if missing:
        raise ValueError(f"Unsupported model feature schema: {missing}")

    for estimator in getattr(model, "estimators_", []):
        if hasattr(estimator, "n_jobs"):
            estimator.n_jobs = 1
    for estimator in getattr(model, "named_estimators_", {}).values():
        if hasattr(estimator, "n_jobs"):
            estimator.n_jobs = 1

    return model, feature_names


def predict(
    model: Any,
    feature_names: list[str],
    features: dict[str, float],
    threshold: float = 0.5,
) -> tuple[float, float, str, dict[str, float]]:
    vector = [[float(features.get(name, 0.0)) for name in feature_names]]
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="X does not have valid feature names",
            category=UserWarning,
        )
        probabilities = model.predict_proba(vector)[0]
    tunnel_index = _positive_class_index(model)
    benign_index = 0 if tunnel_index == 1 else 1

    p_tunnel = float(probabilities[tunnel_index])
    p_benign = float(probabilities[benign_index])
    decision = "TUNNEL" if p_tunnel >= threshold else "BENIGN"

    base_probs: dict[str, float] = {}
    named_estimators = getattr(model, "named_estimators_", {})
    for name, estimator in named_estimators.items():
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="X does not have valid feature names",
                category=UserWarning,
            )
            estimator_probabilities = estimator.predict_proba(vector)[0]
        base_probs[str(name)] = float(estimator_probabilities[tunnel_index])

    return p_tunnel, p_benign, decision, base_probs


def _positive_class_index(model: Any) -> int:
    classes = list(getattr(model, "classes_", [0, 1]))
    if 1 in classes:
        return classes.index(1)
    return len(classes) - 1
