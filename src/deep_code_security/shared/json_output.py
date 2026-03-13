"""Structured JSON serialization helpers for Pydantic models."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

__all__ = ["serialize_model", "serialize_models", "to_json_dict", "to_json_string"]


def serialize_model(model: BaseModel) -> dict[str, Any]:
    """Serialize a Pydantic model to a JSON-compatible dict.

    Args:
        model: Pydantic model instance.

    Returns:
        Dictionary suitable for JSON serialization.
    """
    return model.model_dump(mode="json")


def serialize_models(models: list[BaseModel]) -> list[dict[str, Any]]:
    """Serialize a list of Pydantic models to JSON-compatible dicts.

    Args:
        models: List of Pydantic model instances.

    Returns:
        List of dictionaries suitable for JSON serialization.
    """
    return [m.model_dump(mode="json") for m in models]


def to_json_dict(obj: BaseModel | list[BaseModel] | dict[str, Any]) -> Any:
    """Convert an object to a JSON-compatible representation.

    Args:
        obj: Pydantic model, list of models, or plain dict.

    Returns:
        JSON-compatible object.
    """
    if isinstance(obj, BaseModel):
        return serialize_model(obj)
    if isinstance(obj, list):
        return [to_json_dict(item) for item in obj]
    return obj


def to_json_string(obj: BaseModel | list[BaseModel] | dict[str, Any]) -> str:
    """Serialize an object to a JSON string.

    Args:
        obj: Pydantic model, list of models, or plain dict.

    Returns:
        JSON-formatted string.
    """
    return json.dumps(to_json_dict(obj), indent=2, ensure_ascii=False)
