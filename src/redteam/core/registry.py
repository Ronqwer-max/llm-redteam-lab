"""Attack plugin registry.

Attacks register themselves with the :func:`register` decorator; the CLI and
runner resolve configured attack ids through :func:`get` / :func:`available`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:  # pragma: no cover
    from ..attacks.base import Attack

_REGISTRY: dict[str, type["Attack"]] = {}

T = TypeVar("T", bound="type[Attack]")


def register(attack_id: str):
    """Class decorator that adds an attack to the registry under ``attack_id``."""

    def deco(cls: T) -> T:
        cls.attack_id = attack_id
        _REGISTRY[attack_id] = cls
        return cls

    return deco


def get(attack_id: str) -> type["Attack"]:
    try:
        return _REGISTRY[attack_id]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "<none>"
        raise KeyError(f"unknown attack {attack_id!r} (known: {known})") from None


def available() -> list[str]:
    return sorted(_REGISTRY)
