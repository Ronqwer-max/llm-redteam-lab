import pytest

from redteam import attacks  # noqa: F401 - registers attacks
from redteam.core import registry
from redteam.core.config import DEFAULTS, load_config


def test_all_five_techniques_registered():
    expected = {
        "direct_injection",
        "jailbreak",
        "agent_escalation",
        "memory_extraction",
        "multimodal_injection",
    }
    assert expected.issubset(set(registry.available()))


def test_registry_get_unknown_raises():
    with pytest.raises(KeyError, match="unknown attack"):
        registry.get("does_not_exist")


def test_registered_classes_carry_metadata():
    for attack_id in registry.available():
        cls = registry.get(attack_id)
        assert cls.attack_id == attack_id
        assert cls.technique
        assert cls.description


def test_load_config_defaults_and_merge(tmp_path):
    pure = load_config(None)
    assert pure == DEFAULTS

    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text('[run]\nname = "x"\n[attacks.jailbreak]\nbudget = 5\n')
    cfg = load_config(cfg_file)
    assert cfg["run"]["name"] == "x"
    # merged-over defaults survive
    assert cfg["attacks"]["jailbreak"]["generations"] == 3
    assert cfg["attacks"]["jailbreak"]["budget"] == 5


def test_missing_config_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.toml")
