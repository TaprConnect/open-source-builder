"""Versioned, strictly validated operator configuration (F01-CLI).

The file must live outside the target repository and its Git metadata, because a
target-controlled configuration could loosen analysis limits. Unknown keys, wrong
types, out-of-range values and other versions are refused.
"""
import json

VERSION = 1
_MIB = 1024 * 1024
SCHEMA = {
    "analysis": {"cpu": (1, 600), "memory": (32, 16384), "budget": (1, 86400)},
    "cache": {"max_entries": (1, 10 ** 7), "max_bytes": (1, 2 ** 40), "retention_days": (0, 3650)},
    "budget": {"max_blob": (1, 128 * _MIB), "max_total": (1, 128 * _MIB)},
}
DEFAULTS = {
    "analysis": {"cpu": 10, "memory": 512, "budget": 600},
    "cache": {"max_entries": 100000, "max_bytes": 256 * _MIB, "retention_days": 30},
    "budget": {"max_blob": 2 * _MIB, "max_total": 32 * _MIB},
}


def validate(document):
    if not isinstance(document, dict) or type(document.get("version")) is not int:
        raise ValueError("configuration must be a JSON object with an integer version")
    if document["version"] != VERSION:
        raise ValueError(f"unsupported configuration version {document['version']}; expected {VERSION}")
    unknown = set(document) - set(SCHEMA) - {"version"}
    if unknown:
        raise ValueError(f"unknown configuration keys: {sorted(unknown)}")
    for section, fields in SCHEMA.items():
        values = document.get(section, {})
        if not isinstance(values, dict) or set(values) - set(fields):
            raise ValueError(f"invalid configuration section {section}")
        for name, value in values.items():
            low, high = fields[name]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{section}.{name} must be an integer from {low} to {high}")
    return document


def load(repo, path):
    """Load and validate a private configuration file; None means built-in defaults."""
    if path is None:
        return {"version": VERSION}
    source = repo.private_path(path)
    try:
        document = json.loads(source.read_bytes())
    except ValueError as exc:
        raise ValueError(f"configuration is not valid JSON: {exc}") from exc
    return validate(document)


def resolve(document, section, name, override):
    """Command-line flag, else configuration file, else built-in default."""
    if override is not None:
        low, high = SCHEMA[section][name]
        if not low <= override <= high:
            raise ValueError(f"--{section}-{name} must be from {low} to {high}")
        return override
    return document.get(section, {}).get(name, DEFAULTS[section][name])
