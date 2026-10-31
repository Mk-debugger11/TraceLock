import yaml

DEFAULTS = {
    "upload_dir": "instance/avatars",
    "export_path": "instance/notes-export.csv",
    "home_city": None,
}


def read_settings(path):
    """Read the YAML config; safe_load only builds plain dicts, lists and scalars."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    merged = dict(DEFAULTS)
    merged.update(data)
    missing = [key for key in ("secret_key", "notes_key") if not merged.get(key)]
    if missing:
        raise RuntimeError(f"config is missing {', '.join(missing)}")
    return merged
