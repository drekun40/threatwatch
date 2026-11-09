"""Loading and saving configuration (YAML files + .env secrets)."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"
EXPORTS_DIR = ROOT / "exports"

FACILITIES_FILE = CONFIG_DIR / "facilities.yaml"
KEYWORDS_FILE = CONFIG_DIR / "keywords.yaml"
SOURCES_FILE = CONFIG_DIR / "sources.yaml"
SOURCES_LOCAL_FILE = CONFIG_DIR / "sources.local.yaml"   # dashboard edits; overrides sources.yaml, keeps its comments
ENV_FILE = ROOT / ".env"
FILTERS_FILE = CONFIG_DIR / "filters.yaml"
DB_FILE = DATA_DIR / "threatwatch.db"

for d in (DATA_DIR, REPORTS_DIR, EXPORTS_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _load_dotenv() -> None:
    """Minimal .env loader so python-dotenv is optional."""
    env_file = ENV_FILE
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value if value not in ("", None) else default


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_yaml(path: Path, data: dict, header: str = "") -> None:
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120)
    with open(path, "w", encoding="utf-8") as f:
        if header:
            f.write(header.rstrip() + "\n\n")
        f.write(text)


def load_facilities() -> dict:
    return load_yaml(FACILITIES_FILE)


def load_keywords() -> dict:
    return load_yaml(KEYWORDS_FILE)


def deep_merge(base: dict, over: dict) -> dict:
    """Dicts merge key by key; any other value (lists included) in `over` replaces the one in `base`."""
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_sources() -> dict:
    base = load_yaml(SOURCES_FILE)
    if SOURCES_LOCAL_FILE.exists():
        base = deep_merge(base, load_yaml(SOURCES_LOCAL_FILE))
    return base


def save_source_settings(name: str, settings: dict) -> None:
    """Store dashboard changes for one source in sources.local.yaml (sources.yaml stays as written)."""
    local = load_yaml(SOURCES_LOCAL_FILE) if SOURCES_LOCAL_FILE.exists() else {}
    local.setdefault("sources", {})
    local["sources"][name] = deep_merge(local["sources"].get(name, {}), settings)
    save_yaml(SOURCES_LOCAL_FILE, local, "# Written by the dashboard (Admin > Data sources). Overrides config/sources.yaml.")


def set_env(updates: dict[str, str]) -> None:
    """Write keys into .env (replacing existing lines, appending new ones) and apply them to this process."""
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    done = set()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in updates:
            lines[i] = f"{key}={updates[key]}"
            done.add(key)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in done]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass
    for k, v in updates.items():
        os.environ[k] = v


KEYWORDS_HEADER = """# Threat keywords, grouped by category. Managed from the dashboard (Keywords tab) or by hand.
# weight 0–10: severity of a hit in that category. weight 0 = context only (boosts, never triggers).
# Terms match case-insensitively on word boundaries; simple plurals (s/es) match automatically."""

FACILITIES_HEADER = """# Monitored facilities. Managed from the dashboard (Facilities tab) or by hand.
# aliases always count; ambiguous aliases only count when a Buffalo context term is also present.
# lat/lon are approximate centre points — verify before enabling X geo search."""


def load_filters() -> dict:
    return load_yaml(FILTERS_FILE) if FILTERS_FILE.exists() else {}
