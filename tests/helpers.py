import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.assessment import load_advisories  # noqa: E402

DB_PATH = ROOT / "data" / "advisories.json"


def load_db():
    return load_advisories(DB_PATH)
