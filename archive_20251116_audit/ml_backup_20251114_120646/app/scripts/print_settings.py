import os
import json

from ..core.config import settings


def main():
    data = {
        "model_storage_path": os.path.abspath(settings.model_storage_path),
        "temp_model_path": os.path.abspath(settings.temp_model_path),
    }
    out_path = os.path.join(os.path.dirname(__file__), "settings_dump.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()