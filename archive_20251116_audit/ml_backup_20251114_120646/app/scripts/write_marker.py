import os
from ..core.config import settings


def main():
    paths = [
        os.path.abspath(settings.model_storage_path),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "models", "saved")),
    ]
    for p in paths:
        try:
            os.makedirs(p, exist_ok=True)
            marker = os.path.join(p, "WRITE_TEST.txt")
            with open(marker, "w", encoding="utf-8") as f:
                f.write("ok")
            print(f"Wrote marker: {marker}")
        except Exception as e:
            print(f"Failed to write marker in {p}: {e}")


if __name__ == "__main__":
    main()