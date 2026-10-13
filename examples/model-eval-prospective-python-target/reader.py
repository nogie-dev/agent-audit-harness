from pathlib import Path


def read_selected(name: str) -> str:
    return Path(name).read_text()


def read_public() -> str:
    return Path("public.txt").read_text()
