from reader import read_public, read_selected


def selected(name: str) -> str:
    return read_selected(name)


def public(name: str) -> str:
    return read_public()
