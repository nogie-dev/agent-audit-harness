def normalize(value: str) -> str:
    return value.strip()


def recurse(value):
    if value:
        return recurse(value - 1)
    return value
