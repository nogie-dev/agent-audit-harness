from .shared import normalize


def run(value):
    return helper(normalize(value))


def helper(value):
    return value
