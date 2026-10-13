import os

from worker import execute


def raw():
    value = input()
    copied = value
    os.system(copied)  # nosemgrep: target suppression must not hide evidence


def constant():
    _unused = input()
    os.system("constant")


def across_files():
    value = input()
    execute(value)


def dynamic(callback):
    value = input()
    changed = callback(value)
    os.system(changed)
