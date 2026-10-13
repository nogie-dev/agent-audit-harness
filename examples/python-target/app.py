import auditpkg.ops
from auditpkg import normalize as clean
from auditpkg.worker import run as process


def entry(value: str) -> str:
    return process(auditpkg.ops.stage(clean(value)))


def dynamic(callback, obj, name, value):
    callback(value)
    obj.run(value)
    return getattr(obj, name)(value)
