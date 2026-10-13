from readers import read_field
from writers import send_command


def entry():
    value = read_field()
    send_command(value)


def constant():
    _unused = read_field()
    send_command("constant")


def unknown(callback):
    value = read_field()
    send_command(callback(value))


def shadowed(read_field):
    value = read_field()
    send_command(value)
