"""Validate the synthetic codec's wire images with the host libdbus parser.

Loads no firmware and opens no connection, bus, hardware or audio stream.
This is a host development check, not a runtime dependency of the integration.
"""

import argparse
import ctypes as c
import json
import subprocess
from ctypes.util import find_library
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    result = subprocess.run(
        [str(args.fixture.resolve()), "--wire"], capture_output=True, check=True, timeout=10,
    )
    if len(result.stdout) > 4096:
        raise RuntimeError("oversized synthetic fixture result")
    frames = json.loads(result.stdout)
    if set(frames) != {"request", "reply"}:
        raise RuntimeError("unexpected synthetic fixture fields")
    library = find_library("dbus-1")
    if not library:
        raise RuntimeError("host libdbus-1 is required for independent wire validation")
    lib = c.CDLL(library)
    lib.dbus_message_demarshal.argtypes = [c.c_char_p, c.c_int, c.c_void_p]
    lib.dbus_message_demarshal.restype = c.c_void_p
    lib.dbus_message_unref.argtypes = [c.c_void_p]
    for name in ["get_type", "get_serial", "get_reply_serial"]:
        function = getattr(lib, "dbus_message_" + name)
        function.argtypes = [c.c_void_p]
        function.restype = c.c_uint
    for name in ["get_signature", "get_destination", "get_sender", "get_interface", "get_member", "get_path"]:
        function = getattr(lib, "dbus_message_" + name)
        function.argtypes = [c.c_void_p]
        function.restype = c.c_char_p
    lib.dbus_message_iter_init.argtypes = [c.c_void_p, c.c_void_p]
    lib.dbus_message_iter_init.restype = c.c_int
    lib.dbus_message_iter_get_arg_type.argtypes = [c.c_void_p]
    lib.dbus_message_iter_get_arg_type.restype = c.c_int
    lib.dbus_message_iter_recurse.argtypes = [c.c_void_p, c.c_void_p]
    lib.dbus_message_iter_next.argtypes = [c.c_void_p]
    lib.dbus_message_iter_next.restype = c.c_int
    checks = 0

    def require(good):
        nonlocal checks
        checks += 1
        if not good:
            raise RuntimeError(f"independent wire check {checks} failed")

    for kind in ["request", "reply"]:
        wire = bytes.fromhex(frames[kind])
        require(16 <= len(wire) <= 8192)
        message = lib.dbus_message_demarshal(wire, len(wire), None)
        require(bool(message))
        try:
            require(lib.dbus_message_get_type(message) == (1 if kind == "request" else 2))
            require(lib.dbus_message_get_serial(message) == (7 if kind == "request" else 11))
            require(lib.dbus_message_get_destination(message) == (b"org.bluez" if kind == "request" else b":1.2"))
            require(lib.dbus_message_get_signature(message) == (b"" if kind == "request" else b"a{oa{sa{sv}}}"))
            require(lib.dbus_message_get_sender(message) == (b":1.2" if kind == "request" else None))
            # Overallocate opaque iterators with uint64 alignment; no fields are accessed.
            iterator = (c.c_uint64 * 32)()
            require(bool(lib.dbus_message_iter_init(message, iterator)) == (kind == "reply"))
            if kind == "request":
                require(lib.dbus_message_get_path(message) == b"/")
                require(lib.dbus_message_get_interface(message) == b"org.freedesktop.DBus.ObjectManager")
                require(lib.dbus_message_get_member(message) == b"GetManagedObjects")
            else:
                require(lib.dbus_message_get_reply_serial(message) == 7)
                require(lib.dbus_message_iter_get_arg_type(iterator) == ord("a"))
                child = (c.c_uint64 * 32)()
                lib.dbus_message_iter_recurse(iterator, child)
                require(lib.dbus_message_iter_get_arg_type(child) == 0)
                require(not lib.dbus_message_iter_next(iterator))
        finally:
            lib.dbus_message_unref(message)
    print(json.dumps(dict(check="private-empty-objects-libdbus", checks=checks, ok=True, synthetic_only=True)))


if __name__ == "__main__":
    main()
