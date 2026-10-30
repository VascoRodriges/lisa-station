"""Independently parse the synthetic offline Adapter1 fixture with host libdbus."""

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
    result = subprocess.run([str(args.fixture.resolve()), "--wire"], capture_output=True, check=True, timeout=10)
    if len(result.stdout) > 4096:
        raise RuntimeError("oversized synthetic fixture")
    frames = json.loads(result.stdout)
    if set(frames) != {"reply"}:
        raise RuntimeError("unexpected fixture fields")
    wire = bytes.fromhex(frames["reply"])
    if not 16 <= len(wire) <= 1280:
        raise RuntimeError("invalid synthetic frame size")
    library = find_library("dbus-1")
    if not library:
        raise RuntimeError("host libdbus-1 required")
    lib = c.CDLL(library)
    lib.dbus_message_demarshal.argtypes = [c.c_char_p, c.c_int, c.c_void_p]
    lib.dbus_message_demarshal.restype = c.c_void_p
    lib.dbus_message_unref.argtypes = [c.c_void_p]
    for name in ["type", "serial", "reply_serial"]:
        function = getattr(lib, "dbus_message_get_" + name)
        function.argtypes, function.restype = [c.c_void_p], c.c_uint
    for name in ["signature", "destination", "sender"]:
        function = getattr(lib, "dbus_message_get_" + name)
        function.argtypes, function.restype = [c.c_void_p], c.c_char_p
    for name in ["init", "next", "get_arg_type", "get_element_type"]:
        function = getattr(lib, "dbus_message_iter_" + name)
        function.argtypes = [c.c_void_p, c.c_void_p] if name == "init" else [c.c_void_p]
        function.restype = c.c_int
    lib.dbus_message_iter_recurse.argtypes = [c.c_void_p, c.c_void_p]
    lib.dbus_message_iter_get_basic.argtypes = [c.c_void_p, c.c_void_p]
    checks = 0

    def require(good):
        nonlocal checks
        checks += 1
        if not good:
            raise RuntimeError(f"adapter wire check {checks} failed")

    def iterator():
        return (c.c_uint64 * 32)()  # Opaque, overallocated and uint64-aligned.

    def child(parent, kind):
        require(lib.dbus_message_iter_get_arg_type(parent) == ord(kind))
        item = iterator()
        lib.dbus_message_iter_recurse(parent, item)
        return item

    def string(item, kind="s"):
        require(lib.dbus_message_iter_get_arg_type(item) == ord(kind))
        value = c.c_char_p()
        lib.dbus_message_iter_get_basic(item, c.byref(value))
        return value.value.decode("ascii")

    expected = dict(Address=("s", "02:00:00:00:00:01"), AddressType=("s", "public"),
                    Name=("s", "Lisa synthetic"), Alias=("s", "Lisa synthetic"),
                    Class=("u", 0), Powered=("b", 0), Discoverable=("b", 0),
                    DiscoverableTimeout=("u", 0), Pairable=("b", 0), PairableTimeout=("u", 0),
                    Discovering=("b", 0), UUIDs=("a", []), Modalias=("s", "usb:v0000p0000d0000"), Roles=("a", []))
    message = lib.dbus_message_demarshal(wire, len(wire), None)
    require(bool(message))
    try:
        require(lib.dbus_message_get_type(message) == 2)
        require(lib.dbus_message_get_serial(message) == 11 and lib.dbus_message_get_reply_serial(message) == 7)
        require(lib.dbus_message_get_destination(message) == b":1.2" and lib.dbus_message_get_sender(message) is None)
        require(lib.dbus_message_get_signature(message) == b"a{oa{sa{sv}}}")
        top = iterator()
        require(lib.dbus_message_iter_init(message, top))
        objects = child(top, "a")
        obj = child(objects, "e")
        require(string(obj, "o") == "/org/bluez/hci0")
        require(lib.dbus_message_iter_next(obj))
        interfaces = child(obj, "a")
        interface = child(interfaces, "e")
        require(string(interface) == "org.bluez.Adapter1")
        require(lib.dbus_message_iter_next(interface))
        properties = child(interface, "a")
        seen = set()
        for _ in range(15):
            if not lib.dbus_message_iter_get_arg_type(properties):
                break
            entry = child(properties, "e")
            key = string(entry)
            require(key in expected and key not in seen)
            seen.add(key)
            require(lib.dbus_message_iter_next(entry))
            value = child(entry, "v")
            kind, target = expected[key]
            require(lib.dbus_message_iter_get_arg_type(value) == ord(kind))
            if kind == "s":
                require(string(value) == target)
            elif kind == "a":
                require(lib.dbus_message_iter_get_element_type(value) == ord("s"))
                array = child(value, "a")
                require(lib.dbus_message_iter_get_arg_type(array) == 0)
            else:
                scalar = c.c_uint()
                lib.dbus_message_iter_get_basic(value, c.byref(scalar))
                require(scalar.value == target)
            require(not lib.dbus_message_iter_next(value) and not lib.dbus_message_iter_next(entry))
            lib.dbus_message_iter_next(properties)
        require(seen == set(expected) and not lib.dbus_message_iter_get_arg_type(properties))
        require(not lib.dbus_message_iter_next(interface) and not lib.dbus_message_iter_next(interfaces))
        require(not lib.dbus_message_iter_next(obj) and not lib.dbus_message_iter_next(objects) and not lib.dbus_message_iter_next(top))
    finally:
        lib.dbus_message_unref(message)
    print(json.dumps(dict(check="synthetic-adapter-libdbus", checks=checks, ok=True, hardware_opened=False)))


if __name__ == "__main__":
    main()
