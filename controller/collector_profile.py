"""Transform trusted stock configuration for a jailed collector, without secrets in output.

The result contains the caller's private firmware configuration. Never publish
it. Filesystem containment, not this JSON filter alone, enforces the boundary.
"""

from copy import deepcopy


def prepare_collector_profile(stock, *, lab_clone=False):
    if type(lab_clone) is not bool:
        raise ValueError("invalid collector profile mode")
    result = deepcopy(stock)
    try:
        section = result["fluent-bitd"]
        fluent = section["fluent-bit"]
        paths = fluent["tailPaths"]
        if not isinstance(paths, list) or not paths or any(type(p) is not str for p in paths):
            raise ValueError("invalid collector inputs")
        if len(paths) != len(set(paths)) or set(paths) - {
            "${LOGS}/*.log",
            "/var/log/messages",
            "/tmp/messages",
        }:
            raise ValueError("unreviewed collector input")
        if "${LOGS}/*.log" not in paths or not set(paths) & {"/var/log/messages", "/tmp/messages"}:
            raise ValueError("stock collector inputs changed")
        if fluent["variables"]["tailDbFile"] != "${TMP}/fluent-bit.db":
            raise ValueError("stock collector queue changed")
        if result["patterns"]["TMP"] != "/tmp" or result["patterns"]["DATA"] != "/data/quasar":
            raise ValueError("unreviewed stock filesystem layout")
        logging = section["Logging"]["file"]
        if logging["fileName"] != "${LOGS}/fluent-bitd.log" or logging["enabled"] is not True:
            raise ValueError("stock collector logging changed")
        if type(section["Minidump"]["enabled"]) is not bool:
            raise ValueError("invalid collector crash configuration")
        if type(section["port"]) is not int or not 1024 <= section["port"] <= 65535:
            raise ValueError("invalid collector IPC port")
        fluent["tailPaths"] = ["${LOGS}/*.log"]
        fluent["variables"]["tailDbFile"] = "/tmp/lisa-collector/tail.db"
        logging["fileName"] = "/tmp/lisa-collector/collector.log"
        section["Minidump"]["enabled"] = False
        if lab_clone:
            if section["port"] == 57344:
                raise ValueError("laboratory IPC port already used by stock")
            section["port"] = 57344
    except (KeyError, TypeError) as error:
        raise ValueError("unsupported stock collector configuration") from error
    return result
