"""Split trusted firmware startup without publishing its private configuration."""

from copy import deepcopy

TASKS = {
    "mediad": ("--mediad", 3, 10),
    "maind": ("--platformd", 1, 600),
    "telemetry": ("--telemetry", 0, 600),
    "fluent-bitd": ("--fluent-bitd", 0, 600),
}


def prepare_platform_launch(stock):
    result = deepcopy(stock)
    try:
        if not isinstance(result, dict) or set(result) != {"nodes"}:
            raise ValueError("unreviewed launcher schema")
        nodes = result["nodes"]
        if not isinstance(nodes, list) or len(nodes) != 1:
            raise ValueError("unreviewed launcher nodes")
        node = nodes[0]
        if set(node) != {"name", "root", "tasks"} or node["name"] != "main" or node["root"] != ".":
            raise ValueError("unreviewed launcher node")
        tasks = node["tasks"]
        if not isinstance(tasks, list) or len(tasks) != 4:
            raise ValueError("unreviewed launcher task count")
        names = set()
        required = {"name", "delay", "allowedRestartIntervalSeconds", "root", "path", "arg", "order", "log"}
        for task in tasks:
            if not isinstance(task, dict) or not required <= set(task) <= required | {"envs"}:
                raise ValueError("unreviewed launcher task schema")
            name = task["name"]
            if type(name) is not str or name not in TASKS or name in names:
                raise ValueError("unknown or duplicate launcher task")
            names.add(name)
            flag, order, restart = TASKS[name]
            if task["root"] != "." or task["path"] != "/system/vendor/quasar/maind" or task["arg"] != [flag]:
                raise ValueError("unreviewed launcher command")
            for key, expected in (("delay", 5), ("order", order), ("allowedRestartIntervalSeconds", restart)):
                if type(task[key]) is not int or task[key] != expected:
                    raise ValueError("unreviewed launcher timing")
            if task["log"] is not False:
                raise ValueError("unreviewed launcher logging")
            envs = task.get("envs", [])
            if not isinstance(envs, list):
                raise ValueError("unreviewed launcher environment")
            seen = set()
            for entry in envs:
                if type(entry) is not str or "=" not in entry:
                    raise ValueError("invalid launcher environment")
                key, value = entry.split("=", 1)
                if key in seen:
                    raise ValueError("duplicate launcher environment")
                seen.add(key)
                if key == "MALLOC_ARENA_MAX":
                    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 64:
                        raise ValueError("unreviewed allocator setting")
                elif key != "CA_CERTIFICATES" or value != "/system/vendor/quasar/ca-certificates.crt":
                    raise ValueError("unreviewed launcher environment")
        if names != set(TASKS):
            raise ValueError("incomplete launcher inventory")
        node["tasks"] = [task for task in tasks if task["name"] in {"mediad", "maind"}]
    except (KeyError, TypeError) as error:
        raise ValueError("unsupported stock launch configuration") from error
    return result
