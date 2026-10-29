"""Only synthetic task definitions; no copied firmware configuration."""

from copy import deepcopy

import pytest

from controller.launch_profile import TASKS, prepare_platform_launch


def stock():
    tasks = []
    for name in ("mediad", "telemetry", "maind", "fluent-bitd"):
        flag, order, restart = TASKS[name]
        task = dict(
            name=name,
            root=".",
            path="/system/vendor/quasar/maind",
            arg=[flag],
            delay=5,
            order=order,
            allowedRestartIntervalSeconds=restart,
            log=False,
        )
        if name in {"mediad", "maind"}:
            task["envs"] = ["MALLOC_ARENA_MAX=2", "CA_CERTIFICATES=/system/vendor/quasar/ca-certificates.crt"]
        tasks.append(task)
    return {"nodes": [{"name": "main", "root": ".", "tasks": tasks}]}


def test_only_platform_and_media_remain_without_mutating_source():
    source = stock()
    before = deepcopy(source)
    result = prepare_platform_launch(source)
    assert source == before
    assert [task["name"] for task in result["nodes"][0]["tasks"]] == ["mediad", "maind"]
    assert result["nodes"][0]["tasks"] == [before["nodes"][0]["tasks"][i] for i in (0, 2)]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("name", "unknown"),
        ("path", "/bin/sh"),
        ("root", "/tmp"),
        ("arg", ["--mediad", "--extra"]),
        ("arg", "--mediad"),
        ("delay", True),
        ("delay", 6),
        ("order", 0),
        ("allowedRestartIntervalSeconds", 600),
        ("log", 0),
        ("log", True),
        ("envs", "not-a-list"),
        ("envs", [False]),
        ("envs", ["MALLOC_ARENA_MAX"]),
        ("envs", ["LD_PRELOAD=/unreviewed/library.so"]),
        ("envs", ["MALLOC_ARENA_MAX=0"]),
        ("envs", ["MALLOC_ARENA_MAX=65"]),
        ("envs", ["MALLOC_ARENA_MAX=1;anything"]),
        ("envs", ["MALLOC_ARENA_MAX=２"]),
        ("envs", ["CA_CERTIFICATES=/unreviewed.pem"]),
        ("envs", ["MALLOC_ARENA_MAX=2", "MALLOC_ARENA_MAX=3"]),
    ],
)
def test_unreviewed_command_environment_or_timing_refused(key, value):
    source = stock()
    source["nodes"][0]["tasks"][0][key] = value
    with pytest.raises(ValueError):
        prepare_platform_launch(source)


@pytest.mark.parametrize(
    "fault",
    (
        "root",
        "nodes",
        "multiple",
        "node",
        "node_root",
        "node_name",
        "tasks",
        "missing",
        "duplicate",
        "extra",
        "task_schema",
        "missing_key",
    ),
)
def test_incomplete_or_expanded_task_scope_refused(fault):
    source = stock()
    node = source["nodes"][0]
    if fault == "root":
        source["unreviewed"] = True
    elif fault == "nodes":
        source["nodes"] = {}
    elif fault == "multiple":
        source["nodes"].append(deepcopy(node))
    elif fault == "node":
        source["nodes"][0] = "unknown"
    elif fault == "node_root":
        node["root"] = "/tmp"
    elif fault == "node_name":
        node["name"] = "other"
    elif fault == "tasks":
        node["tasks"] = {}
    elif fault == "missing":
        node["tasks"].pop()
    elif fault == "duplicate":
        node["tasks"][1] = deepcopy(node["tasks"][0])
    elif fault == "extra":
        node["tasks"].append(deepcopy(node["tasks"][0]))
    elif fault == "task_schema":
        node["tasks"][0]["shell"] = "unreviewed"
    elif fault == "missing_key":
        del node["tasks"][0]["path"]
    with pytest.raises(ValueError):
        prepare_platform_launch(source)
