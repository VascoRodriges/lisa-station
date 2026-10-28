"""Bounded telemetry clone using the shared, independently recoverable trial."""

import argparse
from pathlib import Path

from controller.qualify_collector import SCRIPT, run_trial
from controller.qualify_collector import evaluate_events as evaluate_collector_events
from controller.telemetry_profile import prepare_telemetry_profile


def trial_script():
    for marker in ("--fluent-bitd", "/:E000$/", "for sample in 1 2 3; do sleep 2;"):
        if SCRIPT.count(marker) != 1:
            raise RuntimeError("collector trial template changed; review telemetry adaptation")
    script = (
        SCRIPT.replace("collector", "telemetry")
        .replace("--fluent-bitd", "--telemetry")
        .replace("57344", "57345")
        .replace("/:E000$/", "/:(E001|E002)$/")
        .replace("for sample in 1 2 3; do sleep 2;", "for sample in 1 2 3; do sleep 4;")
    )
    warmup = '"$tool" -A "$CHAIN" -m owner --gid-owner 57345 -j DROP'
    closing = 'printf \'%s\\n\' "$CHAIN" > "$STATE/run/policy.chain"'
    if script.count(warmup) != 1 or script.count(closing) != 1:
        raise RuntimeError("telemetry egress template changed; review before running")
    # Reject in warm-up to exercise offline persistence without a long TCP
    # timeout. The strict close verifier still requires DROP in both families.
    script = script.replace(warmup, warmup.replace("-j DROP", "-j REJECT"))
    script = script.replace(
        closing,
        "\n".join(
            [
                'PROBE --lab-observe-telemetry-close "$CANON" > "$STATE/observer.jsonl" &',
                "observer=$!",
                "tries=0",
                'while ! grep -q \'"event":"telemetry-observer-ready"\' "$STATE/observer.jsonl"; do',
                ' [ "$tries" -lt 40 ] || exit 8; sleep .05; tries=$((tries+1))',
                "done",
                'head -n 1 "$STATE/observer.jsonl"',
                'iptables -R "$CHAIN" 2 -m owner --gid-owner 57345 -j DROP',
                'ip6tables -R "$CHAIN" 2 -m owner --gid-owner 57345 -j DROP',
                closing,
            ]
        ),
    )
    marker = 'echo \'{"event":"telemetry-stopped","actors_absent":true}\''
    if script.count(marker) != 1:
        raise RuntimeError("telemetry stop template changed; review observer ordering")
    return script.replace(marker, marker + '\nwait "$observer"\ntail -n 1 "$STATE/observer.jsonl"')


def evaluate_boundary_events(events):
    converted = []
    samples = []
    ready = [r for r in events if r.get("event") == "telemetry-observer-ready"]
    closed = [r for r in events if r.get("event") == "telemetry-epoch-closed"]
    if len(events) != 16 or len(ready) != 1 or len(closed) != 1:
        return False
    for row in events:
        if row.get("event") in {"telemetry-observer-ready", "telemetry-epoch-closed"}:
            continue
        item = dict(row)
        if isinstance(item.get("event"), str):
            item["event"] = item["event"].replace("telemetry", "collector")
        if isinstance(item.get("operation"), str):
            item["operation"] = item["operation"].replace("telemetry", "collector")
        item["collector_jail_verified"] = item.get("telemetry_jail_verified", False)
        if row.get("operation") == "inspect-telemetry":
            paths = row.get("telemetry_batch_paths")
            if (
                type(row.get("telemetry_batch_materialized")) is not bool
                or type(paths) is not int
                or not 0 <= paths <= 7
                or row["telemetry_batch_materialized"] != bool(paths)
            ):
                return False
            samples.append(row["telemetry_batch_materialized"])
        converted.append(item)
    # Real batch materialization is a separate acceptance requirement, not
    # inferred from a configured path, a running process or an LMDB mapping.
    start = next(
        (r for r in events if r.get("operation") == "start-telemetry" and r.get("result") == "ok"), {}
    )
    observed = closed[0]
    return (
        evaluate_collector_events(converted)
        and len(samples) == 3
        and ready[0].get("child_pid") == observed.get("child_pid") == start.get("child_pid")
        and type(ready[0].get("start_ticks")) is int
        and ready[0]["start_ticks"] > 0
        and ready[0]["start_ticks"] == observed.get("start_ticks")
        and observed.get("actor_stopped") is True
        and observed.get("observer_fds_closed") is True
        and observed.get("payload_read") is False
        and type(observed.get("batch_materialized")) is bool
        and type(observed.get("batch_paths")) is int
        and 0 <= observed["batch_paths"] <= 7
        and observed["batch_materialized"] == bool(observed["batch_paths"])
    )


def evaluate_events(events):
    return evaluate_boundary_events(events) and any(
        row.get("telemetry_batch_materialized") is True
        or (row.get("event") == "telemetry-epoch-closed" and row.get("batch_materialized") is True)
        for row in events
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-telemetry-freeze", action="store_true", required=True)
    run_trial(
        parser.parse_args(),
        "telemetry",
        trial_script(),
        prepare_telemetry_profile,
        evaluate_events,
        evaluate_boundary_events,
    )


if __name__ == "__main__":
    main()
