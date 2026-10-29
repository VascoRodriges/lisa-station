"""Clock evidence requires an actual setter return, source and safe handoff."""

import os
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from controller.qualify_time import evaluate_events, trial_script
from controller.service_profiles import compile_profiles
from tests.test_bootstrap import events as policy_events


def events():
    base = policy_events()
    rows = []
    ops = [
        "start",
        "start-proof",
        "start-proof",
        "status",
        "start",
        "status",
        "status",
        "status",
        "start",
        "status",
        "stop",
    ]
    for i, op in enumerate(ops):
        row = deepcopy(base[15])
        row.update(
            operation="lab-time-" + op,
            time_operation_ok=i not in {0, 1, 8},
            result="denied" if i in {0, 1, 8} else "ok",
            requested_mode=(["paused"] * 6 + ["alice"] + ["lisa"] * 4)[i],
        )
        rows.append(row)
    return (
        base[:-1]
        + rows[:2]
        + [
            dict(
                event="profile-child",
                uid=65534,
                gid=65534,
                capabilities_zero=True,
                no_new_privs=True,
                clock_writes_denied=True,
            ),
            dict(event="time-preflight", clock_control=False, offset_within_limit=True),
        ]
        + rows[2:6]
        + [
            dict(event="clock-call", api="adjtimex", modes=2, result=0, errno=0),
            dict(event="time-source", selected_source_observed=True),
        ]
        + rows[6:]
        + [dict(event="time-restored", stock_clock_running=True, single_clock_controller=True), base[-1]]
    )


def test_full_clock_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (16, "result", "ok"),
        (17, "time_operation_ok", True),
        (18, "capabilities_zero", 1),
        (19, "offset_within_limit", False),
        (19, "clock_control", True),
        (20, "policy_ready", False),
        (20, "namespace_owned", False),
        (20, "time_operation_ok", 1),
        (20, "tagged_actors", 1),
        (20, "known_legacy_actors", 0),
        (20, "elapsed_ms", 8000),
        (20, "isolation_verified", True),
        (20, "vendor_started", True),
        (20, "stock_fallback", True),
        (24, "modes", 0),
        (24, "result", -1),
        (24, "result", 5),
        (24, "errno", 1),
        (24, "modes", True),
        (24, "api", "unknown"),
        (25, "selected_source_observed", False),
        (26, "requested_mode", "paused"),
        (28, "result", "ok"),
        (30, "result", "denied"),
        (31, "single_clock_controller", 1),
        (31, "stock_clock_running", False),
    ],
)
def test_missing_or_fabricated_clock_evidence_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_changed_fixture_requires_review(monkeypatch):
    monkeypatch.setattr("controller.qualify_time.POLICY_SCRIPT", "exit 0")
    with pytest.raises(RuntimeError):
        trial_script()


@pytest.fixture(scope="module")
def native_validator(tmp_path_factory):
    if sys.platform != "linux" or not shutil.which("cc"):
        pytest.skip("Linux compiler required")
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp("time-validator") / "validator"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-D_FORTIFY_SOURCE=3",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(root / "controller/time_guard_probe.c"),
            "-o",
            str(output),
        ],
        capture_output=True,
        check=True,
    )
    return output


def test_time_profile_agrees_with_device_validator(native_validator):
    value = compile_profiles(["203.0.113.1"], ["198.51.100.1", "2001:db8::1"]).time
    assert (
        subprocess.run([str(native_validator), "--validate-production"], input=value.encode()).returncode == 0
    )


@pytest.mark.parametrize(
    "before,after",
    [
        ("server 198.51.100.1 iburst", "pool time.example iburst"),
        ("198.51.100.1", "127.0.0.1"),
        ("198.51.100.1", "198.51.100.1 key 7"),
        ("port 0\n", "port 123\n"),
        ("cmdport 0", "cmdport 323"),
        ("bindcmdaddress /\n", "bindcmdaddress /tmp/commands.sock\n"),
        ("makestep 1.0 3", "makestep 0.0 -1"),
        ("rtcsync\n", "rtcsync\ninclude /etc/chrony.conf\n"),
    ],
)
def test_native_time_validator_rejects_other_behavior(native_validator, before, after):
    value = compile_profiles(["203.0.113.1"], ["198.51.100.1"]).time.replace(before, after)
    assert (
        subprocess.run([str(native_validator), "--validate-production"], input=value.encode()).returncode != 0
    )


def test_observer_preserves_results_and_errno_without_real_clock_changes(tmp_path):
    if sys.platform != "linux" or not shutil.which("cc"):
        pytest.skip("Linux dynamic-loader fixture required")
    root = Path(__file__).resolve().parents[1]
    observer = tmp_path / "observer.so"
    mock = tmp_path / "mock.so"
    subject = tmp_path / "subject"
    (tmp_path / "mock.c").write_text(
        "#include <sys/timex.h>\n#include <sys/time.h>\n#include <errno.h>\nint adjtimex(struct timex *p){(void)p;errno=EAGAIN;return 0;}\nint settimeofday(const struct timeval *p,const struct timezone *z){(void)p;(void)z;errno=EPERM;return -1;}\n"
    )
    (tmp_path / "subject.c").write_text(
        "#define _GNU_SOURCE\n#include <sys/timex.h>\n#include <sys/time.h>\n#include <sys/prctl.h>\n#include <linux/capability.h>\n#include <sys/syscall.h>\n#include <unistd.h>\n#include <errno.h>\nint main(void){struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct c[2]={{0},{0}};if(syscall(SYS_capset,&h,c)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 1;struct timex t={.modes=ADJ_FREQUENCY};if(adjtimex(&t)!=0||errno!=EAGAIN)return 2;struct timeval v={0};if(settimeofday(&v,0)!=-1||errno!=EPERM)return 3;return 0;}\n"
    )
    for args in [
        [
            "cc",
            "-shared",
            "-fPIC",
            "-O2",
            f'-DLISA_CLOCK_PROOF_DIRECTORY="{tmp_path}"',
            str(root / "controller/time_clock_proof.c"),
            "-ldl",
            "-o",
            str(observer),
        ],
        ["cc", "-shared", "-fPIC", str(tmp_path / "mock.c"), "-o", str(mock)],
        ["cc", str(tmp_path / "subject.c"), "-o", str(subject)],
    ]:
        subprocess.run(args, capture_output=True, check=True)
    env = os.environ | {"LD_PRELOAD": f"{observer}:{mock}"}
    subprocess.run([str(subject)], env=env, check=True)
    import json

    records = [json.loads(line) for line in (tmp_path / "clock-calls.jsonl").read_text().splitlines()]
    assert records == [
        dict(event="clock-call", api="adjtimex", modes=2, result=0, errno=0),
        dict(event="clock-call", api="settimeofday", modes=1, result=-1, errno=1),
    ]
    (tmp_path / "clock-calls.jsonl").unlink()
    target = tmp_path / "untouched"
    target.write_text("keep")
    (tmp_path / "clock-calls.jsonl").symlink_to(target)
    subprocess.run([str(subject)], env=env, check=True)
    assert target.read_text() == "keep"
