"""Bounded port-53 resolver handoff, without changing Alice or system profiles."""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_bootstrap import SCRIPT as POLICY_SCRIPT
from controller.qualify_bootstrap import evaluate_events as evaluate_policy
from controller.qualify_socket_close import rules_only
from controller.service_profiles import compile_profiles


def trial_script(encoded_profile):
    anchors = (
        "for tool in iptables ip6tables; do\n    for rule",
        'cleanup\necho \'{"event":"boot-policy-cleanup"',
    )
    if any(POLICY_SCRIPT.count(marker) != 1 for marker in anchors):
        raise RuntimeError("bootstrap fixture changed; review resolver handoff")
    script = POLICY_SCRIPT.replace(
        anchors[0],
        r"""if [ -f "$STATE/dns-restore" ] && [ ! -f "$STATE/dns-restored" ]; then
    canon=$(readlink -f "$STATE")
    PROBE --lab-dns-stop "$canon" > "$STATE/dns-stop-cleanup.json" || exit 9
    /etc/init.d/S70unbound start </dev/null > "$STATE/dns-restore.log" 2>&1 9>&- || :
    tries=0
    while :; do
        set -- $(pidof unbound)
        if [ "$#" = 1 ] && grep -q '^Seccomp:[[:space:]]*0$' "/proc/$1/status" &&
            grep -q '^CapEff:[[:space:]]*0000000000000000$' "/proc/$1/status" &&
            LOCAL_QUERY --query-local 53 >/dev/null 2>&1; then break; fi
        [ "$tries" -lt 30 ] || exit 9
        sleep .1; tries=$((tries+1))
    done
    touch "$STATE/dns-restored"
fi
for tool in iptables ip6tables; do
    for rule""",
    )
    return script.replace(
        anchors[1],
        r'''expect lab-dns-start denied
printf '%s' PROFILE_BASE64 | base64 -d | sed "s|/bkupgrade/data/opt/lisa-controller-lab/boot-policy.TEMPLATE/network|$CANON/network|g" > "$STATE/dns.profile"
expect lab-dns-start denied
set -- $(pidof unbound)
[ "$#" = 1 ] && grep -q '^Seccomp:[[:space:]]*0$' "/proc/$1/status"
touch "$STATE/dns-restore"
/etc/init.d/S70unbound stop > "$STATE/dns-stop-stock.log" 2>&1
tries=0
while pidof unbound >/dev/null; do
    [ "$tries" -lt 30 ] || exit 7
    sleep .1; tries=$((tries+1))
done
expect lab-dns-start ok
cp "$STATE/run/dns.child" "$STATE/dns-first.child"
expect lab-dns-status ok
expect lab-dns-start ok
cmp "$STATE/run/dns.child" "$STATE/dns-first.child"
QUERY --dns-query 53
printf 'LISA_MODE_V1 4 alice\n' > "$STATE/state/mode.state"
expect lab-dns-status ok
printf 'LISA_MODE_V1 5 lisa\n' > "$STATE/state/mode.state"
expect lab-dns-status ok
cp "$STATE/dns.profile" "$STATE/dns.saved"
printf '\ninclude: /etc/unbound/unbound.conf\n' >> "$STATE/dns.profile"
expect lab-dns-start denied
LOCAL_QUERY --query-local 53
mv "$STATE/dns.saved" "$STATE/dns.profile"
expect lab-dns-status ok
[ ! -e "$STATE/run/vendor.permit" ]
expect lab-dns-stop ok
cleanup
[ -f "$STATE/dns-restored" ]
echo '{"event":"dns-restored","stock_resolver_running":true,"local_queries_work":true}'
echo '{"event":"boot-policy-cleanup"''',
    ).replace("PROFILE_BASE64", encoded_profile)


def evaluate_events(events):
    if not isinstance(events, list) or any(not isinstance(row, dict) for row in events):
        return False
    dns = [row for row in events if str(row.get("operation", "")).startswith("lab-dns-")]
    other = [
        row
        for row in events
        if row not in dns and row.get("event") not in {"dns-restored", "profile-child", "dns-query"}
    ]
    if len(events) != 33 or len(dns) != 10 or not evaluate_policy(other):
        return False
    operations = ["start", "start", "start", "status", "start", "status", "status", "start", "status", "stop"]
    modes = ["paused"] * 5 + ["alice"] + ["lisa"] * 4
    for i, row in enumerate(dns):
        ok = i not in {0, 1, 7}
        if (
            row.get("event") != "station-boot"
            or row.get("operation") != "lab-dns-" + operations[i]
            or row.get("requested_mode") != modes[i]
            or row.get("result") != ("ok" if ok else "denied")
            or row.get("dns_operation_ok") is not ok
            or row.get("lab_policy_only") is not True
            or row.get("namespace_owned") is not True
            or row.get("policy_ready") is not True
            or any(
                row.get(key) is not False
                for key in ("vendor_started", "stock_fallback", "isolation_verified")
            )
            or type(row.get("known_legacy_actors")) is not int
            or row["known_legacy_actors"] != other[15]["known_legacy_actors"]
            or type(row.get("tagged_actors")) is not int
            or row["tagged_actors"] != 0
            or type(row.get("elapsed_ms")) is not int
            or not 0 <= row["elapsed_ms"] < 7000
        ):
            return False
    expected = (
        ["station-boot"] * 21
        + ["profile-child"]
        + ["dns-query"] * 4
        + ["station-boot"] * 5
        + ["dns-restored", "boot-policy-cleanup"]
    )
    if [row.get("event") for row in events] != expected:
        return False
    child = events[21]
    if child != dict(
        event="profile-child",
        uid=65534,
        gid=65534,
        capabilities_zero=True,
        no_new_privs=True,
        clock_writes_denied=True,
    ) or any(
        child.get(key) is not True for key in ("capabilities_zero", "no_new_privs", "clock_writes_denied")
    ):
        return False
    queries = events[22:26]
    if {(row.get("family"), row.get("transport")) for row in queries} != {
        (4, "udp"),
        (4, "tcp"),
        (6, "udp"),
        (6, "tcp"),
    }:
        return False
    if any(row.get("ok") is not True for row in queries):
        return False
    return events[-2] == dict(
        event="dns-restored", stock_resolver_running=True, local_queries_work=True
    ) and all(events[-2].get(key) is True for key in ("stock_resolver_running", "local_queries_work"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--dns-server", action="append", required=True)
    parser.add_argument("--temporary-dns-handoff", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    profile = compile_profiles(
        args.dns_server,
        ["198.51.100.1"],
        network_directory="/bkupgrade/data/opt/lisa-controller-lab/boot-policy.TEMPLATE/network",
    ).dns
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=110, **kwargs)

    targets = {}
    digests = {}
    for key, name in [
        ("PROBE", "station-boot"),
        ("QUERY", "service-profile-probe"),
        ("LOCAL_QUERY", "dns-profile-probe"),
    ]:
        binary = (root / f"build/{name}.armhf").read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote(
            "umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True
        )
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("resolver helper digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        targets[key] = target
        digests[name] = digest
    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/unbound/unbound.conf /etc/resolv.conf /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    script = trial_script("ENCODED_PROFILE_TOKEN")
    for key in ("LOCAL_QUERY", "PROBE", "QUERY"):
        script = script.replace(key, targets[key])
    script = script.replace("ENCODED_PROFILE_TOKEN", base64.b64encode(profile.encode()).decode())
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digests,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-2000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        other_identity_and_configs_preserved=before == after,
        firewall_rules_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/dns-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "other_identity_and_configs_preserved", "firewall_rules_restored")
    ):
        raise SystemExit("resolver handoff incomplete; inspect private report")


if __name__ == "__main__":
    main()
