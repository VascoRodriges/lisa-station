"""OWN firmware-ALSA/plugin/actual Master GET lab; no SDK, setters or PCM."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.lab_artifact import canonical_lab_artifact
from controller.qualify_master_read import SCRIPT as BASE_SCRIPT
from controller.qualify_master_read import evaluate_events as evaluate_base
from controller.qualify_socket_close import rules_only

SCRIPT = BASE_SCRIPT.replace("/master-read.", "/master-plugin-read.").replace(
    'PROBE --run "$STATE"', 'PROBE --run "$STATE" PLUGIN')


def evaluate_events(events):
    if type(events) is not list or len(events) != 12 or type(events[8]) is not dict:
        return False
    expected = dict(event="master-plugin-read", clients=8, plugin_admission_controls=16, library_version="1.2.1.2",
                    configuration_loader=True, metadata_checked=True, backend_death_error=True, sdk_executed=False, audio_opened=False, ok=True)
    row = events[8]
    return (set(row) == set(expected) and all(type(row[k]) is type(v) and row[k] == v for k, v in expected.items())
            and evaluate_base(events[:8] + events[9:]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-read-only-plugin-lab", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=120, **kwargs)

    remote("test ! -e /data/opt/lisa-lab/trial.lock && test ! -e /bkupgrade/data/opt/lisa-station/state && test ! -e /run/lisa-station", check=True)
    paths, digests = {}, {}
    for name, suffix in [("master-plugin-read-probe", "armhf"), ("master-ctl-plugin", "so")]:
        data = (root / "build" / (name + "." + suffix)).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        alias = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote("umask 077; cat > " + alias + ".new && chmod 700 " + alias + ".new", input=data, check=True)
        if remote("sha256sum " + alias + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("artifact digest mismatch")
        remote("mv " + alias + ".new " + alias, check=True)
        paths[name] = canonical_lab_artifact(remote, alias)
        digests[name] = digest
    identity = "pidof dbus-daemon quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    script = SCRIPT.replace("PROBE", paths["master-plugin-read-probe"]).replace("MONITOR", paths["master-plugin-read-probe"]).replace("PLUGIN", paths["master-ctl-plugin"])
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/master-plugin-read.stdout.private.txt").write_bytes(result.stdout)
    (root / "build/master-plugin-read.stderr.private.txt").write_bytes(result.stderr)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(digests=digests, returncode=result.returncode, events=events,
                  qualified=result.returncode == 0 and evaluate_events(events), stock_identity_and_configs_preserved=before == after,
                  firewall_unchanged=rules_only(firewall) == rules_only(after_firewall), audio_captured=False,
                  sdk_executed=False, production_changed=False, isolation_verified=False)
    (root / "build/master-plugin-read-qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not all(report[k] for k in ["qualified", "stock_identity_and_configs_preserved", "firewall_unchanged"]):
        raise SystemExit("Master plugin lab incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
