"""Check staged and untracked publishable files, never the private workspace."""

import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
names = (
    subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)
    .decode()
    .split("\0")
)
for name in filter(None, names):
    path = root / name
    if path.suffix.lower() in {".wav", ".pcm", ".s16", ".pt", ".pth", ".onnx", ".pem", ".key", ".armhf"}:
        raise SystemExit(f"Non-source asset in public tree: {name}")
    if path.name in {"secrets.yaml", "authorized_keys", "known_hosts", ".env"}:
        raise SystemExit(f"Private configuration in public tree: {name}")
    text = path.read_text(encoding="utf-8")
    patterns = (
        r"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----",
        r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
        r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    )
    if any(re.search(pattern, text) for pattern in patterns):
        raise SystemExit(f"Credential or private-network marker in public tree: {name}")
print("Public source tree check passed")
