"""Run with python3 tests/helm/render.py (requires Helm 3 and PyYAML)."""

import json
from pathlib import Path
import subprocess

import yaml


CHART = Path(__file__).resolve().parents[2] / "charts/quic-sni-router"


def render(config):
    return subprocess.run(
        ["helm", "template", "test", str(CHART), "--show-only",
         "templates/configmap.yaml", "--values", "-"],
        input=json.dumps({"config": config}), text=True, capture_output=True,
    )


route = {"host": "127.0.0.1", "port": 8443}
key = "00000000000000000000000000000012"
cases = [
    {"routes": {"example.test": route}},
    {"cidEncoding": {"key": key},
     "routes": {"example.test": {**route, "serverId": 255}}},
    {"quicLb": {"configurations": [
        {"id": 0, "serverIdLength": 3, "nonceLength": 4},
        {"id": 6, "serverIdLength": 3, "nonceLength": 4, "key": key},
    ]}, "routes": {"example.test": {
        **route, "quicLbServerIds": {"0": "000012", "6": "abcdef"},
    }}},
]
for config in cases:
    result = render(config)
    assert result.returncode == 0, result.stderr
    manifest = yaml.safe_load(result.stdout)
    router = yaml.safe_load(manifest["data"]["router.yaml"])
    for field in ("routes", "cidEncoding", "quicLb"):
        assert router.get(field) == config.get(field), (field, router, config)
    assert router["listen"]["udp"] and router["sessions"]["maxSessions"] > 0

result = render({**cases[1], "quicLb": cases[2]["quicLb"]})
assert result.returncode != 0 and "schema" in result.stderr, result.stderr
print("Helm CID rendering checks passed")
