"""Run with python3 tests/helm/render.py (requires Helm 3 and PyYAML)."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import yaml


CHART = Path(__file__).resolve().parents[2] / "charts/quic-sni-router"


def render(config, **values):
    return subprocess.run(
        ["helm", "template", "test", str(CHART), "--values", "-"],
        input=json.dumps({"config": config, **values}), text=True, capture_output=True,
    )


route = {"host": "127.0.0.1", "port": 8443}
key = "00000000000000000000000000000012"
cases = [
    {"routes": {"example.test": route}},
    {"quicLb": {"configurations": [
        {"id": 0, "serverIdLength": 3, "nonceLength": 4},
        {"id": 6, "serverIdLength": 3, "nonceLength": 4},
    ]}, "routes": {"example.test": {
        **route, "quicLbServerIds": {"0": "000012", "6": "abcdef"},
    }}},
]
for config in cases:
    result = render(config)
    assert result.returncode == 0, result.stderr
    manifest = next(doc for doc in yaml.safe_load_all(result.stdout)
                    if doc["kind"] == "ConfigMap")
    router = yaml.safe_load(manifest["data"]["router.yaml"])
    for field in ("routes", "cidEncoding", "quicLb"):
        assert router.get(field) == config.get(field), (field, router, config)
    assert router["listen"]["udp"] and router["sessions"]["maxSessions"] > 0

for listen, expected in ((None, False), ({"transparent": True}, True), ({"transparent": False}, False)):
    config = {"routes": {"example.test": route}}
    if listen is not None:
        config["listen"] = {"udp": ":8443", **listen}
    result = render(config)
    assert result.returncode == 0, result.stderr
    manifest = next(doc for doc in yaml.safe_load_all(result.stdout) if doc["kind"] == "ConfigMap")
    router = yaml.safe_load(manifest["data"]["router.yaml"])
    assert router["listen"]["transparent"] is expected, (listen, router)
    assert router["listen"]["fwmark"] == 0, router

result = render({"listen": {"udp": ":8443", "transparent": "yes"}, "routes": {"example.test": route}})
assert result.returncode != 0 and "schema" in result.stderr, result.stderr


def service_spec(config, **values):
    result = render(config, **values)
    assert result.returncode == 0, result.stderr
    return next(doc for doc in yaml.safe_load_all(result.stdout) if doc["kind"] == "Service")["spec"]


def notes(config, **values):
    """helm template skips NOTES.txt and install --dry-run needs a cluster, so render it through tpl in a copy."""
    with tempfile.TemporaryDirectory() as directory:
        chart = Path(directory) / "chart"
        shutil.copytree(CHART, chart)
        (chart / "templates/NOTES.txt").rename(chart / "notes.txt")
        (chart / "templates/notes.yaml").write_text('notes: {{ tpl (.Files.Get "notes.txt") . | toJson }}\n')
        result = subprocess.run(
            ["helm", "template", "test", str(chart), "--show-only", "templates/notes.yaml", "--values", "-"],
            input=json.dumps({"config": config, **values}), text=True, capture_output=True,
        )
    assert result.returncode == 0, result.stderr
    return yaml.safe_load(result.stdout)["notes"]


transparent = {"listen": {"udp": ":8443", "transparent": True}, "routes": {"example.test": route}}
plain = {"routes": {"example.test": route}}
# Transparent mode needs real client addresses, so it overrides the Cluster default.
assert service_spec(transparent)["externalTrafficPolicy"] == "Local"
assert service_spec(transparent, service={"type": "NodePort"})["externalTrafficPolicy"] == "Local"
assert service_spec(transparent, existingSecret="router-secret")["externalTrafficPolicy"] == "Local"
assert "externalTrafficPolicy" not in service_spec(transparent, service={"type": "ClusterIP"})
assert service_spec(plain)["externalTrafficPolicy"] == "Cluster"
text = notes(transparent)
assert "WARNING: config.listen.transparent=true." in text, text
assert "externalTrafficPolicy to Local, overriding\nservice.externalTrafficPolicy=Cluster." in text, text
text = notes(transparent, service={"externalTrafficPolicy": "Local"})
assert "externalTrafficPolicy to Local." in text and "overriding" not in text, text
text = notes(transparent, service={"type": "ClusterIP"})
assert "WARNING: config.listen.transparent=true." in text and "externalTrafficPolicy to Local" not in text, text
assert "WARNING: config.listen.transparent" not in notes(plain)

result = render({**cases[1], "cidEncoding": {"key": key}})
assert result.returncode != 0 and "schema" in result.stderr, result.stderr

for config in (
    {"cidEncoding": {"key": key}},
    {"quicLb": {"configurations": [
        {"id": 0, "serverIdLength": 3, "nonceLength": 4, "key": key},
    ]}},
):
    for values in ({}, {"existingSecret": "router-secret"},
                   {"configMap": {"create": False, "name": "external"}}):
        result = render(config, **values)
        assert result.returncode != 0 and "must not be supplied" in result.stderr, result.stderr
        assert key not in result.stdout + result.stderr

for create in (True, False):
    result = render({}, existingSecret="router-secret",
                    configMap={"create": create, "checksumAnnotation": True})
    assert result.returncode == 0, result.stderr
    documents = list(yaml.safe_load_all(result.stdout))
    assert not any(doc["kind"] in ("ConfigMap", "Secret") for doc in documents)
    deployment = next(doc for doc in documents if doc["kind"] == "Deployment")
    template = deployment["spec"]["template"]
    assert "checksum/config" not in (template["metadata"].get("annotations") or {})
    pod = template["spec"]
    volume = next(v for v in pod["volumes"] if v["name"] == "config")
    assert volume == {"name": "config", "secret": {
        "secretName": "router-secret", "defaultMode": 0o440,
        "items": [{"key": "router.yaml", "path": "router.yaml"}],
    }}
    container = pod["containers"][0]
    assert container["args"] == ["/config/router.yaml"]
    assert {"name": "config", "mountPath": "/config", "readOnly": True} in container["volumeMounts"]

result = render({}, configMap={"create": False, "name": "external"})
assert result.returncode == 0, result.stderr
documents = list(yaml.safe_load_all(result.stdout))
assert not any(doc["kind"] == "ConfigMap" for doc in documents)
deployment = next(doc for doc in documents if doc["kind"] == "Deployment")
assert deployment["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"] == "external"
print("Helm CID rendering checks passed")
