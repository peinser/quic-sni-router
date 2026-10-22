"""Run with python3 tests/helm/publication.py (requires PyYAML)."""

from pathlib import Path

import yaml


workflows = Path(__file__).resolve().parents[2] / ".github/workflows"
# BaseLoader preserves GitHub's `on` key instead of YAML 1.1's boolean coercion.
ci, image, helm = [yaml.load((workflows / name).read_text(), Loader=yaml.BaseLoader)
                   for name in ("ci.yaml", "image.yaml", "helm.yaml")]
publish = ci["jobs"]["publish"]
assert set(publish["needs"]) == set(ci["jobs"]) - {"publish"}
assert "always()" not in publish["if"]
assert "github.event_name != 'pull_request'" in publish["if"]
assert "github.ref == 'refs/heads/main'" in publish["if"]
assert "github.ref == 'refs/heads/development'" in publish["if"]
assert publish["uses"] == "./.github/workflows/image.yaml"
assert set(image["on"]) == set(helm["on"]) == {"workflow_call"}
assert image["jobs"]["build"]["needs"] == "prepare"
assert set(image["jobs"]["merge"]["needs"]) == {"prepare", "build"}
chart = image["jobs"]["publish-chart"]
assert chart["needs"] == "merge"
assert chart["uses"] == "./.github/workflows/helm.yaml"
assert chart["if"] == "github.ref == 'refs/heads/main'"
for workflow in (ci, image, helm):
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/checkout@"):
                assert "ref" not in step.get("with", {}), "Checkout must use the validated event SHA"
print("Publication gating checks passed")
