"""Re-run the independent Semgrep check on both pinned production configurations."""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
case = json.loads((root / "public/verified-case.json").read_text())
output = root / "public/evidence"
output.mkdir(exist_ok=True)
version = subprocess.check_output(["semgrep", "--version", "--disable-version-check"], text=True).strip().splitlines()[-1]
for stage, expected in [("before", 1), ("after", 0)]:
    revision = case[stage]["sha"]
    source = subprocess.check_output(["git", "show", revision + ":vercel.json"], cwd=root)
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "vercel.json").write_bytes(source)
        shutil.copyfile(root / ".semgrep/sentinel.yml", work / "rules.yml")
        command = ["semgrep", "scan", "--config", "rules.yml", "--metrics", "off",
                   "--disable-version-check", "--no-git-ignore", "--jobs", "1", "--sarif",
                   "--output", "result.sarif", "vercel.json"]
        subprocess.run(command, check=True, cwd=work)
        data = json.loads((work / "result.sarif").read_text())
    run = data["runs"][0]
    ids = [item["ruleId"].split(".")[-1] for item in run["results"]]
    if ids != ["sentinel-form-destinations"] * expected:
        raise ValueError("Unexpected " + stage + " result: " + str(ids))
    if any(not i.get("executionSuccessful", True) for i in run.get("invocations", [])):
        raise ValueError("Semgrep reported an incomplete scan")
    run["versionControlProvenance"] = [{"repositoryUri": "https://github.com/" + case["repo"],
                                        "revisionId": revision}]
    (output / (stage + ".sarif")).write_text(json.dumps(data, indent=2) + "\n")
    print(stage, revision[:8], len(ids), "finding(s) · Semgrep", version)
