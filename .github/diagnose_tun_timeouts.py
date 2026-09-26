"""Run bounded kernel comparisons without changing production code or publishing."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path.cwd()
RESULTS = ROOT / "diagnostic-results"
RESULTS.mkdir(exist_ok=True)
TEMP = Path(os.environ["RUNNER_TEMP"]) / "tun-timeout-diagnosis"
TEMP.mkdir(exist_ok=True)
UPSTREAM = TEMP / "upstream"
PIN = "97d11460f2ea140441219f3055e3ff00a03282ff"
FORK = ROOT / "third_party/sing-tun"
SOURCE_TEST = "stack_go_integration_flow_linux_test.go"
MODFILE = ROOT / "diagnostic-upstream.mod"
summary = {"upstream_commit": PIN, "results": []}


def output(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def save_summary():
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


def source_function(path):
    data = path.read_bytes()
    start = data.index(b"func TestGoKernelSACKReneging(")
    end = data.index(b"\nfunc ", start + 1)
    return data[start:end]


def compile_binary(name, variant):
    binary = TEMP / name
    args = ["go", "test", "-c", "-tags", "with_gvisor", "-o", str(binary)]
    if variant == "upstream":
        args += ["-modfile", str(MODFILE)]
    args += ["github.com/sagernet/sing-tun"]
    with (RESULTS / f"{name}-compile.log").open("w") as log:
        subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, check=True)
    return binary


def run_case(binary, variant, case, pattern, count, timeout="8m"):
    name = f"{variant}-{case}"
    args = ["sudo", str(binary), "-test.v", "-test.run", pattern,
            "-test.count", str(count), "-test.timeout", timeout]
    start = datetime.now(timezone.utc)
    print(f"START {name} count={count}", flush=True)
    with (RESULTS / f"{name}.log").open("w") as log:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=540)
    data = (RESULTS / f"{name}.log").read_text()
    failures = re.findall(r"(?m)^\s*--- FAIL: (.+)$", data)
    record = {"variant": variant, "case": case, "count": count,
              "started_at": start.isoformat(), "exit_code": result.returncode,
              "elapsed_seconds": (datetime.now(timezone.utc) - start).total_seconds(),
              "failure_lines": failures, "log": f"{name}.log"}
    summary["results"].append(record)
    save_summary()
    print(json.dumps(record), flush=True)


summary["fork_commit"] = output(["git", "rev-parse", "HEAD"])
summary["go_version"] = output(["go", "version"])
summary["kernel"] = output(["uname", "-a"])
summary["cpu"] = output(["lscpu"])
summary["kernel_settings"] = output(["sysctl", "net.ipv4.tcp_congestion_control",
    "net.ipv4.tcp_invalid_ratelimit", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"])
subprocess.run(["git", "init", str(UPSTREAM)], check=True)
subprocess.run(["git", "-C", str(UPSTREAM), "fetch", "--depth=1",
                "https://github.com/SagerNet/sing-tun.git", PIN], check=True)
subprocess.run(["git", "-C", str(UPSTREAM), "checkout", "--detach", "FETCH_HEAD"], check=True)
assert output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"]) == PIN
assert source_function(FORK / SOURCE_TEST) == source_function(UPSTREAM / SOURCE_TEST)
summary["original_sack_test_sha256"] = hashlib.sha256(source_function(FORK / SOURCE_TEST)).hexdigest()
shutil.copyfile(ROOT / "go.mod", MODFILE)
shutil.copyfile(ROOT / "go.sum", MODFILE.with_suffix(".sum"))
subprocess.run(["go", "mod", "edit", "-modfile", str(MODFILE),
                f"-replace=github.com/sagernet/sing-tun={UPSTREAM}"], check=True)
save_summary()

# Compile both original suites before adding any instrumentation.
binaries = {variant: compile_binary(f"{variant}-original.test", variant)
            for variant in ("upstream", "fork")}
# Only a new test file is added; original production and test files stay intact.
diagnostic_binaries = {}
for variant, directory in (("upstream", UPSTREAM), ("fork", FORK)):
    shutil.copyfile(ROOT / ".github/tun-timeout-diagnostic_test.go",
                    directory / "timeout_diagnostic_linux_test.go")
    subprocess.run(["gofmt", "-w", str(directory / "timeout_diagnostic_linux_test.go")], check=True)
    diagnostic_binaries[variant] = compile_binary(f"{variant}-diagnostic.test", variant)
    args = ["go", "list", "-m", "-f", "{{.Path}} {{.Version}} {{with .Replace}}{{.Path}} {{.Version}}{{end}}"]
    if variant == "upstream":
        args += ["-modfile", str(MODFILE)]
    (RESULTS / f"{variant}-modules.txt").write_text(output(args + ["all"]) + "\n")

graphs = [(RESULTS / f"{variant}-modules.txt").read_text().splitlines()
          for variant in ("upstream", "fork")]
assert [line for line in graphs[0] if not line.startswith("github.com/sagernet/sing-tun ")] == [
    line for line in graphs[1] if not line.startswith("github.com/sagernet/sing-tun ")]
summary["other_module_versions_identical"] = True
save_summary()
for variant in ("upstream", "fork"):
    run_case(binaries[variant], variant, "original-sack", "^TestGoKernelSACKReneging$", 100)
for variant in ("upstream", "fork"):
    run_case(binaries[variant], variant, "original-flowcontrol",
             "^TestGoKernelFlowControl$/^mtu=65535$/^gso=false$/^mq=false$", 25)
for variant in ("upstream", "fork"):
    for case, count in (("natural", 30), ("early-recovery", 10), ("gate-sacks", 30)):
        run_case(diagnostic_binaries[variant], variant, case, f"^TestDiagnosticSACKReneging$/^{case}$", count)

summary["completed"] = True
summary["note"] = "Test exit codes are evidence, not suppressed release gates. This diagnostic workflow does not build or publish an APK."
save_summary()
with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as report:
    report.write("| Source | Case | Repetitions | Exit | Seconds |\n|---|---|---:|---:|---:|\n")
    for result in summary["results"]:
        report.write(f"| {result['variant']} | {result['case']} | {result['count']} | {result['exit_code']} | {result['elapsed_seconds']:.1f} |\n")
