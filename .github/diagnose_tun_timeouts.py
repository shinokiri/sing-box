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
FIX = "f949e929e267c62844834e25c7626ef80d7e9c9d"
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


def compile_binary(name, variant, race=False):
    binary = TEMP / name
    args = ["go", "test", "-c", "-tags", "with_gvisor", "-o", str(binary)]
    if race:
        args += ["-race"]
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

# Validate the exact final function, with no diagnostic harness hooks.
subprocess.run(["git", "fetch", "--no-tags", "origin", FIX], check=True)
fixed_file = TEMP / SOURCE_TEST
fixed_file.write_text(output(["git", "show", f"{FIX}:third_party/sing-tun/{SOURCE_TEST}"]) + "\n")
format_check = subprocess.run(["gofmt", "-d", str(fixed_file)], text=True,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(RESULTS / "whole-file-gofmt.diff").write_text(format_check.stdout)
print(f"Whole-file gofmt status={format_check.returncode}; diff preserved", flush=True)
fixed_function = source_function(fixed_file)
# Check the changed function independently of pre-existing file formatting.
format_probe = "package tun\n\n" + fixed_function.decode().rstrip() + "\n"
formatted = subprocess.run(["gofmt"], input=format_probe, text=True,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
(RESULTS / "changed-function-gofmt.go").write_text(formatted.stdout)
assert formatted.stdout == format_probe, "The changed function needs gofmt"
summary["fix_commit"] = FIX
summary["fixed_sack_test_sha256"] = hashlib.sha256(fixed_function).hexdigest()
fixed_binaries = {}
for variant, directory in (("upstream", UPSTREAM), ("fork", FORK)):
    source = directory / SOURCE_TEST
    source.write_bytes(source.read_bytes().replace(source_function(source), fixed_function))
    fixed_binaries[variant] = compile_binary(f"{variant}-fixed.test", variant)
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
    run_case(fixed_binaries[variant], variant, "final-sack", "^TestGoKernelSACKReneging$", 100)
race_binary = compile_binary("fork-fixed-race.test", "fork", race=True)
run_case(race_binary, "fork", "final-sack-race", "^TestGoKernelSACKReneging$", 10)
expected_passes = list(summary["results"])

# Keep first-hole recovery working, but suppress retransmission of data beyond
# that hole. The fixture must reach reneging, then fail full-payload recovery.
retransmit = FORK / "stack_go_tcp_ack.go"
original_retransmit = retransmit.read_text()
signature = "func (e *goEngine) transmitRetransmit(conn *GoConn, offset uint64, length int, probe bool) int {\n"
assert original_retransmit.count(signature) == 1
try:
    retransmit.write_text(original_retransmit.replace(signature,
        signature + "\tif offset > 1 {\n\t\treturn 0\n\t}\n"))
    mutation_binary = compile_binary("fork-blocked-retransmission.test", "fork")
finally:
    retransmit.write_text(original_retransmit)
run_case(mutation_binary, "fork", "blocked-retransmission", "^TestGoKernelSACKReneging$", 2)

mutation = summary["results"][-1]
summary["final_patch_validated"] = all(r["exit_code"] == 0 for r in expected_passes)
mutation_log = (RESULTS / mutation["log"]).read_text()
summary["mutation_detected"] = (mutation["exit_code"] != 0
    and sum("/ipv6=" in line for line in mutation["failure_lines"]) == 8
    and mutation_log.count("SACK reneging: received=") == 8)

# Restore only the old complete-initial-burst assumption. The final controlled
# regression must still reproduce the original setup timeout with this change.
test_source = FORK / SOURCE_TEST
fixed_source = test_source.read_text()
start = fixed_source.index("\t\t\t\tretained := goSackBlock{start:")
end = fixed_source.index("\n\t\t\t\terr := client.SetReadBuffer(512)", start)
old_setup = '''\t\t\t\tretained := goSackBlock{start: uint64(mss + 1), end: uint64(len(payload) + 1)}
\t\t\t\ttraffic.await(test, server, "kernel SACK of queued out-of-order data", func(flow kernelTCPFlow) bool {
\t\t\t\t\treturn slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool {
\t\t\t\t\t\treturn !event.outgoing && slices.Contains(event.sacks, retained)
\t\t\t\t\t})
\t\t\t\t})'''
try:
    test_source.write_text(fixed_source[:start] + old_setup + fixed_source[end:])
    before_binary = compile_binary("fork-original-setup.test", "fork")
finally:
    test_source.write_text(fixed_source)
run_case(before_binary, "fork", "original-setup", "^TestGoKernelSACKReneging$/^early_recovery=true$", 5)
before = summary["results"][-1]
before_log = (RESULTS / before["log"]).read_text()
summary["original_setup_reproduced"] = (before["exit_code"] != 0
    and sum("/ipv6=" in line for line in before["failure_lines"]) == 10
    and before_log.count("kernel SACK of queued out-of-order data timed out") == 10)

summary["completed"] = True
summary["note"] = "Test exit codes are evidence, not suppressed release gates. This diagnostic workflow does not build or publish an APK."
save_summary()
with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as report:
    report.write("| Source | Case | Repetitions | Exit | Seconds |\n|---|---|---:|---:|---:|\n")
    for result in summary["results"]:
        report.write(f"| {result['variant']} | {result['case']} | {result['count']} | {result['exit_code']} | {result['elapsed_seconds']:.1f} |\n")
assert summary["final_patch_validated"], "The exact final patch failed a positive test"
assert summary["mutation_detected"], "The fixture did not detect blocked retransmission of reneged data"
assert summary["original_setup_reproduced"], "The final controlled regression did not reproduce the original setup timeout"
