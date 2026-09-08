"""Follow upstream stable releases and publish the tested Android build."""

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

UPSTREAM = "SagerNet/sing-box"
MANIFEST = Path("release/udpflow.json")
CLIENT = Path("clients/android")


def git(*args, cwd=None, env=None):
    return subprocess.check_output(["git", *args], cwd=cwd, env=env, text=True).strip()


def api(path, missing_ok=False):
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + os.environ["GH_TOKEN"]},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise


def stable_version(tag):
    if not re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag):
        raise ValueError(f"Not an upstream stable tag: {tag!r}")
    return tuple(map(int, tag[1:].split(".")))


def fork_version(tag, revision=0):
    stable_version(tag)
    if type(revision) is not int or revision < 0:
        raise ValueError("fork_revision must be a non-negative integer")
    return tag[1:] + "-udpflow" + (f".{revision}" if revision else "")


def properties(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def output(**values):
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        for key, value in values.items():
            print(f"{key}={str(value).lower() if isinstance(value, bool) else value}", file=stream)


def plan():
    current = json.loads(MANIFEST.read_text())
    fork_version(current["upstream_tag"], current.get("fork_revision", 0))
    if os.environ["GITHUB_EVENT_NAME"] == "pull_request":
        output(build=True, publish=False, **current)
        return

    sync = os.environ.get("SYNC_UPSTREAM") == "true"
    release_path = "latest" if sync else "tags/" + current["upstream_tag"]
    upstream = api(f"repos/{UPSTREAM}/releases/{release_path}")
    tag = upstream["tag_name"]
    if upstream["draft"] or upstream["prerelease"]:
        raise ValueError("Upstream release is not published and stable")
    if stable_version(tag) < stable_version(current["upstream_tag"]):
        raise ValueError("Refusing to move the upstream base backwards")
    ref = api(f"repos/{UPSTREAM}/git/ref/tags/{tag}")["object"]
    while ref["type"] == "tag":
        ref = api(f"repos/{UPSTREAM}/git/tags/{ref['sha']}")["object"]
    if ref["type"] != "commit":
        raise ValueError("Upstream tag does not point to a commit")
    if tag == current["upstream_tag"] and ref["sha"] != current["upstream_commit"]:
        raise ValueError("Recorded upstream tag was moved; review the new commit before publishing")

    repository = os.environ["GITHUB_REPOSITORY"]
    revision = current.get("fork_revision", 0) if tag == current["upstream_tag"] else 0
    version = fork_version(tag, revision)
    release = api(f"repos/{repository}/releases/tags/v{version}", missing_ok=True)
    published = release is not None and not release["draft"]
    if published and release["prerelease"]:
        raise ValueError("The udpflow release is incorrectly marked as a prerelease")
    build = os.environ["GITHUB_EVENT_NAME"] != "schedule" or not published or tag != current["upstream_tag"]
    output(build=build, publish=not published, upstream_tag=tag, upstream_commit=ref["sha"])


def merge_upstream_tree(upstream_base, ours, upstream):
    # Compare release snapshots explicitly: upstream development history may
    # have been reset/rebased since the last stable release.
    with tempfile.TemporaryDirectory() as directory:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(directory).resolve() / "index")}
        git("read-tree", upstream, env=env)
        # Neutralize upstream changes to paths owned by this fork. Android is
        # pinned separately after its VERSION_NAME matches the stable core.
        git("restore", f"--source={upstream_base}", "--staged", "--", ".github/workflows", str(CLIENT), env=env)
        incoming = git("write-tree", env=env)
    result = subprocess.run(
        ["git", "merge-tree", "--write-tree", f"--merge-base={upstream_base}", ours, incoming],
        capture_output=True, text=True,
    )
    if result.returncode == 1:
        raise ValueError("Upstream merge needs review:\n" + result.stdout)
    result.check_returncode()
    return result.stdout.strip()


def prepare():
    tag = os.environ["UPSTREAM_TAG"]
    stable_version(tag)
    expected_commit = os.environ["UPSTREAM_COMMIT"]
    current = json.loads(MANIFEST.read_text())
    revision = current.get("fork_revision", 0) if tag == current["upstream_tag"] else 0
    version = fork_version(tag, revision)
    base = git("rev-parse", "HEAD")
    git("fetch", "--no-tags", f"https://github.com/{UPSTREAM}.git", f"refs/tags/{tag}")
    commit = git("rev-parse", "FETCH_HEAD^{commit}")
    if commit != expected_commit:
        raise ValueError("Upstream tag changed since planning")
    git("submodule", "update", "--init", "--recursive", str(CLIENT))

    if tag != current["upstream_tag"]:
        if stable_version(tag) <= stable_version(current["upstream_tag"]):
            raise ValueError("Refusing to downgrade the upstream base")
        git("diff", "--quiet")
        git("diff", "--cached", "--quiet")
        git("merge-base", "--is-ancestor", current["upstream_commit"], base)
        merged_tree = merge_upstream_tree(current["upstream_commit"], base, commit)
        git("fetch", "origin", "main", cwd=CLIENT)
        client_commit = git("rev-parse", "FETCH_HEAD", cwd=CLIENT)
        client_props = dict(line.split("=", 1) for line in git("show", f"{client_commit}:version.properties", cwd=CLIENT).splitlines() if "=" in line)
        if client_props["VERSION_NAME"] != tag[1:]:
            raise ValueError("Upstream Android main has not reached this stable version")
        git("read-tree", "-m", "-u", base, merged_tree)
        git("checkout", "--detach", client_commit, cwd=CLIENT)
        git("submodule", "update", "--init", "--recursive", cwd=CLIENT)
        MANIFEST.write_text(json.dumps({"upstream_tag": tag, "upstream_commit": commit, "fork_revision": 0}, indent=2) + "\n")
        git("add", str(CLIENT), str(MANIFEST))
        merged_commit = git(
            "-c", "user.name=github-actions[bot]", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit-tree", git("write-tree"), "-p", base, "-p", commit, "-m", f"release: follow upstream {tag}",
        )
        git("update-ref", "HEAD", merged_commit, base)
    elif commit != current["upstream_commit"]:
        raise ValueError("Recorded upstream commit does not match the stable tag")
    git("merge-base", "--is-ancestor", commit, "HEAD")

    props = properties(CLIENT / "version.properties")
    if props["VERSION_NAME"] != tag[1:]:
        raise ValueError("Pinned Android client does not match the stable core")
    # Keep the upstream gitlink intact; this small, reviewed patch belongs to
    # this repository and is applied to the pinned client for every build.
    git("apply", "--check", "../../.github/android-udpflow.patch", cwd=CLIENT)
    git("apply", "../../.github/android-udpflow.patch", cwd=CLIENT)
    if os.environ["PUBLISH_RELEASE"] != "true":
        version += ".g" + git("rev-parse", "--short=7", "HEAD")
    props["VERSION_NAME"] = version
    props["VERSION_CODE"] = str(1000000 + int(os.environ["GITHUB_RUN_NUMBER"]))
    (CLIENT / "version.properties").write_text("".join(f"{key}={value}\n" for key, value in props.items()))
    build_tag = "v" + version
    existing = subprocess.run(["git", "rev-parse", "--verify", f"refs/tags/{build_tag}^{{commit}}"], capture_output=True, text=True)
    if existing.returncode == 0:
        if existing.stdout.strip() != git("rev-parse", "HEAD"):
            raise ValueError("An existing build tag points to a different commit")
    else:
        git("tag", build_tag)
    state = {"base": base, "commit": git("rev-parse", "HEAD"), "tag": build_tag, "version": version}
    (Path(os.environ["RUNNER_TEMP"]) / "udpflow-source.json").write_text(json.dumps(state))
    output(go_version=props["GO_VERSION"].removeprefix("go"))


def publish():
    repository = os.environ["GITHUB_REPOSITORY"]
    state = json.loads((Path(os.environ["RUNNER_TEMP"]) / "udpflow-source.json").read_text())
    metadata = json.loads(Path("dist/android/SFA-version-metadata.json").read_text())
    if metadata["core_commit"] != state["commit"] or metadata["version_name"] != state["version"]:
        raise ValueError("Release metadata does not describe the tested source")
    release = api(f"repos/{repository}/releases/tags/{state['tag']}", missing_ok=True)
    if release and not release["draft"]:
        raise ValueError("Release is already public; it will not be overwritten")
    remote = git("ls-remote", "origin", "refs/heads/udpflow").split()[0]
    if remote not in {state["base"], state["commit"]}:
        raise ValueError("udpflow changed during the build; refusing to publish stale sources")
    # No forced branch/tag updates. A concurrent push also fails atomically.
    git("push", "--atomic", "origin", f"{state['commit']}:refs/heads/udpflow", f"{state['commit']}:refs/tags/{state['tag']}")
    notes = Path(os.environ["RUNNER_TEMP"]) / "udpflow-release-notes.md"
    notes.write_text(
        f"基于 [官方 {metadata['upstream_tag']}](https://github.com/{UPSTREAM}/releases/tag/{metadata['upstream_tag']})，加入 UDP flow 支持与已验证的修复。\n\n"
        "仅提供 Android 16+（API 36）ARM64 安装包，沿用本仓库签名。客户端默认从本仓库检查正式版及 fork 修订版更新；已关闭检查的设置保持不变。\n\n"
        "原生 libbox 使用 NDK r29 的最高原生 API 35（APK 最低 API 36），启用 RELR 重定位压缩。原生库直接从 APK 加载，并检查 16 KB 对齐；下载体积会增大，安装时不再额外解压原生库。\n\n"
        "TUN 首次分流与 DNS 解析在有界异步任务中执行，保留首包和同流包顺序；UDP 适配器使用单调时钟回收空闲连接。system、mixed 和 gVisor 栈均通过内存 TUN 回归测试。\n\n"
        "DNS 解析失败按固定一秒间隔允许重试，持续流量不会延长失败缓存；DNS 回答及拒绝报文的设备写回不会持有分流器状态锁。稳定通道只检查 latest Release，避免遍历历史版本。\n\n"
        "已安装 udpflow 正式版的 Android 16 用户可通过客户端更新；从更新器仍指向官方的旧构建迁移时需手动安装一次。\n\n"
        f"Core: `{metadata['core_commit']}`\n\nAndroid client: `{metadata['android_client_commit']}`（含本仓库的更新补丁）\n\n"
        "发布前已通过核心测试、竞态测试、客户端更新选择测试及 APK 签名/ABI/API/版本/原生库对齐检查。真实 Android 16 设备的 TUN、耗电与公网代理环境仍需实测。\n"
    )
    assets = sorted(str(path) for path in Path("dist/android").iterdir() if path.is_file())
    gh = ["gh", "release"]
    if release:
        subprocess.run([*gh, "upload", state["tag"], *assets, "--clobber"], check=True)
    else:
        subprocess.run([*gh, "create", state["tag"], *assets, "--verify-tag", "--draft", "--title", state["version"], "--notes-file", str(notes)], check=True)
    subprocess.run([*gh, "edit", state["tag"], "--draft=false", "--prerelease=false", "--latest", "--notes-file", str(notes)], check=True)


if __name__ == "__main__":
    {"plan": plan, "prepare": prepare, "publish": publish}[sys.argv[1]]()
