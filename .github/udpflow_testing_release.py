"""Build and publish an explicitly reviewed, immutable upstream testing snapshot."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from udpflow_release import CLIENT, MANIFEST, UPSTREAM, api, git, output, properties

BRANCH = "udpflow-testing"


def snapshot():
    source = json.loads(MANIFEST.read_text())
    if source.get("upstream_branch") != "testing":
        raise ValueError("Expected an explicitly pinned testing snapshot")
    for field in ("upstream_commit", "android_client_commit"):
        if not re.fullmatch(r"[0-9a-f]{40}", source.get(field, "")):
            raise ValueError(f"Invalid {field}")
    if not re.fullmatch(r"[1-9]\d*\.\d+\.\d+-(alpha|beta|rc)\.\d+", source["upstream_version"]):
        raise ValueError("Expected an upstream development version")
    revision = source["fork_revision"]
    if type(revision) is not int or revision < 1:
        raise ValueError("Expected a positive fork revision")
    return source, f"{source['upstream_version']}-udpflow.{revision}"


def plan():
    source, version = snapshot()
    if os.environ["GITHUB_EVENT_NAME"] == "pull_request":
        output(build=True, publish=False)
        return
    if os.environ["GITHUB_REF"] != f"refs/heads/{BRANCH}":
        raise ValueError("Testing snapshots must be published from udpflow-testing")
    recorded = api(f"repos/{UPSTREAM}/commits/{source['upstream_commit']}")
    if recorded["sha"] != source["upstream_commit"]:
        raise ValueError("Upstream did not return the pinned commit")
    release = api(f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/v{version}", missing_ok=True)
    published = release is not None and not release["draft"]
    if published and not release["prerelease"]:
        raise ValueError("Testing release must be marked as a prerelease")
    output(build=True, publish=not published)


def prepare():
    source, version = snapshot()
    base = git("rev-parse", "HEAD")
    git("diff", "--quiet")
    git("diff", "--cached", "--quiet")
    git("fetch", "--no-tags", f"https://github.com/{UPSTREAM}.git", source["upstream_commit"])
    if git("rev-parse", "FETCH_HEAD^{commit}") != source["upstream_commit"]:
        raise ValueError("Fetched a different upstream commit")
    git("merge-base", "--is-ancestor", source["upstream_commit"], base)
    git("submodule", "update", "--init", "--recursive", str(CLIENT))
    if git("rev-parse", "HEAD", cwd=CLIENT) != source["android_client_commit"]:
        raise ValueError("Android client does not match the reviewed pin")
    props = properties(CLIENT / "version.properties")
    if props["VERSION_NAME"] != source["upstream_version"]:
        raise ValueError("Android client does not match the upstream development version")
    git("apply", "--check", "../../.github/android-udpflow.patch", cwd=CLIENT)
    git("apply", "../../.github/android-udpflow.patch", cwd=CLIENT)
    if os.environ["PUBLISH_RELEASE"] != "true":
        version += ".g" + base[:7]
    props["VERSION_NAME"] = version
    props["VERSION_CODE"] = str(1000000 + int(os.environ["GITHUB_RUN_NUMBER"]))
    (CLIENT / "version.properties").write_text("".join(f"{key}={value}\n" for key, value in props.items()))
    tag = "v" + version
    existing = subprocess.run(["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], capture_output=True, text=True)
    if existing.returncode == 0:
        if existing.stdout.strip() != base:
            raise ValueError("Existing build tag belongs to a different commit")
    else:
        git("tag", tag)
    state = {"base": base, "commit": base, "tag": tag, "version": version, **source}
    (Path(os.environ["RUNNER_TEMP"]) / "udpflow-source.json").write_text(json.dumps(state))
    output(go_version=props["GO_VERSION"].removeprefix("go"))


def publish():
    if os.environ["GITHUB_REF"] != f"refs/heads/{BRANCH}":
        raise ValueError("Testing snapshots must be published from udpflow-testing")
    repository = os.environ["GITHUB_REPOSITORY"]
    state = json.loads((Path(os.environ["RUNNER_TEMP"]) / "udpflow-source.json").read_text())
    metadata = json.loads(Path("dist/android/SFA-version-metadata.json").read_text())
    expected = {"core_commit": state["commit"], "version_name": state["version"], "upstream_commit": state["upstream_commit"], "android_client_commit": state["android_client_commit"]}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("Release metadata does not describe the tested snapshot")
    release = api(f"repos/{repository}/releases/tags/{state['tag']}", missing_ok=True)
    if release and not release["draft"]:
        raise ValueError("Published releases cannot be overwritten")
    remote = git("ls-remote", "origin", f"refs/heads/{BRANCH}").split()[0]
    if remote != state["commit"]:
        raise ValueError("Testing branch changed during the build")
    git("push", "--atomic", "origin", f"{state['commit']}:refs/heads/{BRANCH}", f"{state['commit']}:refs/tags/{state['tag']}")
    notes = Path(os.environ["RUNNER_TEMP"]) / "udpflow-testing-notes.md"
    notes.write_text(
        f"基于上游 [testing `{state['upstream_commit'][:7]}`](https://github.com/{UPSTREAM}/commit/{state['upstream_commit']}) 的开发快照，包含现有 UDP flow 修复。\n\n"
        "Android 16+（API 36）ARM64 签名 APK，沿用本仓库签名；versionCode 递增，可覆盖安装。此 Release 标记为预发布，客户端可选择测试更新通道。\n\n"
        "修复 FakeIP 元数据缺失时的缓存重置、跨写缓冲层的正反向映射错配，以及地址重分配时误删已迁移域名的问题。真正的存储重置错误会阻止启动，避免继续使用不一致映射。\n\n"
        "优化 FakeIP 查询：正常数据库命中只读一次，数据库等待移到共享锁外；查询跨越刷盘批次切换时再校验地址归属。新增刷盘交接、数据库等待期间继续缓冲写入的回归测试，以及读事务计数和混合读写基准。\n\n"
        "补齐并发重置边界：数据库删除成功后再清理 FakeIP 缓冲并更换批次身份，避免查询返回重置前已失效的地址。删除失败保留缓冲映射，DNS/RDRC 等其他缓存继续保留；正常查询仍使用现有短锁路径。\n\n"
        "已迁移本地 sing-tun / sing-mux 补丁，并适配上游新增的默认 Go TUN 栈。发布流程执行核心测试、两套竞态检查、转发基准、客户端更新测试，以及 APK 签名、ABI、版本、最低 API 和 16 KB 对齐检查。\n\n"
        f"Core: `{state['commit']}`\n\nAndroid client: `{state['android_client_commit']}`（含本仓库更新补丁）\n\n"
        "这是上游 testing 开发版本。Android 真机切网、长期运行、RTT 和耗电尚未实测。\n"
    )
    assets = sorted(str(path) for path in Path("dist/android").iterdir() if path.is_file())
    if release:
        subprocess.run(["gh", "release", "upload", state["tag"], *assets, "--clobber"], check=True)
    else:
        subprocess.run(["gh", "release", "create", state["tag"], *assets, "--verify-tag", "--draft", "--prerelease", "--title", state["version"], "--notes-file", str(notes)], check=True)
    subprocess.run(["gh", "release", "edit", state["tag"], "--draft=false", "--prerelease=true", "--latest=false", "--notes-file", str(notes)], check=True)


if __name__ == "__main__":
    {"plan": plan, "prepare": prepare, "publish": publish}[sys.argv[1]]()
