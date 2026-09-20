"""Follow published testing releases while preserving local patches and release gates."""

import json
import os
from pathlib import Path
import subprocess
import sys

from udpflow_release import CLIENT, MANIFEST, UPSTREAM, api, git, output, properties
import udpflow_testing_sync as sync

BRANCH = "udpflow-testing"


def snapshot():
    source = json.loads(MANIFEST.read_text())
    return source, sync.validate_source(source)


def plan():
    current, _ = snapshot()
    event = os.environ["GITHUB_EVENT_NAME"]
    if event == "pull_request":
        output(build=True, publish=False, source=json.dumps(current), reason="pull-request")
        return
    if os.environ["GITHUB_REF"] != f"refs/heads/{BRANCH}":
        raise ValueError("Testing snapshots must be published from udpflow-testing")
    auto_sync = event == "schedule" or os.environ.get("SYNC_UPSTREAM") == "true"
    source = sync.select_source(current) if auto_sync else current
    version = sync.validate_source(source)
    if not auto_sync:
        recorded = api(f"repos/{UPSTREAM}/commits/{source['upstream_commit']}")
        if recorded["sha"] != source["upstream_commit"]:
            raise ValueError("Upstream did not return the pinned commit")
    release = api(f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/v{version}", missing_ok=True)
    published = release is not None and not release["draft"]
    if published and not release["prerelease"]:
        raise ValueError("Testing release must be marked as a prerelease")
    if published and source != current:
        raise ValueError("A newer fork release is already public but its source manifest is not adopted; reconcile the branch before publishing")
    build = not published or event == "push" or os.environ.get("FORCE_BUILD") == "true"
    reason = "new-upstream-release" if source != current else "unpublished-fork-revision" if not published else "verify-current-source" if build else "already-published"
    output(build=build, publish=not published, source=json.dumps(source), reason=reason)
    print(f"{reason}: {version}")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as stream:
            stream.write(f"Testing update: **{reason}** — `{version}`\n\nCore: `{source['upstream_commit']}`; Android: `{source['android_client_commit']}`.\n")


def prepare():
    current, _ = snapshot()
    source = json.loads(os.environ["TESTING_SOURCE"]) if os.environ.get("TESTING_SOURCE") else current
    version = sync.validate_source(source)
    base = git("rev-parse", "HEAD")
    git("diff", "--quiet")
    git("diff", "--cached", "--quiet")
    git("fetch", "--no-tags", f"https://github.com/{UPSTREAM}.git", source["upstream_commit"])
    if git("rev-parse", "FETCH_HEAD^{commit}") != source["upstream_commit"]:
        raise ValueError("Fetched a different upstream commit")
    git("merge-base", "--is-ancestor", current["upstream_commit"], base)
    if source != current:
        # Recheck the release tag after planning, before merging any source.
        git("fetch", "--no-tags", f"https://github.com/{UPSTREAM}.git", f"refs/tags/v{source['upstream_version']}")
        if git("rev-parse", "FETCH_HEAD^{commit}") != source["upstream_commit"]:
            raise ValueError("Upstream release tag changed after planning")
    git("submodule", "update", "--init", "--recursive", str(CLIENT))
    commit = sync.synchronize(current, source, base) if source != current else base
    if git("rev-parse", "HEAD", cwd=CLIENT) != source["android_client_commit"]:
        raise ValueError("Android client does not match the reviewed pin")
    props = properties(CLIENT / "version.properties")
    if props["VERSION_NAME"] != source["upstream_version"]:
        raise ValueError("Android client does not match the upstream development version")
    git("apply", "--check", "../../.github/android-udpflow.patch", cwd=CLIENT)
    git("apply", "../../.github/android-udpflow.patch", cwd=CLIENT)
    if os.environ["PUBLISH_RELEASE"] != "true":
        version += ".g" + commit[:7]
    props["VERSION_NAME"] = version
    props["VERSION_CODE"] = str(1000000 + int(os.environ["GITHUB_RUN_NUMBER"]))
    (CLIENT / "version.properties").write_text("".join(f"{key}={value}\n" for key, value in props.items()))
    tag = "v" + version
    existing = subprocess.run(["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], capture_output=True, text=True)
    if existing.returncode == 0:
        if existing.stdout.strip() != commit:
            raise ValueError("Existing build tag belongs to a different commit")
    else:
        git("tag", tag)
    state = {"base": base, "commit": commit, "tag": tag, "version": version, **source}
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
    if remote not in {state["base"], state["commit"]}:
        raise ValueError("Testing branch changed during the build")
    git("push", "--atomic", "origin", f"{state['commit']}:refs/heads/{BRANCH}", f"{state['commit']}:refs/tags/{state['tag']}")
    notes = Path(os.environ["RUNNER_TEMP"]) / "udpflow-testing-notes.md"
    notes.write_text(
        f"基于上游 [testing `{state['upstream_commit'][:7]}`](https://github.com/{UPSTREAM}/commit/{state['upstream_commit']}) 的开发快照，包含现有 UDP flow 修复。\n\n"
        "Android 16+（API 36）ARM64 签名 APK，沿用本仓库签名；versionCode 递增，可覆盖安装。此 Release 标记为预发布，客户端可选择测试更新通道。\n\n"
        "修复 FakeIP 元数据缺失时的缓存重置、跨写缓冲层的正反向映射错配，以及地址重分配时误删已迁移域名的问题。真正的存储重置错误会阻止启动，避免继续使用不一致映射。\n\n"
        "优化 FakeIP 查询：正常数据库命中只读一次，数据库等待移到共享锁外；查询跨越刷盘批次切换时再校验地址归属。新增刷盘交接、数据库等待期间继续缓冲写入的回归测试，以及读事务计数和混合读写基准。\n\n"
        "补齐并发重置边界：数据库删除成功后再清理 FakeIP 缓冲并更换批次身份，避免查询返回重置前已失效的地址。删除失败保留缓冲映射，DNS/RDRC 等其他缓存继续保留；正常查询仍使用现有短锁路径。\n\n"
        "进一步减少 FakeIP 管理与首次分配开销：重置和元数据读取使用同步写事务，省去批处理聚合等待；成功重置后、首次地址映射刷盘前，跳过已知空库的正反向读取。保留事务、失败处理和已有并发保护，并覆盖首次刷盘交接、失败重置及 IPv4/IPv6 新域名分配。\n\n"
        "优化 FakeIP 刷盘：优先复用当前写事务内已有的 bucket，缺失时再创建，减少重复桶名复制。已有桶写入基准每条减少两次分配、32 字节；空库首次建桶会多一次查找，批量刷盘耗时仍受 I/O 影响。补齐混合 IPv4/IPv6 迁移和事务回滚回归，并记录事务内写入、首次刷盘与重分配刷盘基准。\n\n"
        "已迁移本地 sing-tun / sing-mux 补丁，并适配上游新增的默认 Go TUN 栈。发布流程执行核心测试、两套竞态检查、转发基准、客户端更新测试，以及 APK 签名、ABI、版本、最低 API 和 16 KB 对齐检查。\n\n"
        "修复 UDP DNS 经 Snell 与 TCP Fast Open 转发时，在首包发送前提前取消建连上下文、导致解析超时的问题。连接上下文保留至连接退役，关闭、失效、重置与失败时仍释放资源；覆盖真实 Snell UDP 解析、连接复用及重置、上下文清理和进行中建连的取消。\n\n"
        "修复 Android 自动启动 VPN 时与内核初始化之间的竞态：启动入口共同等待一次后台初始化完成，避免提前使用未设置的控制接口目录；在等待前及时建立前台通知，启动失败原因同步写入系统日志。覆盖初始化等待、并发启动、失败传播及等待者取消的回归测试。\n\n"
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
    try:
        {"plan": plan, "prepare": prepare, "publish": publish}[sys.argv[1]]()
    except (ValueError, subprocess.CalledProcessError) as error:
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a") as stream:
                stream.write(f"\nTesting update stopped; the existing public release is retained.\n\n```text\n{error}\n```\n")
        raise
