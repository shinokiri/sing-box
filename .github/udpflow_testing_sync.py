"""Select published prereleases and merge immutable upstream snapshots locally."""

import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from udpflow_release import CLIENT, MANIFEST, UPSTREAM, api, git, properties

ANDROID = "SagerNet/sing-box-for-android"
MODULES = ("sing-mux", "sing-tun", "sing-snell")
VERSION = re.compile(r"([1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-(alpha|beta|rc)\.(0|[1-9]\d*)")


def version_key(version):
    match = VERSION.fullmatch(version)
    if not match:
        raise ValueError(f"Not a canonical testing version: {version!r}")
    major, minor, patch, stage, number = match.groups()
    return int(major), int(minor), int(patch), ("alpha", "beta", "rc").index(stage), int(number)


def validate_source(source):
    if source.get("upstream_branch") != "testing":
        raise ValueError("Expected a pinned testing snapshot")
    version_key(source["upstream_version"])
    for field in ("upstream_commit", "android_client_commit"):
        if not re.fullmatch(r"[0-9a-f]{40}", source.get(field, "")):
            raise ValueError(f"Invalid {field}")
    revision = source["fork_revision"]
    if type(revision) is not int or revision < 1:
        raise ValueError("Expected a positive fork revision")
    return f"{source['upstream_version']}-udpflow.{revision}"


def latest_testing_release():
    # REST release pages include every asset (tens of MB for this upstream).
    # Query only version-selection metadata while still scanning all pages.
    query = """query($owner: String!, $name: String!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        releases(first: 100, after: $cursor, orderBy: {field: CREATED_AT, direction: DESC}) {
          nodes { tag_name: tagName draft: isDraft prerelease: isPrerelease published_at: publishedAt }
          pageInfo { hasNextPage endCursor }
        }
      }
    }"""
    owner, name = UPSTREAM.split("/")
    candidates = []
    cursor = None
    seen = set()
    while True:
        result = api("graphql", data={"query": query, "variables": {"owner": owner, "name": name, "cursor": cursor}})
        if result.get("errors"):
            raise ValueError("GitHub release query failed: " + json.dumps(result["errors"]))
        repository = (result.get("data") or {}).get("repository")
        if repository is None:
            raise ValueError("GitHub release query did not return the upstream repository")
        connection = repository["releases"]
        for release in connection["nodes"]:
            tag = release["tag_name"]
            if not release["draft"] and release["prerelease"] and release.get("published_at") and tag.startswith("v") and VERSION.fullmatch(tag[1:]):
                candidates.append(release)
        if not connection["pageInfo"]["hasNextPage"]:
            break
        cursor = connection["pageInfo"]["endCursor"]
        if not cursor or cursor in seen:
            raise ValueError("GitHub release pagination did not advance")
        seen.add(cursor)
    if not candidates:
        raise ValueError("No published upstream alpha/beta/rc release found")
    return max(candidates, key=lambda item: version_key(item["tag_name"][1:]))


def tag_commit(tag):
    ref = api(f"repos/{UPSTREAM}/git/ref/tags/{tag}")["object"]
    while ref["type"] == "tag":
        ref = api(f"repos/{UPSTREAM}/git/tags/{ref['sha']}")["object"]
    if ref["type"] != "commit" or not re.fullmatch(r"[0-9a-f]{40}", ref["sha"]):
        raise ValueError("Upstream release tag does not point to a commit")
    return ref["sha"]


def android_properties(commit):
    value = api(f"repos/{ANDROID}/contents/version.properties?ref={commit}")
    return dict(line.split("=", 1) for line in base64.b64decode(value["content"]).decode().splitlines() if "=" in line)


def matching_android_commit(version):
    # Pin the matching dev snapshot. If dev has advanced to a newer version,
    # search version-bump commits rather than pairing a new client with old core.
    head = api(f"repos/{ANDROID}/commits/dev")["sha"]
    if android_properties(head).get("VERSION_NAME") == version:
        return head
    page = 1
    while True:
        commits = api(f"repos/{ANDROID}/commits?sha={head}&path=version.properties&per_page=100&page={page}")
        for commit in commits:
            sha = commit["sha"]
            if sha != head and android_properties(sha).get("VERSION_NAME") == version:
                return sha
        if len(commits) < 100:
            break
        page += 1
    raise ValueError(f"Android dev has no matching {version} snapshot; wait for the client release")


def select_source(current):
    release = latest_testing_release()
    version = release["tag_name"][1:]
    if version_key(version) < version_key(current["upstream_version"]):
        raise ValueError("Refusing to downgrade the pinned testing version")
    commit = tag_commit(release["tag_name"])
    if version == current["upstream_version"]:
        if commit != current["upstream_commit"]:
            raise ValueError("Recorded upstream tag was moved; review it before publishing")
        return current
    source = {
        "upstream_branch": "testing", "upstream_version": version,
        "upstream_commit": commit, "android_client_commit": matching_android_commit(version),
        "fork_revision": 1,
    }
    validate_source(source)
    return source


def commit_tree(tree, parents, message, cwd=None):
    args = ["-c", "user.name=github-actions[bot]", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com", "-c", "commit.gpgsign=false", "commit-tree", tree]
    for parent in parents:
        args.extend(["-p", parent])
    return git(*args, "-m", message, cwd=cwd)


def merge_snapshots(base, ours, incoming, cwd=None, owned_paths=()):
    # Explicit bases remain valid when upstream rebases its development history.
    if owned_paths:
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, "GIT_INDEX_FILE": str(Path(directory) / "index")}
            git("read-tree", incoming, cwd=cwd, env=env)
            git("restore", f"--source={base}", "--staged", "--", *owned_paths, cwd=cwd, env=env)
            incoming = git("write-tree", cwd=cwd, env=env)
    result = subprocess.run(["git", "merge-tree", "--write-tree", f"--merge-base={base}", ours, incoming], cwd=cwd, capture_output=True, text=True)
    if result.returncode == 1:
        raise ValueError("Upstream patch conflict; retain the published version and rebase these paths:\n" + result.stdout)
    result.check_returncode()
    return result.stdout.strip()


def module_ref(version):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError(f"Invalid module version: {version!r}")
    pseudo = re.search(r"[.-]\d{14}-([0-9a-f]{12,40})$", version)
    return pseudo[1] if pseudo else version


def module_requirement(path, name):
    matches = re.findall(rf"(?m)^\s*(?:require\s+)?github\.com/sagernet/{re.escape(name)}\s+(v\S+)", path.read_text())
    if len(matches) != 1:
        raise ValueError(f"Expected one {name} requirement in {path}")
    return matches[0]


def migrate_module(name, directory, required):
    previous = (directory / "UPSTREAM_VERSION").read_text().strip()
    if previous == required:
        return
    with tempfile.TemporaryDirectory(prefix=f"{name}-sync-") as temporary:
        repo = Path(temporary) / "repo"
        git("init", "--quiet", str(repo))
        commits = []
        for version in (previous, required):
            ref = module_ref(version)
            if re.fullmatch(r"[0-9a-f]{12,40}", ref):
                resolved = api(f"repos/SagerNet/{name}/commits/{ref}")["sha"]
                if not re.fullmatch(r"[0-9a-f]{40}", resolved) or not resolved.startswith(ref):
                    raise ValueError(f"{name}: pseudo-version resolved to an unexpected commit")
                ref = resolved
            git("fetch", "--depth=1", "--no-tags", f"https://github.com/SagerNet/{name}.git", ref, cwd=repo)
            commits.append(git("rev-parse", "FETCH_HEAD^{commit}", cwd=repo))
        old, new = commits
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(temporary) / "index")}
        git("read-tree", "--empty", cwd=repo, env=env)
        git(f"--work-tree={directory.resolve()}", "add", "--all", "--force", "--", ".", cwd=repo, env=env)
        ours = commit_tree(git("write-tree", cwd=repo, env=env), [old], "local module patches", cwd=repo)
        try:
            merged = merge_snapshots(old, ours, new, cwd=repo)
        except ValueError as error:
            raise ValueError(f"{name} {previous} -> {required}: {error}") from error
        staged = Path(temporary) / "merged"
        staged.mkdir()
        git("read-tree", merged, cwd=repo, env=env)
        git("checkout-index", "--all", f"--prefix={staged}/", cwd=repo, env=env)
        (staged / "UPSTREAM_VERSION").write_text(required + "\n")
        # This is a disposable CI checkout; nothing is pushed until all gates pass.
        shutil.rmtree(directory)
        shutil.copytree(staged, directory, symlinks=True)
    print(f"Migrated {name}: {previous} -> {required}")


def synchronize(current, selected, base):
    validate_source(selected)
    if version_key(selected["upstream_version"]) <= version_key(current["upstream_version"]):
        raise ValueError("Automatic synchronization requires a newer published testing version")
    target = selected["upstream_commit"]
    merged = merge_snapshots(current["upstream_commit"], base, target, owned_paths=(".github", str(CLIENT)))
    git("read-tree", "-m", "-u", base, merged)
    git("fetch", "--no-tags", "origin", selected["android_client_commit"], cwd=CLIENT)
    git("checkout", "--detach", selected["android_client_commit"], cwd=CLIENT)
    git("submodule", "update", "--init", "--recursive", cwd=CLIENT)
    if properties(CLIENT / "version.properties")["VERSION_NAME"] != selected["upstream_version"]:
        raise ValueError("Selected Android client does not match the new testing core")
    for name in MODULES:
        required = module_requirement(Path("go.mod"), name)
        if module_requirement(Path("test/go.mod"), name) != required:
            raise ValueError(f"Core and test module disagree about {name}; review dependency migration")
        migrate_module(name, Path("third_party") / name, required)
    MANIFEST.write_text(json.dumps(selected, indent=2) + "\n")
    git("add", str(MANIFEST), str(CLIENT), "third_party")
    commit = commit_tree(git("write-tree"), [base, target], f"release: follow upstream v{selected['upstream_version']}")
    git("update-ref", "HEAD", commit, base)
    return commit
