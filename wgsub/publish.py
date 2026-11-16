"""Publish the subscription to GitHub without touching any other repo."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

API = "https://api.github.com"


class GitHub:
    def __init__(self, token: str):
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            API + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "wg-sub",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"{method} {path} -> {exc.code} {detail[:300]}") from exc


def ensure_repo(gh: GitHub, name: str) -> None:
    try:
        gh.request("GET", f"/repos/o6ash/{name}")
        return
    except RuntimeError as exc:
        if "-> 404" not in str(exc):
            raise
    gh.request(
        "POST",
        "/user/repos",
        {
            "name": name,
            "private": False,
            "description": "WireGuard and AmneziaWG links for CoreForge",
            "auto_init": False,
            "has_issues": False,
            "has_wiki": False,
        },
    )


def put_tree(gh: GitHub, repo: str, files: dict[str, str], message: str) -> str:
    blobs = []
    for path, content in files.items():
        blob = gh.request(
            "POST",
            f"/repos/o6ash/{repo}/git/blobs",
            {"content": content, "encoding": "utf-8"},
        )
        blobs.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    tree = gh.request("POST", f"/repos/o6ash/{repo}/git/trees", {"tree": blobs})
    commit_body = {"message": message, "tree": tree["sha"]}
    try:
        ref = gh.request("GET", f"/repos/o6ash/{repo}/git/ref/heads/main")
        commit_body["parents"] = [ref["object"]["sha"]]
    except RuntimeError as exc:
        if "-> 409" not in str(exc) and "-> 404" not in str(exc):
            raise
    commit = gh.request("POST", f"/repos/o6ash/{repo}/git/commits", commit_body)
    if "parents" in commit_body:
        gh.request(
            "PATCH",
            f"/repos/o6ash/{repo}/git/refs/heads/main",
            {"sha": commit["sha"]},
        )
    else:
        gh.request(
            "POST",
            f"/repos/o6ash/{repo}/git/refs",
            {"ref": "refs/heads/main", "sha": commit["sha"]},
        )
    return commit["sha"]


def subscription_text(uris: list[str]) -> str:
    lines = [uri for uri in uris if uri.startswith("wireguard://")]
    if not lines:
        raise RuntimeError("refusing to publish an empty subscription")
    if any("raw.githubusercontent.com" in uri for uri in lines):
        raise RuntimeError("subscription must contain links, not file addresses")
    return "\n".join(lines) + "\n"


def subscription_base64(plain: str) -> str:
    return base64.b64encode(plain.encode("utf-8")).decode("ascii") + "\n"
