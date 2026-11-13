#!/usr/bin/env python3
"""Publish matching, HTTPS-tested Clash and Shadowrocket subscriptions to a Gist."""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

import yaml

TARGETS = (
    ("cloudflare", "https://cp.cloudflare.com/generate_204"),
    ("google", "https://www.gstatic.com/generate_204"),
    ("cloudflare_warm", "https://cp.cloudflare.com/generate_204"),
)
SUPPORTED = {"hysteria2", "ss", "vmess", "vless", "trojan"}


def b64(text: str, urlsafe: bool = False) -> str:
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    result = encode(text.encode()).decode()
    return result.rstrip("=") if urlsafe else result


def prepare_proxy(proxy: dict) -> dict:
    """Keep only self-contained, representable outbounds and enforce TLS checking."""
    p = copy.deepcopy(proxy)
    if p.get("type") not in SUPPORTED:
        raise ValueError("unsupported protocol")
    if not all(p.get(key) for key in ("name", "server", "port")):
        raise ValueError("missing required endpoint field")
    if any(p.get(key) for key in ("dialer-proxy", "plugin", "http-opts", "h2-opts",
                                   "ca", "ca-str", "ech-opts", "ports", "tls-fingerprint")):
        raise ValueError("unsupported share-link option")
    if p.get("network", "tcp") not in ("tcp", "ws", "grpc"):
        raise ValueError("unsupported transport")
    if p.get("network") == "ws":
        ws = p.get("ws-opts", {})
        if ws.get("max-early-data") or ws.get("early-data-header-name"):
            raise ValueError("unsupported WebSocket early-data option")
        if set(ws.get("headers", {})) - {"Host", "host"}:
            raise ValueError("unsupported WebSocket header")
    if p["type"] == "ss" and str(p.get("cipher", "")).startswith("2022-"):
        raise ValueError("unsupported Shadowsocks 2022 share-link format")
    if p["type"] in {"hysteria2", "trojan"} or p.get("tls"):
        p["skip-cert-verify"] = False
    # The input config never controls listeners, routing, controllers, or the shell.
    for key in ("sub", "liveness", "interface-name", "routing-mark"):
        p.pop(key, None)
    return p


def transport_query(p: dict) -> dict:
    network = p.get("network", "tcp")
    result = {"type": network}
    if network == "ws":
        ws = p.get("ws-opts", {})
        result["path"] = ws.get("path", "/")
        headers = ws.get("headers", {})
        if headers.get("Host") or headers.get("host"):
            result["host"] = headers.get("Host", headers.get("host"))
    elif network == "grpc":
        result["serviceName"] = p.get("grpc-opts", {}).get("grpc-service-name", "")
    return result


def share_uri(p: dict) -> str:
    protocol = p["type"]
    host = str(p["server"])
    address = f'[{host}]' if ":" in host else host
    endpoint = f'{address}:{int(p["port"])}'
    label = urllib.parse.quote(str(p["name"]), safe="")
    sni = p.get("sni") or p.get("servername") or host
    if protocol == "hysteria2":
        query = {"sni": sni, "insecure": "0"}
        if p.get("obfs"):
            query.update({"obfs": p["obfs"], "obfs-password": p["obfs-password"]})
        if p.get("fingerprint"):
            query["pinSHA256"] = p["fingerprint"]
        auth = urllib.parse.quote(str(p["password"]), safe="")
        return f'hysteria2://{auth}@{endpoint}/?{urllib.parse.urlencode(query)}#{label}'
    if protocol == "ss":
        auth = b64(str(p["cipher"]) + ":" + str(p["password"]), urlsafe=True)
        return f'ss://{auth}@{endpoint}#{label}'
    if protocol == "vmess":
        transport = transport_query(p)
        item = {"v": "2", "ps": p["name"], "add": host, "port": str(p["port"]),
                "id": p["uuid"], "aid": str(p.get("alterId", 0)),
                "scy": p.get("cipher", "auto"), "net": transport["type"],
                "type": "none", "host": transport.get("host", ""),
                "path": transport.get("path", transport.get("serviceName", "")),
                "tls": "tls" if p.get("tls") else "", "sni": sni if p.get("tls") else "",
                "alpn": ",".join(p.get("alpn", [])),
                "fp": p.get("client-fingerprint", "")}
        return "vmess://" + b64(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
    query = transport_query(p)
    if protocol == "trojan" or p.get("tls"):
        query.update({"security": "tls", "sni": sni, "allowInsecure": "0"})
        if p.get("alpn"):
            query["alpn"] = ",".join(p["alpn"])
        if p.get("client-fingerprint"):
            query["fp"] = p["client-fingerprint"]
    else:
        query["security"] = "none"
    if protocol == "vless":
        query["encryption"] = "none"
        if p.get("flow"):
            query["flow"] = p["flow"]
        if p.get("reality-opts"):
            reality = p["reality-opts"]
            query.update({"security": "reality", "pbk": reality["public-key"],
                          "sid": str(reality.get("short-id", ""))})
        auth = str(p["uuid"])
    else:
        auth = str(p["password"])
    return f'{protocol}://{urllib.parse.quote(auth, safe="")}@{endpoint}?{urllib.parse.urlencode(query)}#{label}'


def github_request(path: str, token: str, payload: dict | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "verified-subscriptions",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if payload is None else json.dumps(payload).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request("https://api.github.com/" + path, data=data,
                                     headers=headers, method="GET" if data is None else "PATCH")
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def read_source(args) -> tuple[str, str]:
    if args.source:
        return Path(args.source).read_text(), "local-input"
    parts = args.gist.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("GIST_LINK must have owner/gist_id form")
    gist = github_request("gists/" + parts[1], os.environ.get("GIST_PAT", ""))
    item = gist["files"]["clash.yaml"]
    if item.get("truncated"):
        url = item["raw_url"]
        if urllib.parse.urlsplit(url).hostname != "gist.githubusercontent.com":
            raise ValueError("unexpected Gist raw hostname")
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(5 * 1024 * 1024 + 1)
        if len(raw) > 5 * 1024 * 1024:
            raise ValueError("source exceeds size limit")
        content = raw.decode()
    else:
        content = item["content"]
    return content, gist.get("history", [{}])[0].get("version", "unknown")


def probe_proxies(proxies: list[dict], core: Path, workers: int, timeout: int) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="verified-proxy-test-") as directory:
        work = Path(directory)
        sockets, ports = [], []
        try:
            for _ in proxies:
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                sockets.append(sock)
                ports.append(sock.getsockname()[1])
            config = {"allow-lan": False, "bind-address": "127.0.0.1", "ipv6": False,
                      "mode": "rule", "log-level": "silent",
                      "profile": {"store-selected": False, "store-fake-ip": False},
                      "proxies": proxies,
                      "listeners": [{"name": f'probe-{i}', "type": "mixed", "listen": "127.0.0.1",
                                     "port": port, "proxy": p["name"], "udp": False}
                                    for i, (p, port) in enumerate(zip(proxies, ports))],
                      "rules": ["MATCH,REJECT"]}
            config_path = work / "config.yaml"
            config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
            config_path.chmod(0o600)
            command = [str(core), "-d", str(work), "-f", str(config_path)]
            checked = subprocess.run(command + ["-t"], capture_output=True, timeout=30)
            if checked.returncode:
                # Mihomo diagnostics can include secrets; never print them.
                raise RuntimeError("isolated Mihomo configuration validation failed")
        finally:
            for sock in sockets:
                sock.close()
        environment = {k: v for k, v in os.environ.items()
                       if k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=environment)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("isolated Mihomo process stopped")
                try:
                    with socket.create_connection(("127.0.0.1", ports[0]), timeout=.3):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("isolated Mihomo readiness timed out")
                    time.sleep(.1)

            def check(index: int) -> dict:
                checks = []
                for label, target in TARGETS:
                    result = subprocess.run(
                        ["curl", "--silent", "--show-error", "--noproxy", "", "--proxy",
                         f'http://127.0.0.1:{ports[index]}', "--connect-timeout", str(timeout),
                         "--max-time", str(timeout), "--output", os.devnull,
                         "--write-out", "%{http_code} %{time_total}", target],
                        capture_output=True, text=True, timeout=timeout + 3)
                    values = result.stdout.split()
                    status = int(values[0]) if len(values) == 2 and values[0].isdigit() else 0
                    elapsed = round(float(values[1]) * 1000) if len(values) == 2 else None
                    checks.append({"target": label, "http_status": status,
                                   "delay_ms": elapsed, "passed": result.returncode == 0 and status == 204})
                return {"name": proxies[index]["name"], "type": proxies[index]["type"],
                        "passed": all(item["passed"] for item in checks), "checks": checks,
                        "median_ms": statistics.median([item["delay_ms"] for item in checks
                                                        if item["passed"]])
                                     if any(item["passed"] for item in checks) else None}

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                return list(pool.map(check, range(len(proxies))))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def make_files(proxies: list[dict], records: list[dict], metadata: dict) -> dict:
    available = {item["name"]: item for item in records if item["passed"]}
    selected = [p for p in proxies if p["name"] in available]
    selected.sort(key=lambda p: (available[p["name"]]["median_ms"], p["name"]))
    if not selected:
        raise RuntimeError("no nodes passed; retaining the last successful subscriptions")
    links = [share_uri(p) for p in selected]
    provider = yaml.safe_dump({"proxies": selected}, allow_unicode=True, sort_keys=False)
    mobile = b64("\n".join(links) + "\n") + "\n"
    assert len(yaml.safe_load(provider)["proxies"]) == len(base64.b64decode(mobile).decode().splitlines())
    report = dict(metadata, status="ok", available_count=len(selected), nodes=records,
                  feeds_updated=True, retained_previous_feeds=False,
                  last_success_at=metadata.get("checked_at"))
    return {"verified-clash.yaml": {"content": provider},
            "shadowrocket.txt": {"content": mobile},
            "verified-status.json": {"content": json.dumps(report, ensure_ascii=False, indent=2)}}


def make_failure_files(records: list[dict], metadata: dict, previous: dict) -> dict:
    """Report this failed check without replacing either client's cached feed."""
    retained_count = previous.get("retained_node_count", previous.get("available_count"))
    last_success = previous.get("last_success_at")
    if not last_success and previous.get("available_count", 0) > 0:
        last_success = previous.get("checked_at")
    report = dict(metadata, status="unavailable", available_count=0, nodes=records,
                  feeds_updated=False, retained_previous_feeds=bool(retained_count),
                  retained_node_count=retained_count, last_success_at=last_success)
    return {"verified-status.json": {"content": json.dumps(report, ensure_ascii=False, indent=2)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="local Clash candidate file; otherwise read the Gist")
    parser.add_argument("--gist", default=os.environ.get("GIST_LINK", ""))
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    content, revision = read_source(args)
    data = yaml.safe_load(content)
    candidates = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 1000:
        raise ValueError("source must contain 1 to 1000 proxy candidates")
    proxies, rejected, names = [], [], set()
    for candidate in candidates:
        try:
            proxy = prepare_proxy(candidate)
            share_uri(proxy)  # Validate required conversion fields before testing.
            if proxy["name"] in names:
                raise ValueError("duplicate node name")
            names.add(proxy["name"])
            proxies.append(proxy)
        except (KeyError, TypeError, ValueError):
            rejected.append({"name": candidate.get("name", "") if isinstance(candidate, dict) else "",
                             "reason": "not representable by the supported secure share-link formats"})
    if not proxies:
        raise RuntimeError("no compatible candidates; previous subscriptions were not changed")
    print(f'Testing {len(proxies)} candidates with TLS verification; compatibility exclusions: {len(rejected)}', flush=True)
    records = probe_proxies(proxies, args.core.resolve(), max(1, min(args.workers, 12)),
                           max(3, min(args.timeout, 20)))
    metadata = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source_revision": revision, "source_sha256": hashlib.sha256(content.encode()).hexdigest(),
                "candidate_count": len(candidates), "tls_verification": True,
                "vantage": "github-actions" if os.getenv("GITHUB_ACTIONS") == "true" else "local",
                "compatibility_exclusions": rejected}
    count = sum(item["passed"] for item in records)
    previous = {}
    if count == 0 and args.publish:
        parts = args.gist.split("/")
        token = os.environ.get("GIST_PAT", "")
        if len(parts) != 2 or not all(parts) or not token:
            raise ValueError("publishing requires GIST_LINK and GIST_PAT")
        gist = github_request("gists/" + parts[1], token)
        previous_text = gist.get("files", {}).get("verified-status.json", {}).get("content", "{}")
        try:
            previous = json.loads(previous_text)
        except (TypeError, ValueError):
            previous = {}
        if not isinstance(previous, dict):
            previous = {}
    files = (make_files(proxies, records, metadata) if count else
             make_failure_files(records, metadata, previous))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, item in files.items():
        path = args.output_dir / name
        path.write_text(item["content"])
        path.chmod(0o600)
    if args.publish:
        parts = args.gist.split("/")
        token = os.environ.get("GIST_PAT", "")
        if len(parts) != 2 or not all(parts) or not token:
            raise ValueError("publishing requires GIST_LINK and GIST_PAT")
        response = github_request("gists/" + parts[1], token, {"files": files})
        if not all(name in response.get("files", {}) for name in files):
            raise RuntimeError("GitHub did not confirm all output files")
    if count:
        print(f'Verified {count}/{len(candidates)} nodes; matching Clash and Shadowrocket feeds ' +
              ("published." if args.publish else "written locally."), flush=True)
    else:
        print('No usable nodes. Current status updated to unavailable; previous client feeds retained.', flush=True)
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            if count:
                summary.write(f'Verified **{count}/{len(candidates)}** nodes with TLS certificate checking. '
                              'Clash and Shadowrocket contain the same nodes. '
                              'Measurements are from the GitHub runner; client-network latency differs.\n')
            else:
                summary.write(f'**0/{len(candidates)} nodes passed.** `verified-status.json` records '
                              'this failure and the last successful check time. The client feeds '
                              'were retained for recovery and are **not currently verified usable**.\n')
    if count == 0:
        raise RuntimeError("no nodes passed; unavailable status recorded; previous client feeds retained")


if __name__ == "__main__":
    main()
