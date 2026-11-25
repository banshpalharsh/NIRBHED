"""Cheap structured extraction from distilled tool output into the asset graph.

Keeps the agent's running state rich (ports, urls, subdomains) without paying to
have the LLM re-parse raw output every turn.
"""

from __future__ import annotations

import re

from nirbhed.core.graph import AssetGraph

_URL = re.compile(r"https?://[^\s'\"<>]+")
_PORT = re.compile(r"\b(\d{1,5})/(tcp|udp)\b.*\bopen\b", re.IGNORECASE)
_SUB = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def update_graph(graph: AssetGraph, root: str, text: str) -> None:
    for m in _URL.findall(text):
        graph.add_endpoint(m.rstrip(".,);"))
    for port, proto in _PORT.findall(text):
        graph.add_service(f"{root}:{port} {proto}")
    # subdomains of the root
    base = root.split("://")[-1].split("/")[0]
    for m in _SUB.findall(text):
        host = m.lower()
        if host.endswith(base) and host != base:
            graph.add_subdomain(host)
