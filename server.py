"""
ThreatFox - Malware IOC lookup

This is a super simple MCP server for the ThreatFox Community API
(https://threatfox.abuse.ch/api/), run by abuse.ch. ThreatFox is a free,
community-driven platform for sharing indicators of compromise (IOCs)
associated with malware.

This server exposes the read/lookup endpoints of the API (recent IOCs,
lookup by ID, search, search by hash, tag/malware info, and the reference
lists). It does not expose the `submit_ioc` endpoint, since that writes
data to a shared community database — see "Notes / next steps" in the
README if you want to add that yourself.

Docs: https://threatfox.abuse.ch/api/

Setup:
    pip install mcp httpx
    export THREATFOX_AUTH_KEY=your_auth_key_here   # required, see README

Run (for local testing over stdio):
    python server.py
"""

import os
from typing import Any
from collections import Counter
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "")

mcp = FastMCP("threatfox")


async def _query(payload: dict[str, Any]) -> dict[str, Any]:
    """POST a query to the ThreatFox API and return parsed JSON."""
    headers = {"Auth-Key": THREATFOX_AUTH_KEY} if THREATFOX_AUTH_KEY else {}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(THREATFOX_API_URL, headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()

def _matches_query(ioc: dict[str, Any], query: str) -> bool:
    """Loose semantic match across IOC fields."""
    if not query:
        return True

    q = query.lower()

    malware = (ioc.get("malware") or "").lower()
    malware_printable = (ioc.get("malware_printable") or "").lower()
    tags = [t.lower() for t in (ioc.get("tags") or [])]
    ioc_value = (ioc.get("ioc") or "").lower()

    return (
        q in malware
        or q in malware_printable
        or q in ioc_value
        or any(q in t for t in tags)
    )

@mcp.tool()
async def get_recent_iocs(days: int = 1, limit: int = 50,) -> dict[str, Any]:
    """Get recently added IOCs from ThreatFox.

    Args:
        days: Number of days to look back (1-7).
        limit: Maximum number of IOCs to return.

    Returns:
        A dict containing the most recent IOCs.
    """
    result = await _query({"query": "get_iocs", "days": days})

    if result.get("query_status") == "ok":
        data = result.get("data", [])
        result["total_results"] = len(data)
        result["returned_results"] = min(limit, len(data))
        result["data"] = data[:limit]

    return result

@mcp.tool()
async def filter_recent_iocs(
    days: int = 1,
    limit: int = 100,
    query: str | None = None,
    ioc_type: str | None = None,
    threat_type: str | None = None,
    confidence_min: int | None = None,
) -> dict[str, Any]:
    """Semantically filter recent IOCs across malware, tags, and IOC value."""

    result = await _query({"query": "get_iocs", "days": days})

    if result.get("query_status") != "ok":
        return result

    data = result.get("data") or []

    # --- semantic filter ---
    if query:
        data = [ioc for ioc in data if _matches_query(ioc, query)]

    # --- structured filters ---
    if ioc_type:
        data = [
            ioc for ioc in data
            if (ioc.get("ioc_type") or "").lower() == ioc_type.lower()
        ]

    if threat_type:
        data = [
            ioc for ioc in data
            if (ioc.get("threat_type") or "").lower() == threat_type.lower()
        ]

    if confidence_min is not None:
        data = [
            ioc for ioc in data
            if int(ioc.get("confidence_level") or 0) >= confidence_min
        ]

    # --- dedupe ---
    seen = set()
    deduped = []

    for ioc in data:
        key = ioc.get("id") or ioc.get("ioc")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ioc)

    # --- truncate ---
    result["total_results"] = len(deduped)
    result["returned_results"] = min(limit, len(deduped))
    result["data"] = deduped[:limit]

    return result

@mcp.tool()
async def get_ioc_by_id(ioc_id: str) -> dict[str, Any]:
    """Look up a single IOC on ThreatFox by its ThreatFox ID.

    Args:
        ioc_id: The ThreatFox IOC ID to look up, e.g. "41".

    Returns:
        A dict with the full IOC record, including associated malware
        samples if any.
    """
    return await _query({"query": "ioc", "id": ioc_id})


@mcp.tool()
async def search_ioc(search_term: str, exact_match: bool = False) -> dict[str, Any]:
    """Search ThreatFox for an IOC (IP, domain, URL, or ip:port).

    Args:
        search_term: The IOC value to search for, e.g. "139.180.203.104".
        exact_match: If True, search for the exact IOC instead of doing a
            wildcard search. Default: False.

    Returns:
        A dict with query_status and a list of matching IOC records under
        "data".
    """
    return await _query(
        {"query": "search_ioc", "search_term": search_term, "exact_match": exact_match}
    )


@mcp.tool()
async def search_by_hash(file_hash: str) -> dict[str, Any]:
    """Search ThreatFox for IOCs associated with a malware sample hash.

    Args:
        file_hash: An MD5 or SHA256 hash of the file to look up.

    Returns:
        A dict with query_status and a list of IOC records associated with
        that file hash under "data".
    """
    return await _query({"query": "search_hash", "hash": file_hash})


@mcp.tool()
async def get_tag_info(tag: str, limit: int = 100) -> dict[str, Any]:
    """Get IOCs on ThreatFox associated with a given tag.

    Args:
        tag: The tag to query, e.g. "Magecart".
        limit: Max number of results. Default: 100, max: 1000.

    Returns:
        A dict with query_status and a list of matching IOC records under
        "data".
    """
    return await _query({"query": "taginfo", "tag": tag, "limit": limit})


@mcp.tool()
async def get_malware_info(malware: str, limit: int = 100) -> dict[str, Any]:
    """Get IOCs on ThreatFox associated with a given malware family.

    Args:
        malware: The malware family name (Malpedia naming scheme), e.g.
            "win.cobalt_strike". Use get_malware_list to find valid names.
        limit: Max number of results. Default: 100, max: 1000.

    Returns:
        A dict with query_status and a list of matching IOC records under
        "data".
    """
    return await _query({"query": "malwareinfo", "malware": malware, "limit": limit})


@mcp.tool()
async def get_malware_label(malware: str, platform: str | None = None) -> dict[str, Any]:
    """Look up the correct Malpedia malware label/name for a given malware name.

    Args:
        malware: The malware name you want to resolve, e.g. "warzone".
        platform: Optional platform filter: "win", "osx", "apk", "jar",
            or "elf".

    Returns:
        A dict with query_status and matching malware label(s) under
        "data".
    """
    payload: dict[str, Any] = {"query": "get_label", "malware": malware}
    if platform:
        payload["platform"] = platform
    return await _query(payload)


@mcp.tool()
async def get_malware_list() -> dict[str, Any]:
    """Get the full list of malware families known to ThreatFox (from Malpedia).

    Returns:
        A dict with query_status and a mapping of malware name to
        printable name / aliases under "data".
    """
    return await _query({"query": "malware_list"})


@mcp.tool()
async def get_ioc_types() -> dict[str, Any]:
    """Get the list of supported IOC / threat types on ThreatFox.

    Returns:
        A dict with query_status and a mapping of type info under "data".
    """
    return await _query({"query": "types"})


@mcp.tool()
async def get_tag_list() -> dict[str, Any]:
    """Get the list of tags known to ThreatFox.

    Returns:
        A dict with query_status and a mapping of tag name to first_seen /
        last_seen / color under "data".
    """
    return await _query({"query": "tag_list"})


if __name__ == "__main__":
    mcp.run(transport="stdio")
