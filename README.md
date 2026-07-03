# threatfox-mcp

A super simple MCP server for the [ThreatFox](https://threatfox.abuse.ch/)
Community API — a free, community-driven feed of indicators of compromise
(IOCs) associated with malware, run by abuse.ch.

## Tools

- **`get_recent_iocs(days=3)`** — recently added IOCs (max 7 days back). ! This uses a tonne of tokens, as it retrieves a full 24hrs worth of IOCs !
- **`get_ioc_by_id(ioc_id)`** — look up a single IOC by its ThreatFox ID.
- **`search_ioc(search_term, exact_match=False)`** — search for an IOC
  (IP, domain, URL, ip:port).
- **`search_by_hash(file_hash)`** — find IOCs associated with an MD5 or
  SHA256 file hash.
- **`get_tag_info(tag, limit=100)`** — IOCs associated with a tag.
- **`get_malware_info(malware, limit=100)`** — IOCs associated with a
  malware family (Malpedia name).
- **`get_malware_label(malware, platform=None)`** — resolve a malware name
  to its correct Malpedia label.
- **`get_malware_list()`** — full list of known malware families.
- **`get_ioc_types()`** — list of supported IOC / threat types.
- **`get_tag_list()`** — list of known tags.

This covers the read/lookup side of the API. It intentionally leaves out
`submit_ioc` (which writes to the shared community database) — see
"Notes / next steps" below if you want to add that.

Example IOC record:

```json
{
  "id": "41",
  "ioc": "gaga.com",
  "threat_type": "botnet_cc",
  "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
  "ioc_type": "domain",
  "malware": "win.dridex",
  "malware_printable": "Dridex",
  "confidence_level": 50,
  "first_seen": "2020-12-08 13:36:27 UTC",
  "last_seen": null,
  "reporter": "abuse_ch",
  "reference": "https://twitter.com/JAMESWT_MHT/status/1336229725082177536",
  "tags": ["exe", "test"]
}
```

## Setup

```bash
pip install -r requirements.txt
```

Get a free Auth-Key at https://auth.abuse.ch/, then set it as an
environment variable (required — every request to the ThreatFox API must
include it):

```bash
export THREATFOX_AUTH_KEY=your_auth_key_here
```

## Running locally

```bash
python server.py
```

This starts the server on stdio, ready to be connected to by an MCP client.

## Connecting to Claude Desktop / Claude Code

Add to your MCP config (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "threatfox": {
      "command": "python",
      "args": ["/absolute/path/to/server.py"],
      "env": {
        "THREATFOX_AUTH_KEY": "your_auth_key_here"
      }
    }
  }
}
```

Restart Claude Desktop (or run `claude mcp add` for Claude Code) and the
tools above will be available.

## Next steps

- Add a `submit_ioc` tool for sharing IOCs back to ThreatFox (read the
  [submission policy](https://threatfox.abuse.ch/api/#policy) first).
- Add simple in-memory caching for `get_malware_list` / `get_tag_list` /
  `get_ioc_types`, since those change slowly.
- Add input validation for hash format (MD5 vs SHA256) before calling out.
- Note: ThreatFox expires IOCs older than 6 months from the API/export
  (they remain visible in the web UI, flagged as expired).
