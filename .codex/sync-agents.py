#!/usr/bin/env python3
"""Generate the Codex agent definitions from the Claude Code ones.

.claude/agents/<name>.md is the single source of truth for the usg-plat team
(the plat-workflow skill). This writes .codex/agents/<name>.toml with the same
name, description and instructions, so both tools run the same roles.

Codex has no per-agent tool list: the Claude Code `tools:` limits are carried
into the instructions instead, and are enforced only by the agent itself.

    python3 .codex/sync-agents.py          # regenerate
    python3 .codex/sync-agents.py --check  # exit 1 if any file is stale
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / ".claude" / "agents"
DST = ROOT / ".codex" / "agents"

WRITE_TOOLS = {"Edit", "Write", "NotebookEdit"}


def parse(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        sys.exit(f"{path}: no frontmatter")
    head, sep, body = text[4:].partition("\n---\n")
    if not sep:
        sys.exit(f"{path}: unterminated frontmatter")
    meta = {}
    for line in head.splitlines():
        key, colon, value = line.partition(":")
        if colon:
            meta[key.strip()] = value.strip()
    for key in ("name", "description"):
        if not meta.get(key):
            sys.exit(f"{path}: missing {key}")
    return meta, body.strip("\n")


def toml_basic(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(src, meta, body):
    tools = [t.strip() for t in meta.get("tools", "").split(",") if t.strip()]
    note = ""
    if tools:
        note = (
            "Tool limits (from the Claude Code definition, enforced by you under "
            f"Codex): {', '.join(tools)}."
        )
        if not WRITE_TOOLS & set(tools):
            note += " Do not create or modify any file."
        elif "Edit" not in tools:
            note += " Only write the report file your instructions name; do not edit source."
        note += "\n\n"
    instructions = note + body + "\n"
    if "'''" in instructions:
        sys.exit(f"{src}: contains ''' which a TOML literal string cannot hold")
    rel = src.relative_to(ROOT)
    return (
        f"# Generated from {rel} by .codex/sync-agents.py. Do not edit:\n"
        f"# change {rel} and run `make codex-agents`.\n"
        f"name = {toml_basic(meta['name'])}\n"
        f"description = {toml_basic(meta['description'])}\n"
        f"developer_instructions = '''\n{instructions}'''\n"
    )


def main():
    check = "--check" in sys.argv[1:]
    DST.mkdir(parents=True, exist_ok=True)
    want = {}
    for src in sorted(SRC.glob("*.md")):
        meta, body = parse(src)
        want[DST / f"{meta['name']}.toml"] = render(src, meta, body)
    stale = []
    for path, content in want.items():
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old != content:
            stale.append(path)
            if not check:
                path.write_text(content, encoding="utf-8")
    extra = [p for p in DST.glob("*.toml") if p not in want]
    for path in extra:
        stale.append(path)
        if not check:
            path.unlink()
    if check and stale:
        for path in stale:
            print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
        print("run `make codex-agents`", file=sys.stderr)
        return 1
    if not check:
        print(f"{len(want)} agents written to {DST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
