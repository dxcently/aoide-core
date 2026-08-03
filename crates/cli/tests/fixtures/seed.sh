#!/usr/bin/env bash
# seed.sh — write a plausible stage tree for driving `aoide conductor` without a live
# desktop. The whole conductor honours $AOIDE_STAGE_DIR / $AOIDE_AUDIT_LOG, so a
# throwaway tempdir is a full rig.
#
#   export AOIDE_STAGE_DIR=$(mktemp -d) AOIDE_AUDIT_LOG=$AOIDE_STAGE_DIR/log
#   pkgs/aoide/tests/fixtures/seed.sh "$AOIDE_STAGE_DIR"
#   aoide conductor
#
# Arg 1: the stage dir to seed (default: $AOIDE_STAGE_DIR, else ./stage).
set -euo pipefail

STAGE="${1:-${AOIDE_STAGE_DIR:-./stage}}"
mkdir -p "$STAGE"

cat > "$STAGE/projects.json" <<'JSON'
{
  "schemaVersion": "0",
  "projects": [
    { "name": "aoide", "path": "/home/khoa/Aoide" },
    { "name": "wiki",  "path": "/home/khoa/Aoide-Wiki" }
  ]
}
JSON

cat > "$STAGE/sessions.json" <<'JSON'
{
  "schemaVersion": "0",
  "sessions": [
    { "sessionId": "root-1", "agent": "claude", "windowAddress": "0xaaaa01",
      "cwd": "/home/khoa/Aoide", "state": "running", "startedAt": "2026-07-26T09:00:00Z",
      "tags": ["orchestrator", "opus"] },
    { "sessionId": "child-a", "agent": "claude", "windowAddress": "0xaaaa02",
      "cwd": "/home/khoa/Aoide/pkgs", "state": "idle", "startedAt": "2026-07-26T09:05:00Z",
      "parentSessionId": "root-1" },
    { "sessionId": "wiki-1", "agent": "claude", "windowAddress": "0xbbbb01",
      "cwd": "/home/khoa/Aoide-Wiki", "state": "done", "startedAt": "2026-07-26T08:30:00Z" },
    { "sessionId": "loose-1", "agent": "claude", "windowAddress": "0xcccc01",
      "cwd": "/tmp/scratch", "state": "idle", "startedAt": "2026-07-26T09:10:00Z" }
  ]
}
JSON

cat > "$STAGE/hooks.json" <<'JSON'
{
  "schemaVersion": "0",
  "hooks": [
    { "sessionId": "root-1", "phase": "PreToolUse", "updatedAt": "2026-07-26T09:12:00Z" },
    { "sessionId": "wiki-1", "phase": "Stop",       "updatedAt": "2026-07-26T08:59:00Z" }
  ]
}
JSON

cat > "$STAGE/drachma.json" <<'JSON'
{
  "schemaVersion": "0",
  "palette": { "bg": "#1e1e2e", "fg": "#cdd6f4", "accent": "#89b4fa", "urgent": "#f38ba8" }
}
JSON

# Seed a couple of audit lines so the LOG panel has content on first paint.
LOG="${AOIDE_AUDIT_LOG:-$STAGE/log}"
mkdir -p "$(dirname "$LOG")"
cat > "$LOG" <<'JSON'
{"ts":1753520400,"door":"cli","class":"audit","command":"graph.view","status":"ok","message":"6 node(s), 2 edge(s)"}
{"ts":1753520460,"door":"daemon","class":"audit","command":"shellbridge","status":"started","message":"shellbridge skeleton online; stage files seeded"}
{"ts":1753520520,"door":"cli","class":"audit","command":"graph.emit","status":"ok","message":"staged graph.json (6 node(s), 2 edge(s))"}
{"ts":1753520580,"door":"cli","class":"audit","command":"rice.gen","status":"not-implemented","message":"walking-skeleton stub"}
JSON

echo "seeded stage tree at: $STAGE"
echo "  audit log: $LOG"
