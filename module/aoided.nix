# pkgs/aoide/module/aoided.nix — the orchestrator daemon service.
#
# aoided is the central event bus and policy enforcer of the Aoide framework:
#
#   - Emits a neutral event stream consumed by thin per-agent adapters.
#   - Subscriptions are default-deny per event class (OSD flood → no agent run).
#   - Policy, lint, and the single audit log (aoide.auditLog) live here.
#   - Owns the user-gated rebuild pipeline (polkit pattern):
#       agent proposes → user admits → git records.
#   - Both the CLI door and the MCP door write to the same audit log;
#     there is no separate per-door log (concepts/Governance).
#
# Security boundary: forwarded notification text is untrusted input. Adapters
# must wrap it as data and never execute it as a command. This is enforced by
# the adapter pattern (modules/nucleus/melete-adapter.nix), not by aoided
# itself — but aoided's subscription-class gating is the structural backstop.
#
# The `aoide` binary (installed by pkgs/aoide, Agent B) ships both `aoide` (CLI)
# and `aoided` (daemon). We reference it via pkgs so eval stays clean even
# before the package is fully realised.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.aoide;
in

lib.mkIf config.aoide.enable {

  # ── Runtime directories ──────────────────────────────────────────────────
  # Two atomic JSON state trees (CONTRACTS.md §4), both created at runtime,
  # never committed, never imported by any module (checks.no-song-read):
  # `song/stage/` is rice/paint staging (livery.json, mode.json — lyra's
  # tree); `state/stage/` is CONDUCTING state (sessions.json/hooks.json/
  # projects.json/graph.json/pending.json/herald.json — command-defrag S1,
  # 2026-08-27). `state/stage/` nests under the already-0700 `state/` dir, so
  # its own 0755 grants nothing beyond the owner the parent doesn't already
  # gate — matching `song/stage/`'s own mode rather than inventing a second
  # convention for the same class of data.
  systemd.user.tmpfiles.rules = [
    "d ${config.aoide.root}/log        0700 - - -"
    "d ${config.aoide.root}/song/stage 0755 - - -"
    "d ${config.aoide.root}/state      0700 - - -"
    "d ${config.aoide.root}/state/stage 0755 - - -"
  ];

  # ── The terminal, for the interactive half ───────────────────────────────
  # See the unit's own `Environment` note below: `spawn --windowed` and
  # `resurrect` are ordinary commands an operator runs in a shell, and a
  # shell inherits this no more than a systemd unit does. One option, two
  # consumers.
  environment.sessionVariables =
    (lib.optionalAttrs (config.aoide.terminal != "") { AOIDE_TERMINAL = config.aoide.terminal; })
    // {
      # Non-default values only need to WORK; the defaults are chosen so
      # that unset == set-to-default already matches core's own code
      # default (L-C2, task #107) — exported anyway so an interactive shell
      # agrees with every unit above on where the runtime root/checkout
      # sit, the same "one option, two consumers" shape `AOIDE_TERMINAL`
      # already holds.
      AOIDE_ROOT = config.aoide.root;
      AOIDE_FLAKE_ROOT = config.aoide.checkout;
    };

  # ── aoided systemd user service ──────────────────────────────────────────
  systemd.user.services.aoided = {
    description = "Aoide orchestrator daemon — neutral event stream + policy + audit";

    # `aoide.sessionTarget` (options.nix) is the seam a paint-dependent
    # anchor enters through — this module may not read
    # `config.aoide.facets.quickshell.enable` directly (root AGENTS.md
    # house rule 5, no module reads another module). Default
    # `"default.target"`: headless, with linger on, the daemon and its
    # doors come up at boot and stay resident. A painting host (AoideOS,
    # `modules/nucleus/aoided.nix`) sets `aoide.sessionTarget` to
    # `"graphical-session.target"` instead, so the unit starts when the
    # compositor is up and PartOf ties its lifetime to that session —
    # anchoring to `default.target` there would leave no graphical-session
    # target for a manually started daemon, and PartOf would propagate an
    # immediate stop while BindsTo drags the a2a/mcp doors down with it.
    wantedBy = [ cfg.sessionTarget ];
    after = lib.optional (cfg.sessionTarget != "default.target") cfg.sessionTarget;
    partOf = lib.optional (cfg.sessionTarget != "default.target") cfg.sessionTarget;

    serviceConfig = {
      # The `aoide` package installs both the `aoide` CLI and the `aoided`
      # daemon binary. We reference it via pkgs so this evaluates cleanly
      # even when Agent B hasn't yet realised the package.
      ExecStart = "${pkgs.aoide}/bin/aoided";

      # aoided is the resident daemon (P-D2, docs/architecture/AOIDED.md):
      # `daemon::run_loop` binds its own control socket, spawns the accept
      # loop, and ticks forever — it never exits on its own, so Type=simple
      # is the correct declaration (an EARLIER skeleton build that exited
      # after one policy self-check needed oneshot+RemainAfterExit instead,
      # since a clean exit under Type=simple back then flipped the unit
      # inactive and BindsTo dragged the a2a/mcp doors down with it — found
      # live on osaka). Restart=on-failure covers a crash (a first-loop bug,
      # a bind failure) without masking one as permanently "active".
      Type = "simple";
      Restart = "on-failure";
      RestartSec = "5s";

      # Audit log path comes from the option contract (modules/nucleus/options.nix).
      # Passed as an environment variable so the daemon picks it up without a
      # secondary config file. The control socket and events feed need no
      # entry here — `daemon::socket_path`/`daemon::events_path` default to
      # `$XDG_RUNTIME_DIR/aoide/aoided.sock`/`events.jsonl` (a systemd user
      # unit already has `XDG_RUNTIME_DIR` set); `AOIDE_DAEMON_SOCKET`/
      # `AOIDE_DAEMON_EVENTS` are the override seam for a host that needs
      # something else, not something this unit has to set.
      #
      # `AOIDE_TERMINAL` rides here for the same reason the audit log does,
      # and is load-bearing rather than convenience: the boot auto-resume
      # sweep opens REAL terminals, and a systemd user unit inherits no
      # shell environment, so without this entry the sweep runs, selects its
      # carried sessions, and fails every windowed spawn with the taught
      # no-terminal error — resuming nothing while looking healthy. Omitted
      # entirely when `aoide.terminal` is empty, since the resolver reads
      # "set but blank" as a configured template and would answer with a
      # confusing parse instead of that taught error.
      Environment = [
        "AOIDE_AUDIT_LOG=${config.aoide.auditLog}"
        "AOIDE_USER=${config.aoide.user}"
        "AOIDE_ROOT=${config.aoide.root}"
        "AOIDE_FLAKE_ROOT=${config.aoide.checkout}"
      ]
      # Quoted as one assignment per systemd.exec(5)'s own `Environment=`
      # syntax (`Environment="VAR=word1 word2"`): the template carries
      # spaces (e.g. `kitty -e {cmd}`), and an unquoted assignment is
      # whitespace-split into separate tokens, silently dropping everything
      # after the first word as an invalid assignment.
      ++ lib.optional (config.aoide.terminal != "") ''"AOIDE_TERMINAL=${config.aoide.terminal}"'';
      # The interactive half of the same need: `spawn --windowed` and
      # `resurrect` are ordinary commands an operator runs in a shell,
      # and a shell has no more of this variable than the unit does. The unit
      # entry above and this export are the two consumers of one option; a
      # box configured for the daemon but not the shell would answer the
      # taught no-terminal error to the operator while resuming fine at boot.

      # Harden: no new privileges; keep the user session's dbus accessible.
      NoNewPrivileges = true;

      # Standard output goes to the journal for `journalctl --user -u aoided`.
      StandardOutput = "journal";
      StandardError = "journal";
    };

    # The control socket, events feed, and registry dispatch are live
    # (P-D2/P-D4, docs/architecture/AOIDED.md) — `ping`/`subscribe` today,
    # `dispatch` (the fourth door) once P-D4 lands. Producers onto the
    # events feed (the secrets-feed mirror, the #69 hand-edit watcher) are
    # P-D3, not yet wired into the tick loop.
  };
}
