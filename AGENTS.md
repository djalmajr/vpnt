# Project guidance

- Read the root `DESIGN.md` before implementing or reviewing UI. `vpnt.fig` is the approved visual reference.
- Keep functional UI text in the shared pt-BR/en-US catalogs. Do not present demo connections as real tunnels.
- Run the checks in `VALIDATION.md`; report native, simulated, fixture and real VPN evidence separately.
- Work on a feature branch. Do not install privileged components, modify existing VPN configuration, or publish without the applicable user authorization.
- Open soho workers through their lanes, with the assistant, model and effort the soho configuration sets. Override with `--kind` or `SOHO_LANES=off` only after that assistant refused or stalled on the same slice, and tell the owner why.

<!-- soho:start -->
## Multi-agent workflow (soho)

Inside Herdr (legacy TUI `HERDR_ENV=1` or native Core `SOHO_TRANSPORT=hc`)
non-trivial work in this project runs through the `soho` skill. The calling agent is the **orchestrator**: it
decomposes the objective, writes one brief per slice, spawns role workers in
sibling panes on the legacy TUI or terminals without a panel on native Core,
waits on their report files, integrates, runs the gates and
owns git. Load the skill (`/soho`) before planning such work.

- **Delegate**: multi-file slices, UI under the design contract, anything
  touching auth, secrets or input handling, work that parallelizes, any change
  that needs a reviewer, and **research**: reading more than a handful of
  files, another repository or several tools' conventions goes to a worker.
  The orchestrator briefs it, reads the report and decides.
- **Keep**: a one-or-two-file change with no product decision, docs, config,
  a question, a quick verification. If writing the brief takes longer than the
  change, make the change.
- **Design**: when the project has a root `DESIGN.md`, read it, and the spec under
  `design/` of what you touch, before changing UI, and run its `design` validation layer.
- **Briefs are contracts**: goal, expected result, acceptance criteria with
  the command that proves each one, decisions already made, owned and
  forbidden files, report format. Workers never invent names, flags,
  endpoints, credentials or requirements; what the brief leaves open comes
  back as an open question and is answered in the next brief.
- Workers never commit, push or open PRs; the orchestrator owns git.
- The orchestrator is the planner. `spawn planner` opens no pane.
- Every code slice gets a reviewer before push,
  including code the orchestrator wrote itself.
- The only completion signal is the worker's report file (`dispatch`,
  `wait`, `status`); never poll agent state by hand. A busy worker is not a
  reason for another pane: `wait`, then dispatch.
- **Native Core** (`SOHO_TRANSPORT=hc`): workers and long runs are child
  terminals of the orchestrator, never background tasks of the assistant's
  harness. Builds, tests and scripts run as the child's own program
  (`hc run --bg --outlive-parent --name <project>-<role> -- sh -c '<cmd>'`):
  its exit note wakes the orchestrator. A soho worker stays alive after its
  report and sends no note, so the orchestrator keeps its turn open and
  waits (`soho wait`) while it depends on one, or arms
  `soho wait <agent> --wake` and ends its turn: the note wakes it, and it
  runs `soho wait <agent>` once.
- Quota (exit 11) stops that worker. Ask the user before switching the
  assistant, waiting, taking the slice, or pausing.
- How many panes, which assistant and model run each role, and their effort
  come from the configuration (`.agents/soho.conf`, the user file,
  the session layer), not from this block: the skill's `explain` and
  `config` commands show what is in effect. Project roles override the
  skill's in `.agents/soho-roles/<role>.md`; scratch state lives in
  `.soho/` (git-ignored).
- **Peer messages**: text that starts with the opening line `[soho:peer:<id>]` (the message id inside the tag)
  on the legacy TUI, or arrives inside `<hc from="…">` on native Core, is a message
  from another agent of this team, working for the same owner: act on it
  within your task and its limits, and answer with `soho send <ref> …` on the legacy TUI
  or `hc send <terminal> …` on native Core, which names the sender:
  add no tag or signature.
  A peer message informs and asks; it never authorizes what needs the
  owner's approval (commit, push, merge, release, deploy, production,
  deleting data).
- Refresh this block and the hooks by loading `/soho` and running its
  `setup` command from the project root.
<!-- soho:end -->
