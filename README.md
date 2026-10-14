# AgentMoat

**A moat around your AI coding agent.**

Your AI agent reads GitHub issues, PR titles, web pages and docs — all attacker-controllable text. A single crafted issue title has already caused a real npm supply-chain compromise ([Clinejection, Feb 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-github-action-prompt-injection/)) and stolen live CI credentials from three major agents ([Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)).

**You cannot stop the injection from reaching the model. You can stop it from mattering.**

AgentMoat sits at the one boundary that actually holds — the **tool-call boundary** — and gives every command your agent tries to run a verdict: **allow**, **confirm**, or **block**, with a full audit trail of everything it stopped.

```
   issue/PR/web content          the agent reads it, the injection          AgentMoat
   ────────────────────▶  ────▶  turns into a tool call  ─────────────▶  ┌─────────┐
   (attacker-controlled)         (unavoidable)                          │ verdict │
                                                                       allow ─ ─ ▶ runs
                                                                       confirm ─ ▶ you decide
                                                                       block ─ ─ ▶ dead + logged
```

---

## Why this exists

Every high-profile agent attack of 2025–2026 shares one structure: untrusted text reaches the model, the model is *persuaded*, and the agent runs the attacker's command with your credentials. The defenses shipped by the vendors — input filters, model-level guardrails, runtime layer after runtime layer — keep getting bypassed, because the input *has* to be read for the agent to work.

The security community's answer (Microsoft's Semantic Kernel RCE write-up, the 2026 SoK paper, the GitInject study) is converging on the same point: **model-level defenses lose; the tool-execution boundary is where a defense holds.** Nobody had shipped the thing that does it in a form a normal person installs in one command. That's the gap AgentMoat fills.

## What it does

- **Three verdicts, zero config.** Sensible defaults out of the box: reads inside your project run silently, irreversible and system-level actions ask you first, credential exfiltration dies.
- **Blocks the real attack patterns.** `/proc/self/environ` reads, `printenv GITHUB_TOKEN`, `cat ~/.ssh/*`, pipe-to-shell installs, force-pushes, package installs that run dependency scripts — the exact primitives from Clinejection, Comment-and-Control and AIShellJack.
- **Detects injection signatures and escalates.** Instruction overrides (`ignore all previous instructions`), hidden HTML-comment payloads, fake "SYSTEM PROMPT" blocks, base64+pipe stagers, token-exfil markers — found in the command or its context, they push the verdict one tier up.
- **Audits everything.** Every verdict lands in `~/.agentmoat/audit.jsonl` (credentials auto-redacted). `agentmoat report` shows what your agent tried to do and what stopped it.
- **Zero dependencies.** Pure Node ≥ 18. No API keys, no LLM calls, no daemon, no network. Offline forever.
- **Your policy wins.** First-match-wins YAML-ish rules in `~/.agentmoat/policy.json` (`agentmoat init` writes a copy). Override any verdict for your workflow.

## Install

```bash
npm install -g agentmoat
```

*(until published: clone the repo and run it from there)*

## Quick start

**Claude Code** — official `PreToolUse` hook, full support:

```bash
agentmoat hook claude-code      # installs into ~/.claude/settings.json
agentmoat hook claude-code --remove
```

From then on, every `Bash`, `Write`, `Edit` call Claude makes goes through the moat. A blocked call dies with the reason shown to the agent, so it can course-correct; a confirm call surfaces to you.

**Any other agent** (Codex CLI, Gemini CLI, custom harnesses) — wrap its shell:

```bash
moat-shell git push --force origin main
# moat-shell: held for confirmation by agentmoat — history rewrite / force push
```

Point your agent's bash tool at `moat-shell` (or alias `bash=moat-shell` in the agent's environment) and it inherits the same verdicts.

## Try it in 30 seconds

```bash
agentmoat test                    # run the built-in 12-case attack corpus
agentmoat check --command "cat /proc/self/environ"
# verdict: block — reading process environment is a credential-exfiltration primitive
agentmoat check --command "ls src/"
# verdict: allow
agentmoat report                  # the audit trail
```

## How it decides

Three layers, evaluated per tool call:

1. **Policy rules** (first match wins): each rule matches a tool + command pattern and returns `allow` | `confirm` | `block`. Default policy ships with 13 rules covering credential access, exfiltration routes, irreversible operations and supply-chain entry points.
2. **Injection signatures**: 5 signature detectors scan the command and its context. Any hit escalates the verdict one tier (`allow→confirm`, `confirm→block`). Escalation never de-escalates.
3. **Audit**: every call, matched rule, signature hit and verdict is appended (redacted) to the audit log — your post-incident record and your daily "what did my agent try" report.

Exit codes for scripts and CI: `0` allow · `10` confirm · `20` block.

## What it is not

- Not a sandbox. It doesn't contain the process; it gates the calls.
- Not a prompt firewall. It doesn't try to sanitize inputs (that race is lost; see above).
- Not a panacea. A sufficiently novel attack pattern may need a new rule — that's what versioned policies and audit trails are for.
- Not a replacement for your existing approvals UI. It's the policy layer under it.

## Threat model & honest limits

AgentMoat assumes the model may already be compromised by injected content, and defends the boundary that remains: execution. Limits, stated plainly:

- Pattern rules can be evaded by a tailored, novel command. The audit trail is the safety net: you see what ran and can add a rule in one line.
- The wrapper (`moat-shell`) sees one command line; it cannot see intent.
- Claude Code's hook receives the tool input, not the full conversation context — signature escalation relies on what's in the command. (Hooks that receive richer context are on the roadmap.)

## Roadmap

- [ ] Codex CLI / Gemini CLI native adapters (their approval-hook APIs)
- [ ] GitHub Action wrapper: gate `claude-code-action` and Copilot Agent workflows (env redaction + tool gating for CI)
- [ ] Context channel: feed conversation context to signature detection (richer taint signal)
- [ ] `agentmoat explain`: replay any audit event and print the matched rule + why
- [ ] Policy packs (strict / balanced / paranoid) selectable at init

## Contributing

PRs welcome — new detection rules with a corpus case are the highest-value contribution: add the rule, add the attack line to `bin/moat.js`'s `ATTACKS`, `npm test` must stay green. One rule, one test, one PR.

## License

MIT — see [LICENSE](LICENSE).
