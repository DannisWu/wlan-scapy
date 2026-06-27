# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and Hermes Agent when
working with code in this repository.

## Project Overview

Wi-Fi (WLAN) packet manipulation and automated testing using Scapy. This project
deals with crafting, sending, sniffing, and analyzing 802.11 frames programmatically
in Python, organized as:

```
src/
├── wlan/         802.11 frame builders, IEs, PHY rate sets, anomaly sequences
├── devices/      AP, STA, Sniffer, WiredPC device abstractions
├── connections/  SSH, Serial, Telnet connection management
├── transport/    Radio (injection) and base frame transport
├── traffic/      L3/L4 traffic builders + 802.11-encapsulated data frames
├── utils/        Config, pcap, sniffing utilities
└── cli/          Standalone CLI test runner (WifiMgmtSender pattern)
tests/scenarios/  pytest async integration tests by scenario category
```

## Development Environment

```bash
cd /home/wudan/wlan-scapy
source venv/bin/activate

# Run all tests (requires hardware/AP)
python3 -m pytest tests/ -v

# Run a scenario's tests
python3 -m pytest tests/scenarios/sta_association/ -v

# Run unit tests only (no hardware needed)
python3 -m pytest tests/wlan/ tests/traffic/ tests/utils/ -v

# CLI injection (requires monitor interface)
sudo python3 -m src.cli.run probe --iface wlan0mon --sta-count 10
```

## CodeGraph Integration

CodeGraph (colbymchenry/codegraph v0.9.9) is installed and indexed on this repo.
Query before coding: `codegraph callers <symbol>` / `codegraph impact <symbol>`.

---

# Karpathy-Inspired Development Standards

*Adapted from Andrej Karpathy's observations on LLM coding pitfalls
([multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills)).*

These four principles guide all code changes in this repository.

## 1. Think Before Coding

**Don't assume. Surface confusion. Present tradeoffs.**

Before implementing any test or module:

- **State assumptions explicitly.** If the test depends on AP firmware behavior,
  RF environment, or specific channel — say so.
- **If multiple protocol interpretations exist, present them.** 802.11 specs have
  ambiguities; don't silently pick one.
- **Push back when warranted.** If a user asks for a test that violates 802.11
  protocol semantics, say so and explain why.
- **Stop when confused.** If you don't understand what a fixture does or how a
  frame should be constructed, name what's unclear and ask.

*WLAN-specific example:*
```
[ASSUMPTION] This test assumes AP is on channel 6, 2.4GHz, with WPA2-PSK.
[ASSUMPTION] Monitor interface wlan0mon exists and supports injection.
[TRADEOFF] Using broadcast Probe Request vs targeted SSID: broadcast causes
           more air traffic but doesn't require knowing the exact SSID.
```

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

When writing WLAN automation:

- **One test function = one scenario.** Don't combine deauth flood and invalid
  rates into one test.
- **No abstractions for single-use code.** If only `test_truncated_frames.py`
  uses `_build_control_short()`, keep it in that file.
- **No "flexibility" that wasn't requested.** Don't add `--phy` parameter
  support to a test that only ever uses 802.11g.
- **No error handling for impossible scenarios.** A `RuntimeError` catch
  around Scapy's `sendp()` is noise unless you've seen it fail.
- **If 200 lines could be 50, rewrite it.** Many of the migrated RUN/scapy
  tests were compact (50-80 lines); match that density.

*Acid test:* Would a senior WLAN test engineer say this is overcomplicated?

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing test code or modules:

- **Don't "improve" adjacent code, comments, or formatting.** The frame builder
  you're not touching doesn't need a docstring upgrade right now.
- **Don't refactor things that aren't broken.** The `wifi_mgmt_common.py` style
  vs `src/wlan/frames.py` style — both work, pick one for new code but don't
  retrofit the other.
- **Match existing style in the file you're editing.** `build_auth_frame()`
  uses `_dot11_header()` pattern; follow that, not `build_probe_req()` pattern.
- **If you notice unrelated dead code, mention it — don't delete it.**
  The `src/cli/parser.py` may be unused; flag it, don't remove it.
- **For your own changes:** remove imports/variables/functions that YOUR changes
  made unused. The `from src.wlan.frames import build_reassoc_req_frame` should
  be purged if no code in that file uses it.

*The test:* Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

| Instead of... | Transform to... |
|---|---|
| "Add a deauth flood test" | "Write test_deauth_flood that sends 10 deauth frames and verifies all 10 appear in pcap" |
| "Fix the StaInjector.associate bug" | "Write a test that reproduces the sequence number bug, then fix it" |
| "Migrate test_sta_reassoc to pytest" | "Create test_reassoc.py that runs via pytest, verifies ReassoReq in pcap, and passes in < 5s" |

For multi-step tasks, state a brief plan with verification:

```
1. Add build_reassoc_req_frame() to frames.py      → verify: import succeeds, type checks pass
2. Create tests/scenarios/sta_roaming/test_reassoc.py  → verify: pytest collects it
3. Run test with codegraph callers to confirm no breakage → verify: 0 failures
```

*Strong success criteria let the agent loop independently.* Weak criteria
("make it work") require constant clarification.

---

## How to Know It's Working

Signs these standards are effective:

- **Diffs show only requested changes** — no unrelated "improvements" to
  adjacent frame builders.
- **No rewrites due to overcomplication** — test functions fit in 20-80 lines.
- **Clarifying questions come before implementation** — "Should this test
  expect Status Code 18 or a Deauth?" before writing the assert.
- **Clean, minimal PRs** — one scenario per PR, no drive-by refactoring.
