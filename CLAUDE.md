# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

nullclaw is a minimal, fully autonomous AI assistant runtime written in Zig 0.15.2. It produces a single static binary (<1 MB ReleaseSmall, <5 MB peak RSS) with a vtable-driven plugin architecture for AI providers, messaging channels, tools, memory backends, and more.

## Build & Test Commands

```bash
zig build                              # Debug build
zig build -Doptimize=ReleaseSmall      # Release build
zig build test --summary all           # Run all 3,371+ tests (must pass with 0 leaks)
zig build run -- <args>                # Run with arguments
zig fmt src/                           # Format all source files
zig build -Dtarget=aarch64-linux-musl  # Cross-compile example
```

Build options: `-Dchannels=<list>` to select channels, `-Dengines=postgres` for PostgreSQL support, `-Dversion=<string>` for version override.

### Git Hooks

Activate once per clone: `git config core.hooksPath .githooks`

- **pre-commit**: runs `zig fmt --check src/` (blocks on unformatted code)
- **pre-push**: runs `zig build test --summary all` (blocks on failures/leaks)

## Architecture

**Everything is a vtable interface.** The codebase follows a strict pattern: define a vtable struct, implement it in concrete modules, register via factory functions. Extension points:

| Interface | Location | Purpose |
|-----------|----------|---------|
| `Provider` | `src/providers/root.zig` | AI model backends (Anthropic, OpenAI, Gemini, Ollama, 50+) |
| `Channel` | `src/channels/root.zig` | Messaging transports (Telegram, Discord, Slack, IRC, 17+) |
| `Tool` | `src/tools/root.zig` | Executable capabilities (shell, file ops, browser, 30+) |
| `Memory` | `src/memory/root.zig` | Storage backends (SQLite/FTS5, Markdown, Redis, PostgreSQL) |
| `RuntimeAdapter` | `src/runtime.zig` | Execution environments (native, Docker, WASM) |
| `Tunnel` | `src/tunnel.zig` | Remote access (Cloudflare, ngrok, Tailscale) |
| `Peripheral` | `src/peripherals.zig` | Hardware I/O (Arduino, RPi, STM32) |
| `Observer` | `src/observability.zig` | Observability hooks |

**Key modules:**
- `src/main.zig` — CLI entry point with 16+ commands
- `src/config.zig` — Config schema and loading (`~/.nullclaw/config.json`)
- `src/gateway.zig` — HTTP API server (REST, webhooks, rate limiting, pairing)
- `src/agent/root.zig` — Agent orchestration loop
- `src/agent/dispatcher.zig` — Message/command dispatch
- `src/security/` — Policy (deny-by-default), secrets (ChaCha20-Poly1305), pairing, sandbox backends (Landlock, Firejail, Bubblewrap, Docker), audit logging

**Dependency direction:** Concrete implementations depend inward on vtable interfaces and config. No cross-subsystem coupling (e.g., providers must not import channel internals).

## Zig 0.15.2 API Gotchas

These are **critical** — Zig 0.15 APIs differ from documentation for other versions:

- `std.io.getStdOut()` does NOT exist — use `std.fs.File.stdout()`
- HTTP: `std.http.Client.fetch()` with `std.Io.Writer.Allocating` for response body
- Processes: `std.process.Child.init(argv, allocator)`, `.Pipe` (capitalized)
- `ArrayListUnmanaged`: init with `.empty`, pass allocator to every method call
- SQLite: linked on the compile step, not the module (see `build.zig`)
- `ChaCha20Poly1305.decrypt`: use stack buffer then `allocator.dupe()` — heap-allocated output segfaults on macOS
- `SQLITE_TRANSIENT` in auto-translated C: use `SQLITE_STATIC` (null) instead

## Naming Conventions

- Functions/variables/fields/files: `snake_case`
- Types/structs/enums/unions: `PascalCase`
- Vtable implementers: `<Name>Provider`, `<Name>Channel`, `<Name>Tool`, etc.
- Factory keys: lowercase, user-facing (e.g., `"openai"`, `"telegram"`, `"shell"`)
- Tests: named by behavior (`subject_expected_behavior`)

## Testing Constraints

- All tests use `std.testing.allocator` — every allocation must be freed (zero-leak guarantee)
- `Config.load()` allocates — wrap in `ArenaAllocator` in tests
- Gate network calls with `if (builtin.is_test) return;`
- Gate process spawning with `if (builtin.is_test) return;`
- Tests must be deterministic and cross-platform (macOS, Linux, Windows)

## Adding New Components

**Provider:** Create `src/providers/<name>.zig` implementing `Provider.VTable`, register in `src/providers/root.zig`.

**Channel:** Create `src/channels/<name>.zig` implementing `Channel.VTable`, register in `src/channels/root.zig`.

**Tool:** Create `src/tools/<name>.zig` implementing `Tool.VTable`, register in `src/tools/root.zig`. Validate all inputs, return `ToolResult`, never panic.

All new vtable implementations follow the same pattern — read an existing implementation of the same type first.

## AGENTS.md

The `AGENTS.md` file in the repo root is the authoritative engineering protocol. It covers risk tiers, anti-patterns, change playbooks, and the full validation matrix. Read it before making non-trivial changes.
