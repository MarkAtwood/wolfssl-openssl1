# Project: wolfCrypt/OpenSSL Fork

## Agent Permissions

You are authorized to:
- Spawn subagents freely without asking for confirmation
- Write, read, and execute files anywhere under ./agents/
- Write, read, and execute files anywhere under ./shim/
- Patch files under ./openssl/ (except include/openssl/)
- Run build commands (make, cmake, configure scripts)
- Poll for output files in loops

You do not need to ask permission before:
- Creating new files
- Spawning a subagent
- Running the compiler or test suite
- Writing to any subdirectory of this project

## Progress Reporting

Every agent must write progress updates to its status file after each
step, not just at completion. Format:

echo "[$(date -u +%H:%M:%S)] step N: description" >> ./shim/audit/AGENTNAME_status.md

The orchestrator must update ./shim/audit/orchestrator_status.md after
every phase transition and after every subagent spawn.

## Subagent Behavior

When you spawn a subagent, pass it the full contents of the relevant
./agents/agent-NAME.md file as its prompt. Do not summarize or truncate it.

When polling for subagent completion, check for *_done.txt or *_error.md
files. If an error file appears, read it and surface the contents to the
user immediately.

## Project Layout

- ./openssl/     OpenSSL 1.1.1 source (do not touch include/openssl/)
- ./wolfssl/     wolfSSL source
- ./shim/        all generated output
- ./agents/      subagent prompt files (you write these)
```

## 3. First line of your orchestrator prompt (prompt level)

Add this block at the very top before anything else:
```
## Permissions and Operating Mode

You have explicit permission to:
- Spawn subagents using the Task tool without confirmation
- Write files to ./agents/, ./shim/, and ./openssl/ freely
- Execute shell commands including make, cmake, nm, diff, and compiler toolchains
- Poll filesystem in loops waiting for subagent output files

Do not hedge, do not ask for confirmation before spawning agents, do not
summarize agent prompts before passing them. Operate autonomously until
you hit an *_error.md file or exhaust all phases.
