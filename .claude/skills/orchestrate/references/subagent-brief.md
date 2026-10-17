# Subagent brief template

A subagent starts with no memory of the conversation. Everything it needs goes in the brief, and everything it should not do is said out loud. A tight brief is the main lever for speed: vague briefs make subagents research, re-read and over-verify.

```text
<One line: what to produce, for which repo or path.>

## Context (facts, so you don't have to look them up)
- Repo: <absolute path>. Purpose: <one line>.
- Already decided: <decisions, versions, names, ports>.
- Read first: <the 2-5 files that matter>. Style reference: <file to imitate>.
- Tools: <where they live, PATH or module path setup>.

## Your files
- Write: <exact paths>.
- Do not touch: <paths other agents or the main thread own>.

## Requirements
1. <testable requirement>
2. ...

## Verify (bounded)
- Run: <exact commands>. They must report <expected result>.
- Stop when they pass. Do not pull extra images, try alternatives or research beyond this.
- If a check exposes a real bug outside your files, make the smallest fix and report it.

## Rules
- Do NOT commit, push, or create remote resources.
- No new dependencies unless a requirement needs one; say why.

## Report back (at most <N> lines)
- What changed (paths), the verification results with numbers, anything not verified.
```

## Model and effort cheat sheet

| Brief type | model | effort |
|---|---|---|
| Lookup or search only | haiku | low |
| Exact edits listed in the brief | sonnet | low |
| Build from a clear spec plus a reference file | sonnet | medium |
| Needs judgment across files, or debugging | opus | high |
| Design or a subtle correctness problem | opus | xhigh (rare) |
