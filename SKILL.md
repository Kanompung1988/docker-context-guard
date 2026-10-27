---
name: docker-context-guard
description: Review Dockerfile build context for accidental inclusion of secret-looking filenames, ineffective .dockerignore exclusions, broad COPY or ADD, and sensitive ARG/ENV variable names. Use during Docker image build PR reviews and container release preparation, with file/line guidance. Fully offline read-only static heuristics; never opens potential secret files or runs docker builds.
license: MIT
compatibility: Python 3.10+ standard library; local build context and Dockerfile, no Docker daemon, credentials, or network required.
metadata:
  author: AREAZERO Skill Lab
  version: "1.0.0"
---

# Docker build context guard

## Trigger / non-trigger
Use to inspect a local Docker image build context for accidental sensitive files or risky Dockerfile instructions, especially during CI/CD rollout. Do **not** use for runtime container scanning, complete Dockerfile validation, software composition analysis, or a guarantee that built images contain no secrets.

## Procedure
1. Identify Docker build context root and Dockerfile(s). Avoid showing or opening sensitive file values; this scanner only looks at filenames and Dockerfile/ignore instructions.
2. Run `python scripts/audit.py /path/to/context --format markdown --fail-on high`. For a single Dockerfile, pass its path; when `docker build -f subdir/file` uses a different context, pass the actual context root and interpret source paths accordingly.
3. Review findings `DC001–DC005`, explaining whether broad COPY and `.dockerignore` ordering expose `.env*`, key material or `.git`; see [rules](references/RULES.md).
4. Verify `.dockerignore` semantics manually for patterns outside the documented supported subset: the built-in Python glob approximation does **not** implement Docker's full Go patternmatcher.
5. Do not print file contents, tokens or Dockerfile ENV values. Suggest `RUN --mount=type=secret` rather than `ARG`/`ENV` for build-time secrets.
6. Re-run locally and include command, exact findings, limitations and regression tests in review. Exit codes: `0` below threshold, `2` findings above threshold, `1` malformed/unreadable input.

## Reproducible examples
`python scripts/audit.py examples/unsafe --format json --fail-on none` shows synthetic metadata, including `.env.production`, `.git`, `ARG NPM_TOKEN`, broad COPY; `python scripts/audit.py examples/safe --format json --fail-on high` yields zero findings. Run `python -m unittest discover -s tests -v` for deterministic local QA.

## Safety and limitations
No network, Docker daemon, shell execution, or secret file value reads. Only filename metadata and explicitly identified Dockerfiles and ignore files are opened. Dockerfile parser and `.dockerignore` matching are deliberately conservative approximations, not Docker BuildKit conformance; build context may differ with named/remote contexts, Dockerfile location, symlinks, stage copies, `RUN` steps or builder versions. Uses file/path caps and skips symlinks rather than following them; a clean scan is not evidence of container security. Refer to [rules](references/RULES.md) and [Docker docs](references/SOURCES.md).
