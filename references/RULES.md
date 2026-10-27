# Docker context guard rules

| Rule | Severity | Finding | Suggested response |
|---|---|---|---|
| DC001 | High | Secret-looking ARG/ENV **key names** in Dockerfile | Use BuildKit `--secret` mounts; do not pass credentials through ARG/ENV |
| DC002 | Medium | Context-wide `COPY .` / `ADD .` | Narrow sources and enforce `.dockerignore` |
| DC003 | High | Broad context COPY without effective `.dockerignore` | Add reviewed ignore patterns |
| DC004 | Medium | `.git` directory potentially included when broad COPY used | Exclude `.git` |
| DC005 | High | Secret-looking filename included in the build context | Explicitly ignore it; verify with Docker's real matcher |

## Caveats

`DC005` checks only filenames, not values, and includes common key/certificate suffixes. `.env.example`/`.env.sample` are ignored as documented placeholders (not secret-validated). Rule matching implements an ordered subset of Docker patterns: `!` rules override earlier rules, `**/` and path patterns supported heuristically; Go `patternmatcher` is authoritative. For multiple Dockerfiles, `<Dockerfile>.dockerignore` overrides the context-root `.dockerignore`. The scanner deliberately skips symlinks and does not follow paths outside the supplied context. A clean result does not prove container security.
