# Primary sources (consulted 2026-10-27)

- Docker build context and `.dockerignore` including per-Dockerfile precedence and negation: https://docs.docker.com/build/concepts/context/
- Docker build secrets and warning about ARG/ENV: https://docs.docker.com/build/building/secrets/
- Docker Build checks (upstream alternatives): https://docs.docker.com/reference/build-checks/secrets-used-in-arg-or-env/
- Agent Skills open spec: https://agentskills.io/specification

We do not claim this tool replaces Docker's official `patternmatcher`, BuildKit checks, container scanning, or secret scanners.
