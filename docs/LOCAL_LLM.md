# Local LLM (Qwen2.5-Coder in Docker)

TraceLock can use a local model to help find the functions an advisory affects when the fix commit
alone does not say. The model runs in Docker through [Ollama](https://hub.docker.com/r/ollama/ollama).
Inference needs no Anthropic or OpenAI key, no native Ollama install, and nothing leaves your machine.
OSV and GitHub still need internet access in online mode.

```
OSV + GitHub fix commit
  -> deterministic extraction (fixdiff.py for Python, native.py for C / Rust)
  -> local Qwen proposes candidates, only where deterministic analysis leaves a gap
  -> deterministic verification (kb/verify.py): symbol exists in the pinned version, call path proven
  -> trusted knowledge base (VulnSpec) -> AST + call graph -> verdict engine
```

The model never sets a verdict. Its reply schema has no verdict field, and a reply that contains one is
rejected. Every candidate must pass the checks in `kb/verify.py` before it can become a target, and a
mapping with any unresolved gap can support REACHABLE but never NOT_REACHABLE.

## Setup

You need Docker Desktop (macOS/Windows) or Docker Engine with the Compose plugin (Linux).

```bash
docker compose up -d ollama                                   # start the model server
docker compose exec ollama ollama pull qwen2.5-coder:3b       # once: about 1.9 GB, kept in the ollama_data volume
docker compose exec ollama ollama list                        # check that it is there
docker compose exec ollama ollama run qwen2.5-coder:3b "Explain how Python C extensions expose functions to Python."
curl http://127.0.0.1:11434/api/tags                          # the API from the host
docker compose ps                                             # health
docker compose logs -f ollama                                 # logs
```

The backend never pulls the model and never needs `ollama run`. It loads the model on the first request.

## Connecting the backend

The settings are read in one place: `backend/tracelock/llm/settings.py`.

| Variable | Default | Meaning |
|---|---|---|
| `TRACELOCK_LLM_ENABLED` | `false` | turn LLM help on |
| `TRACELOCK_LLM_PROVIDER` | `ollama` | `ollama`, or `none`. `anthropic`/`openai` only when named here; a key alone never selects one |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | see below |
| `OLLAMA_MODEL` | `qwen2.5-coder:3b` | use `qwen2.5-coder:1.5b` on a tight machine (pull it first) |
| `OLLAMA_TIMEOUT_SECONDS` | `120` | per request |
| `OLLAMA_NUM_CTX` / `OLLAMA_NUM_PREDICT` | `4096` / `900` | context and output caps per request |
| `TRACELOCK_LLM_MAX_CONCURRENCY` | `1` | inference requests in flight |
| `TRACELOCK_LLM_MAX_CALLS_PER_SCAN` | `12` | after this, a scan stays deterministic |

Which URL to use depends on where FastAPI runs:

* **FastAPI on the host** (`uvicorn app.main:app --reload`, or the CLI):
  `OLLAMA_BASE_URL=http://127.0.0.1:11434`
  ```bash
  cd backend
  TRACELOCK_LLM_ENABLED=true OLLAMA_BASE_URL=http://127.0.0.1:11434 venv/bin/uvicorn app.main:app --port 5001
  TRACELOCK_LLM_ENABLED=true venv/bin/python -m tracelock.cli scan ../benchmark/real_flask_app --json out.json
  ```
* **FastAPI in Docker Compose** (`docker compose up -d`): `OLLAMA_BASE_URL=http://ollama:11434`, already set
  in `docker-compose.yml`. Inside a container `localhost` is the container itself, so it cannot reach Ollama.

`scan` results carry `stats.llm` (calls, cache hits, failures, latency) and, per finding,
`spec.discovery` (method, model, candidates suggested/verified/rejected, check results). The UI shows these
under "Function discovery".

## Stopping, restarting, keeping the model

```bash
docker compose restart ollama
docker compose stop ollama
docker compose down          # removes containers; the ollama_data volume and the model stay
```

Do not use `docker compose down -v` as a normal shutdown: `-v` deletes volumes, including `ollama_data`,
and the model would have to be downloaded again.

## Turning it off

Unset `TRACELOCK_LLM_ENABLED` (or set `TRACELOCK_LLM_PROVIDER=none`). Everything deterministic, including
the native C/Rust mapping and the unused-package rule, still runs. If Ollama is down or the model is
missing, the scan continues, prints one warning, and findings that needed the model stay UNCERTAIN.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot reach Ollama at http://127.0.0.1:11434` | `docker compose up -d ollama`; check `docker compose ps` |
| `model qwen2.5-coder:3b is not pulled` | `docker compose exec ollama ollama pull qwen2.5-coder:3b` |
| `did not answer within 120s` | first request loads the model (slow on CPU); raise `OLLAMA_TIMEOUT_SECONDS` or use the 1.5b model |
| container restarts / is killed | give Docker Desktop at least 4 GB memory, or use `qwen2.5-coder:1.5b` |
| API container cannot connect | it must use `http://ollama:11434`, not localhost |

## Performance on an 8 GB Apple Silicon Mac

Docker Desktop on macOS has no Metal GPU passthrough, so the container runs the model on the CPU. Expect
several seconds to a few tens of seconds per request. TraceLock keeps prompts under about 9,000 characters,
runs one request at a time, caps calls per scan, and caches every answer
(`.tracelock/cache/llm/discovery/`), so a second scan of the same project makes no inference calls.
Check memory with `docker stats tracelock-ollama`.

## Optional: NVIDIA GPU (Linux)

With the NVIDIA Container Toolkit installed, add to the `ollama` service in a local override file
(`docker-compose.override.yml`); do not use this on macOS:

```yaml
services:
  ollama:
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

## Security

Scanned repositories and downloaded packages are untrusted. Source goes to the model only inside an
`<evidence>` block that the system prompt marks as data, with obvious secrets redacted; no environment
values are ever included. The model gets no tools, no file system and no network. Its output is parsed
against a strict schema, and nothing it says is trusted until `kb/verify.py` has checked it against the
pinned source. The Ollama port is published on 127.0.0.1 only, and cloud features are off (`OLLAMA_NO_CLOUD=1`).
