# LLM proposal cache

One JSON file per advisory id, written by `tracelock.kb.llm`: the raw model reply, the parsed
`entry_api` proposals, and which of them passed `symbol_exists` against that exact package version
(`verified`, `verified_version`, `rejected`). `kb.resolve()` reads this before calling any model and,
offline without the package source, reuses only `verified` names for the same version.

Fill it with a local open-weight model (nothing leaves the machine), running in Docker:

    docker compose up -d ollama
    docker compose exec ollama ollama pull qwen2.5-coder:3b
    export TRACELOCK_LLM_ENABLED=true              # OLLAMA_MODEL overrides the model (e.g. qwen2.5-coder:7b)

or any OpenAI-compatible server hosting open models (`TRACELOCK_LLM_PROVIDER=openai`,
`OPENAI_BASE_URL=https://api.groq.com/openai/v1`, `TRACELOCK_LLM_MODEL=llama-3.3-70b-versatile`,
`OPENAI_API_KEY=...`), then:

    cd backend && python -m tracelock.kb.llm --seed            # all curated advisories
    cd backend && python -m tracelock.kb.llm --seed CVE-2024-47081
    cd backend && python -m tracelock.kb.llm --seed --fixture ../benchmark/real_flask_app   # all 108 advisories

The seed run downloads each pinned wheel to `.tracelock/cache/src/` (unzipped, never executed) and
prints how many LLM proposals overlap the hand-curated `entry_api` (the accuracy number for the pitch).
Commit the resulting `*.json` files so the demo never waits on the network.

Function-discovery answers (native mappings, pinned equivalents) are cached separately in
`.tracelock/cache/llm/discovery/<key>.json`, keyed by package, version, advisory, fix commit, source hash,
model and prompt schema version; `discovery/` here may hold committed copies for offline demos.
