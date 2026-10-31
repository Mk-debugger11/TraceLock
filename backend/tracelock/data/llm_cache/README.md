# LLM proposal cache

One JSON file per advisory id, written by `tracelock.kb.llm`: the raw model reply, the parsed
`entry_api` proposals, and which of them passed `symbol_exists` against that exact package version
(`verified`, `verified_version`, `rejected`). `kb.resolve()` reads this before calling any model and,
offline without the package source, reuses only `verified` names for the same version.

Fill it with a local open-weight model (nothing leaves the machine):

    brew install ollama && ollama serve &          # once
    ollama pull qwen2.5-coder:7b                   # ~4.7 GB; llama3.1:8b also works
    export TRACELOCK_LLM=ollama                    # TRACELOCK_LLM_MODEL overrides the model

or any OpenAI-compatible server hosting open models (`OPENAI_BASE_URL=https://api.groq.com/openai/v1`,
`TRACELOCK_LLM_MODEL=llama-3.3-70b-versatile`, `OPENAI_API_KEY=...`), then:

    cd backend && python -m tracelock.kb.llm --seed            # all curated advisories
    cd backend && python -m tracelock.kb.llm --seed CVE-2024-47081
    cd backend && python -m tracelock.kb.llm --seed --fixture ../benchmark/real_flask_app   # all 108 advisories

The seed run downloads each pinned wheel to `.tracelock/cache/src/` (unzipped, never executed) and
prints how many LLM proposals overlap the hand-curated `entry_api` (the accuracy number for the pitch).
Commit the resulting `*.json` files so the demo never waits on the network.
