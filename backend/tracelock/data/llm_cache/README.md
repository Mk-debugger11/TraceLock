# LLM proposal cache

One JSON file per advisory id, written by `tracelock.kb.llm`: the raw model reply, the parsed
`entry_api` proposals, and which of them passed `symbol_exists` against that exact package version
(`verified`, `verified_version`, `rejected`). `kb.resolve()` reads this before calling any model and,
offline without the package source, reuses only `verified` names for the same version.

Fill it for the seed advisories (needs `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, or `TRACELOCK_LLM=ollama`):

    cd backend && python -m tracelock.kb.llm --seed            # all curated advisories
    cd backend && python -m tracelock.kb.llm --seed CVE-2024-47081

The seed run downloads each pinned wheel to `.tracelock/cache/src/` (unzipped, never executed) and
prints how many LLM proposals overlap the hand-curated `entry_api` (the accuracy number for the pitch).
Commit the resulting `*.json` files so the demo never waits on the network.
