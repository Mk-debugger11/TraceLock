import os
import subprocess
from typing import List

from app.schemas.scan import normalize_repository_url


def list_branches(repo_url: str) -> List[str]:
    """List a public GitHub repo's branches via `git ls-remote` (no API rate limits).

    Raises ValueError for a bad URL or an inaccessible repo, and TimeoutError if git hangs.
    """
    repo_url = repo_url.strip()
    if not repo_url.startswith(("http://", "https://")):
        repo_url = f"https://github.com/{repo_url}"  # accept "owner/repo"
    repo_url = normalize_repository_url(repo_url)

    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", repo_url],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},  # fail instead of asking for credentials
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError("Timed out trying to reach repository.") from None
    if result.returncode != 0:
        raise ValueError("Could not access repository. Please ensure the URL is correct and public.")

    return [line.split("refs/heads/", 1)[1] for line in result.stdout.splitlines() if "refs/heads/" in line]
