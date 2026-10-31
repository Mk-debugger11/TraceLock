"""Fix-commit tier: map a GitHub fix commit's hunks to the functions they touch. OWNER: Vaibhav.

Scaffold status: STUB. `functions_from_fix` returns ([], [], None).

What to build (see BRIEF_VAIBHAV.md, task 4):
 1. From adv.fix_urls pick URLs matching github.com/<owner>/<repo>/commit/<sha>
    (and /pull/<n>: fetch https://github.com/<o>/<r>/pull/<n>.patch and read the sha from it).
 2. GET https://github.com/<o>/<r>/commit/<sha>.diff  -> unified diff text.
 3. For each file ending in .py: parse hunks `@@ -old_start,old_len +new_start,new_len @@`.
 4. Fetch the PRE-fix file: https://raw.githubusercontent.com/<o>/<r>/<sha>~1/<path> does NOT work;
    use https://api.github.com/repos/<o>/<r>/contents/<path>?ref=<sha>^  (URL-encode the caret as %5E)
    or git clone --depth 2 and `git show <sha>^:<path>`.
 5. ast.parse the pre-fix file; for every FunctionDef/AsyncFunctionDef (including methods, build
    qualnames Class.method) find the innermost one whose [lineno, end_lineno] overlaps the hunk's
    old line range. Do NOT trust the `@@ ... def foo` header text: in Python it often names the
    class or a previous function.
 6. Module name = path with .py stripped, '/' -> '.', with leading 'src/', 'lib/', '<repo>/' removed,
    and '/__init__' dropped. Result e.g. 'jinja2.filters.do_xmlattr'.
 7. Return (sorted unique qualnames, the hunk texts as evidence, the commit URL).
 8. Cache everything under .tracelock/cache/fixes/<sha>.json and also commit the seed CVEs'
    results into tracelock/data/fixes/ so --offline works.
"""
from __future__ import annotations

from typing import Optional

from ..models import Advisory, Dependency


def functions_from_fix(adv: Advisory, dep: Dependency) -> tuple[list[str], list[str], Optional[str]]:
    """Return (vulnerable function qualnames, evidence hunks, commit url). Stub: nothing yet."""
    return [], [], None
