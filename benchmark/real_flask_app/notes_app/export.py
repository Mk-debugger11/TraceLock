import csv

from tqdm import tqdm


def export_notes(users, path):
    """Write one row per user with their note count (CLI: flask export-notes)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["username", "notes"])
        for username, record in tqdm(sorted(users.items()), desc="exporting", unit="user"):
            writer.writerow([username, len(record["notes"])])
    return path
