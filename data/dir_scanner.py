import os
from typing import Optional

CODE_EXTENSIONS = {
    ".c", ".cpp", ".cxx", ".h", ".hpp",
    ".java",
    ".py",
    ".js", ".ts",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".swift",
    ".kt",
    ".scala",
    ".seed",
}


def scan_directory(
    dir_path: str,
    extensions: Optional[set[str]] = None,
    max_depth: int = 10,
) -> list[dict[str, str]]:
    if extensions is None:
        extensions = CODE_EXTENSIONS
    if not os.path.isdir(dir_path):
        raise NotADirectoryError(f"'{dir_path}' is not a valid directory")

    found: list[dict[str, str]] = []
    base = os.path.abspath(dir_path)

    for root, _dirs, files in os.walk(base):
        depth = root[len(base) + 1:].count(os.sep)
        if depth >= max_depth:
            continue
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except Exception:
                    continue
                rel_path = os.path.relpath(fpath, base)
                found.append({
                    "filepath": fpath,
                    "rel_path": rel_path,
                    "filename": fname,
                    "extension": ext,
                    "content": content,
                    "size": len(content),
                })

    found.sort(key=lambda x: x["rel_path"])
    return found
