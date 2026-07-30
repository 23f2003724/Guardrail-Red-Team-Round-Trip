import os
import urllib.parse


def canonicalize_path(path: str, root: str) -> str:
    if "\x00" in path:
        raise ValueError("NUL byte in path")

    if not os.path.isabs(path):
        path = os.path.join(root, path)

    return os.path.realpath(os.path.abspath(path))


def is_subpath(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve_safe_path(path: str, root: str) -> str | None:
    try:
        root = os.path.realpath(os.path.abspath(root))
        raw_path = canonicalize_path(path, root)
        decoded_path = canonicalize_path(urllib.parse.unquote(path), root)
    except (TypeError, ValueError):
        return None

    if is_subpath(raw_path, root) and is_subpath(decoded_path, root):
        return raw_path

    return None
