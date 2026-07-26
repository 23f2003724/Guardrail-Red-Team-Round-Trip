import os
import urllib.parse


# -------------------------
# PATH CANONICALIZATION
# -------------------------
def canonicalize_path(path: str) -> str:
    """
    Normalize user-supplied paths to prevent:
    - ../ traversal
    - encoded traversal (%2e%2e)
    - symlink escapes
    - env / ~ tricks
    """

    # Decode URL-encoded sequences
    path = urllib.parse.unquote(path)

    # Expand environment variables ($HOME, etc.)
    path = os.path.expandvars(path)

    # Expand user home (~)
    path = os.path.expanduser(path)

    # Resolve symlinks + normalize path
    path = os.path.realpath(path)

    return path


# -------------------------
# SAFE PATH JOIN
# -------------------------
def safe_join(base: str, user_path: str) -> str:
    """
    Safely join base path + user path
    then canonicalize the result.
    """
    joined = os.path.join(base, user_path)
    return canonicalize_path(joined)


# -------------------------
# IS SUBPATH CHECK
# -------------------------
def is_subpath(path: str, root: str) -> bool:
    """
    Check if 'path' is inside 'root' directory.
    Prevents escaping via traversal or symlinks.
    """
    try:
        path = canonicalize_path(path)
        root = canonicalize_path(root)

        return path.startswith(root + os.sep) or path == root
    except:
        return False


# -------------------------
# OPTIONAL: DEBUG HELPER
# -------------------------
def debug_path_info(path: str) -> dict:
    """
    Useful for testing / debugging attacks
    (DO NOT expose in production API)
    """
    try:
        return {
            "original": path,
            "decoded": urllib.parse.unquote(path),
            "realpath": os.path.realpath(path),
            "exists": os.path.exists(path)
        }
    except Exception as e:
        return {"error": str(e)}