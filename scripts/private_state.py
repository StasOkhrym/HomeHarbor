"""Shared validation for existing private file sets; never rotates partial state."""


def complete(paths, label):
    present = [p.exists() for p in paths]
    if any(present) and not all(present):
        raise ValueError(f"{label} incomplete; restore the complete existing set")

    for path in paths:
        if path.is_symlink():
            raise ValueError(f"{label}: symlink is not supported: {path.name}")
        if path.exists() and not path.read_bytes():
            raise ValueError(f"{label}: {path.name} is empty; restore it")

    return all(present)
