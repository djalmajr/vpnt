"""Build inputs the SDK adapter adds to every isolated Rust gate copy.

The helper is deliberately small and explicit. Call ``source_hashes(ROOT)``
before copying and ``copy_into(ROOT, copy)`` before the first baseline: a copy
without ``build.rs`` or ``native/`` can silently compile a different crate.
"""
import hashlib
from pathlib import Path
import shutil

BUILD = "build.rs"
NATIVE = "native"
HELPER = Path(__file__).resolve()


def _key(root, path):
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def source_files(root):
    """Return build.rs, every regular file under native/, and this helper.

    Missing or empty native inputs raise before a caller creates or copies a
    destination. Symlinks are rejected so a gate cannot hash or copy a file
    outside the pinned tree.
    """
    root = Path(root).resolve()
    build = root / BUILD
    native = root / NATIVE
    errors = []
    files = []
    if build.is_symlink() or not build.is_file():
        errors.append(f"{BUILD} is missing or not a regular file")
    else:
        files.append(build)
    native_files = []
    if native.is_symlink() or not native.is_dir():
        errors.append(f"{NATIVE}/ is missing or not a directory")
    else:
        for path in sorted(native.rglob("*")):
            if path.is_symlink():
                errors.append(f"{_key(root, path)} is a symlink")
            elif path.is_file():
                native_files.append(path)
        if not native_files:
            errors.append(f"{NATIVE}/ has no regular files")
    if errors:
        raise RuntimeError("missing Rust build inputs: " + "; ".join(errors))
    files.extend(native_files)
    files.append(HELPER)
    unique = []
    seen = set()
    for path in files:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def source_hashes(root):
    """Hash the source files, before any copy, as the existing receipts do."""
    root = Path(root).resolve()
    hashes = {}
    for path in source_files(root):
        hashes[_key(root, path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(hashes.items()))


def copy_into(root, destination):
    """Copy build.rs and the complete native/ tree byte-for-byte.

    Validation happens before the destination is created. An existing
    build.rs or native/ at the destination is refused and preserved; the gate
    uses a fresh copy. Destinations inside native/ or ancestors of the source
    tree are refused as overlap. The helper script itself is a metadata input,
    not a Cargo build input, so it is not copied.
    """
    root = Path(root).resolve()
    destination = Path(destination).resolve()
    native = root / NATIVE
    if destination == root or root.is_relative_to(destination):
        raise RuntimeError("destination is the source tree or its ancestor")
    if destination == native or destination.is_relative_to(native):
        raise RuntimeError("destination is inside native/")
    files = source_files(root)
    build_target = destination / BUILD
    native_target = destination / NATIVE
    if build_target.exists() or build_target.is_symlink():
        raise RuntimeError(f"refusing to overwrite existing {BUILD}")
    if native_target.exists() or native_target.is_symlink():
        raise RuntimeError(f"refusing to overwrite existing {NATIVE}/")
    destination.mkdir(parents=True, exist_ok=True)
    for path in files:
        if path.resolve() == HELPER:
            continue
        relative = path.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
