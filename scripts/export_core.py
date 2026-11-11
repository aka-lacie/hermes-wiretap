#!/usr/bin/env python3
"""Export the reviewable provider-neutral Wiretap package (never local extensions).

This is a local build command, not a runtime self-updater. It refuses existing
output directories and copies only source assets/tests, never profile state,
deployment receipts, caches, symlinks or credential enrichment.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil

SOURCE = Path(__file__).resolve().parent.parent


def export(destination: Path):
    if destination.exists():
        raise FileExistsError(f'Refusing to overwrite {destination}')
    files = []
    for path in SOURCE.rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(SOURCE)
        if any(part in ('extensions', '__pycache__', '.pytest_cache', 'node_modules', '.git') for part in rel.parts):
            continue
        if rel.name in ('deployment.json',):
            continue
        permitted = rel.suffix in ('.py', '.js', '.mjs', '.css', '.md', '.yaml', '.json') or rel.parts[0] == 'bin' or rel.name == 'LICENSE'
        if not permitted:
            continue
        files.append(rel)
    destination.mkdir(parents=True)
    for rel in files:
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / rel, target)
        if rel.parts[0] == 'bin':
            target.chmod(0o755)
    manifest = {str(rel): hashlib.sha256((destination/rel).read_bytes()).hexdigest() for rel in sorted(files)}
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    manifest = export(args.destination)
    if args.manifest:
        args.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'destination': str(args.destination), 'files': len(manifest), 'extensions': False}))
