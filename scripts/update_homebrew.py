#!/usr/bin/env python3
"""Update only the otgo formula for a published stable source release."""

import argparse
import re
from pathlib import Path

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
RELEASE_URL = re.compile(
    r'  url "https://github\.com/darron/go-opentunnel/archive/refs/tags/(v[^"/]+)\.tar\.gz"\n'
)
CHECKSUM = re.compile(r'  sha256 "[a-f0-9]{64}"\n')


def version(tag):
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError("release must be a stable vMAJOR.MINOR.PATCH tag")
    return tuple(int(part) for part in match.groups())


def update(tap, tag, checksum):
    requested = version(tag)
    if not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise ValueError("checksum must be 64 lowercase SHA-256 hex digits")
    path = Path(tap) / "Formula" / "otgo.rb"
    if path.is_symlink() or not path.is_file():
        raise ValueError("otgo formula must be an existing regular file")
    text = path.read_text(encoding="utf-8")
    urls = list(RELEASE_URL.finditer(text))
    if len(urls) != 1 or len(CHECKSUM.findall(text)) != 1:
        raise ValueError("formula must contain exactly one otgo release URL and checksum")
    if requested < version(urls[0].group(1)):
        raise ValueError("refusing to downgrade the stable formula")
    changed = RELEASE_URL.sub(
        f'  url "https://github.com/darron/go-opentunnel/archive/refs/tags/{tag}.tar.gz"\n',
        text,
    )
    changed = CHECKSUM.sub(f'  sha256 "{checksum}"\n', changed)
    if changed == text:
        return False
    path.write_text(changed, encoding="utf-8")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tap-dir", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        changed = update(args.tap_dir, args.tag, args.sha256)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Homebrew update refused: {exc}\n")
    print("Updated otgo formula." if changed else "otgo formula is already current.")


if __name__ == "__main__":
    main()
