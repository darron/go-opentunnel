#!/usr/bin/env python3
"""Install published release binaries in Homebrew without rebuilding them."""

import argparse
import hashlib
import re
from pathlib import Path

from release_artifacts import TARGETS, archive_name, validate_metadata, verify_bundle

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
SOURCE_URL = re.compile(r'^  url "https://github\.com/darron/go-opentunnel/archive/refs/tags/(v[^"/]+)\.tar\.gz"$', re.MULTILINE)
BINARY_URL = re.compile(r'^      url "https://github\.com/darron/go-opentunnel/releases/download/(v[^"/]+)/(otgo_[^"/]+\.tar\.gz)"\n      sha256 "([a-f0-9]{64})"$', re.MULTILINE)
REVISION = re.compile(r'(?<=-X main.buildRevision=)[a-f0-9]{40}(?=[\s"\'])')

# The published source formula is the only supported migration input.
LEGACY_SOURCE = r'''class Otgo < Formula
  desc "OpenTunnel CLI with an embeddable Go client"
  homepage "https://github.com/darron/go-opentunnel"
  url "https://github.com/darron/go-opentunnel/archive/refs/tags/@TAG@.tar.gz"
  sha256 "@SHA256@"
  license "MIT"
  head "https://github.com/darron/go-opentunnel.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %w[-s -w]
    if build.stable?
      ldflags += %w[-X main.buildRevision=@REVISION@ -X main.buildState=clean]
    end
    system "go", "build", *std_go_args(output: bin/"otgo", ldflags: ldflags.join(" ")), "./cmd/otgo"
  end

  test do
    assert_match "Usage: otgo", shell_output("#{bin}/otgo help")
    if build.head? || version >= Version.new("0.6.0")
      output = shell_output("#{bin}/otgo version")
      assert_match(/sha=[a-f0-9]{40} (clean|dirty)/, output)
      assert_match "#{version} sha=", output if build.stable?
      assert_match " clean", output if build.stable?
    end
    output = shell_output("#{bin}/otgo get --data-dir #{testpath}/tunnels --json")
    assert_equal "null\n", output
    refute_path_exists testpath/"tunnels/default/private-key.pem"
  end
end
'''


def version(tag):
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError("release must be a stable vMAJOR.MINOR.PATCH tag")
    return tuple(int(part) for part in match.groups())


def render(tag, checksums, revision):
    lines = [
        'class Otgo < Formula',
        '  desc "OpenTunnel CLI with an embeddable Go client"',
        '  homepage "https://github.com/darron/go-opentunnel"',
        '  license "MIT"',
    ]
    for os_name, stanza in [('darwin', 'on_macos'), ('linux', 'on_linux')]:
        lines += ['', f'  {stanza} do']
        for arch, condition in [('arm64', 'on_arm'), ('amd64', 'on_intel')]:
            filename = archive_name(tag, os_name, arch)
            lines += [f'    {condition} do',
                      f'      url "https://github.com/darron/go-opentunnel/releases/download/{tag}/{filename}"',
                      f'      sha256 "{checksums[filename]}"', '    end']
            if arch == 'arm64':
                lines.append('')
        lines.append('  end')
    lines += [
        '', '  # Preserve the exact executable published on GitHub.',
        '  skip_clean "bin/otgo"', '', '  def install',
        '    bin.install "otgo"', '  end', '', '  test do',
        '    assert_match "Usage: otgo", shell_output("#{bin}/otgo help")',
        f'    assert_equal "otgo #{{version}} sha={revision} clean\\n", shell_output("#{{bin}}/otgo version")',
        '    output = shell_output("#{bin}/otgo get --data-dir #{testpath}/tunnels --json")',
        '    assert_equal "null\\n", output',
        '    refute_path_exists testpath/"tunnels/default/private-key.pem"',
        '  end', 'end', '',
    ]
    return '\n'.join(lines)


def current_tag(text):
    source = SOURCE_URL.findall(text)
    if source:
        hashes = re.findall(r'^  sha256 "([a-f0-9]{64})"$', text, re.MULTILINE)
        revisions = REVISION.findall(text)
        if len(source) != 1 or len(hashes) != 1 or len(revisions) != 1:
            raise ValueError("unrecognized source formula")
        expected = (LEGACY_SOURCE.replace('@TAG@', source[0])
                    .replace('@SHA256@', hashes[0]).replace('@REVISION@', revisions[0]))
        if text != expected:
            raise ValueError("unrecognized source formula; refusing to overwrite manual changes")
        version(source[0])
        return source[0]
    matches = BINARY_URL.findall(text)
    tags = {tag for tag, _, _ in matches}
    if len(tags) != 1:
        raise ValueError("formula must have exactly one release version")
    tag = tags.pop()
    version(tag)
    expected = {archive_name(tag, os_name, arch) for os_name, arch in TARGETS}
    checksums = {filename: checksum for _, filename, checksum in matches}
    revisions = re.findall(r' sha=([a-f0-9]{40}) clean', text)
    if (len(matches) != 4 or set(checksums) != expected
            or any(found_tag != tag for found_tag, _, _ in matches)
            or len(revisions) != 1 or text != render(tag, checksums, revisions[0])):
        raise ValueError("unrecognized binary formula; refusing to overwrite manual changes")
    return tag


def update(tap, tag, assets, revision):
    validate_metadata(tag, revision)
    assets = Path(assets)
    verify_bundle(assets, tag)
    checksums = {archive_name(tag, os_name, arch): hashlib.sha256(
        (assets / archive_name(tag, os_name, arch)).read_bytes()).hexdigest()
        for os_name, arch in TARGETS}
    path = Path(tap) / 'Formula' / 'otgo.rb'
    if path.is_symlink() or not path.is_file():
        raise ValueError("otgo formula must be an existing regular file")
    text = path.read_text(encoding='utf-8')
    previous_tag = current_tag(text)
    if version(tag) < version(previous_tag):
        raise ValueError("refusing to downgrade the stable formula")
    changed = render(tag, checksums, revision)
    if changed == text:
        return False
    if tag == previous_tag and not SOURCE_URL.search(text):
        raise ValueError("refusing changed metadata for the same release")
    path.write_text(changed, encoding='utf-8')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tap-dir', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--assets-dir', type=Path, required=True)
    parser.add_argument('--revision', required=True, help="verified release tag's Git commit SHA")
    args = parser.parse_args()
    try:
        changed = update(args.tap_dir, args.tag, args.assets_dir, args.revision)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Homebrew update refused: {exc}\n')
    print('Updated otgo formula.' if changed else 'otgo formula is already current.')


if __name__ == '__main__':
    main()
