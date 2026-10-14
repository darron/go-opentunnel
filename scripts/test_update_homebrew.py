import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from release_artifacts import package, write_checksums
from update_homebrew import update


class FormulaUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tap = Path(self.tmp.name) / 'tap'
        (self.tap / 'Formula').mkdir(parents=True)
        self.path = self.tap / 'Formula' / 'otgo.rb'
        self.original = r'''class Otgo < Formula
  desc "OpenTunnel CLI with an embeddable Go client"
  homepage "https://github.com/darron/go-opentunnel"
  url "https://github.com/darron/go-opentunnel/archive/refs/tags/v0.11.0.tar.gz"
  sha256 "f6f4154020b3a9dff0fa48bb5003b22d062c4f898e1448396a0f67f049c88057"
  license "MIT"
  head "https://github.com/darron/go-opentunnel.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %w[-s -w]
    if build.stable?
      ldflags += %w[-X main.buildRevision=14620a57b0fe2dc88860304df90093cc24da09f5 -X main.buildState=clean]
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
        self.path.write_text(self.original)
        self.revision = 'd' * 40
        self.assets = Path(self.tmp.name) / 'assets'
        self.make_assets(self.assets, 'v0.12.0')

    def make_assets(self, directory, tag):
        directory.mkdir()
        binary = Path(self.tmp.name) / 'binary'
        license_path = Path(self.tmp.name) / 'LICENSE'
        license_path.write_text('MIT fixture')
        for os_name, arch in [('darwin', 'amd64'), ('darwin', 'arm64'), ('linux', 'amd64'), ('linux', 'arm64')]:
            binary.write_bytes((os_name + ':' + arch).encode())
            package(binary, license_path, directory, tag, os_name, arch)
        write_checksums(directory, tag)

    def apply(self, tag='v0.12.0', assets=None, revision=None):
        return update(self.tap, tag, assets or self.assets, revision or self.revision)

    def test_migrates_source_formula_to_four_exact_release_assets(self):
        other = self.tap / 'Formula' / 'dbrain.rb'
        other.write_text('untouched')
        self.assertTrue(self.apply())
        result = self.path.read_text()
        # A wrong target URL or digest would make Homebrew fetch different bytes.
        for filename in ['otgo_0.12.0_darwin_amd64.tar.gz', 'otgo_0.12.0_darwin_arm64.tar.gz',
                         'otgo_0.12.0_linux_amd64.tar.gz', 'otgo_0.12.0_linux_arm64.tar.gz']:
            digest = hashlib.sha256((self.assets / filename).read_bytes()).hexdigest()
            self.assertIn('https://github.com/darron/go-opentunnel/releases/download/v0.12.0/' + filename, result)
            self.assertIn('sha256 "' + digest + '"', result)
        self.assertNotIn('depends_on', result)
        self.assertNotIn('head ', result)
        self.assertNotIn('system "go"', result)
        self.assertIn('bin.install "otgo"', result)
        self.assertIn('skip_clean "bin/otgo"', result)
        self.assertIn(self.revision, result)
        self.assertEqual(other.read_text(), 'untouched')
        subprocess.run(['ruby', '-c', str(self.path)], check=True, capture_output=True)
        self.assertFalse(self.apply())

    def test_binary_formula_updates_and_refuses_downgrade(self):
        self.apply()
        next_assets = Path(self.tmp.name) / 'next'
        self.make_assets(next_assets, 'v0.13.0')
        self.assertTrue(self.apply('v0.13.0', next_assets))
        previous = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'downgrade'):
            self.apply()
        self.assertEqual(previous, self.path.read_bytes())

    def test_rejects_corrupt_missing_extra_or_symlinked_assets_without_writing(self):
        archive = self.assets / 'otgo_0.12.0_linux_arm64.tar.gz'
        original = archive.read_bytes()
        archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            self.apply()
        archive.write_bytes(original)
        checksum = self.assets / 'otgo_0.12.0_darwin_arm64.tar.gz.sha256'
        text = checksum.read_text()
        checksum.unlink()
        with self.assertRaises(ValueError):
            self.apply()
        checksum.symlink_to(self.assets / 'SHA256SUMS')
        with self.assertRaises(ValueError):
            self.apply()
        checksum.unlink()
        checksum.write_text(text)
        extra = self.assets / 'extra'
        extra.write_text('unexpected')
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(self.path.read_text(), self.original)

    def test_rejects_unstable_injected_tags_and_bad_revisions(self):
        for tag in ['v0.12.0-rc1', '0.12.0', 'v01.0.0', 'v1.0.0"\nother', '../../main', 'v1.0.0;pwd']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.apply(tag)
        for revision in ['d' * 39, 'D' * 40, 'z' * 40, 'sha -X main.other=value']:
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                self.apply(revision=revision)
        self.assertEqual(self.path.read_text(), self.original)

    def test_rejects_missing_duplicate_or_unexpected_formula(self):
        for text in ['', self.original * 2, self.original.replace('darron/go-opentunnel/archive', 'other/project/archive')]:
            self.path.write_text(text)
            with self.assertRaises(ValueError):
                self.apply()
            self.assertEqual(self.path.read_text(), text)

    def test_refuses_manual_source_changes(self):
        for text in [self.original.replace('  def install', '  service do\n    run "custom"\n  end\n\n  def install'),
                     self.original.replace('  license "MIT"', '  license "Apache-2.0"')]:
            self.path.write_text(text)
            with self.assertRaisesRegex(ValueError, 'source formula'):
                self.apply()
            self.assertEqual(text, self.path.read_text())

    def test_refuses_changed_metadata_for_same_binary_release(self):
        self.apply()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'same release'):
            self.apply(revision='e' * 40)
        self.assertEqual(original, self.path.read_bytes())

    def test_rejects_symlink_formula(self):
        backup = self.path.with_suffix('.backup')
        self.path.rename(backup)
        self.path.symlink_to(backup)
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(backup.read_text(), self.original)

    def test_numeric_order_and_binary_slot_tampering(self):
        self.apply()
        original = self.path.read_text()
        for text in [original.replace('darwin_arm64.tar.gz', 'darwin_amd64.tar.gz'),
                     original.replace('releases/download/v0.12.0/', 'releases/download/v0.11.0/'),
                     original.replace('  def install', '  version "0.12.0"\n\n  def install')]:
            self.path.write_text(text)
            with self.assertRaises(ValueError):
                self.apply()
            self.assertEqual(text, self.path.read_text())
        self.path.write_text(self.original.replace('v0.11.0', 'v0.9.0'))
        self.assertTrue(self.apply())


if __name__ == '__main__':
    unittest.main()
