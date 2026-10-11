import tempfile
import unittest
from pathlib import Path

from update_homebrew import update


class FormulaUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tap = Path(self.tmp.name)
        (self.tap / "Formula").mkdir()
        self.path = self.tap / "Formula" / "otgo.rb"
        self.original = (
            'class Otgo < Formula\n'
            '  url "https://github.com/darron/go-opentunnel/archive/refs/tags/v0.3.0.tar.gz"\n'
            f'  sha256 "{"a" * 64}"\n'
            '  head "https://github.com/darron/go-opentunnel.git", branch: "main"\n'
            '  def install\n    system "go", "build", "./cmd/otgo"\n  end\nend\n'
        )
        self.path.write_text(self.original)

    def test_update_preserves_install_head_and_other_formula(self):
        other = self.tap / "Formula" / "dbrain.rb"
        other.write_text("untouched")
        self.assertTrue(update(self.tap, "v0.4.0", "b" * 64))
        result = self.path.read_text()
        self.assertIn("v0.4.0.tar.gz", result)
        self.assertIn('"b' + "b" * 63 + '"', result)
        self.assertIn('system "go", "build", "./cmd/otgo"', result)
        self.assertIn('branch: "main"', result)
        self.assertEqual(other.read_text(), "untouched")
        self.assertFalse(update(self.tap, "v0.4.0", "b" * 64))

    def test_rejects_unstable_or_injected_tags_and_bad_checksums(self):
        for tag in ["v0.4.0-rc1", "0.4.0", "v01.0.0", 'v1.0.0"\nother', "../../main", "v1.0.0;pwd"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                update(self.tap, tag, "b" * 64)
        for checksum in ["b" * 63, "B" * 64, '"\nmalicious', "z" * 64]:
            with self.subTest(checksum=checksum), self.assertRaises(ValueError):
                update(self.tap, "v0.4.0", checksum)
        self.assertEqual(self.path.read_text(), self.original)

    def test_no_downgrade_and_numeric_version_order(self):
        with self.assertRaises(ValueError):
            update(self.tap, "v0.2.9", "b" * 64)
        update(self.tap, "v0.10.0", "b" * 64)
        with self.assertRaises(ValueError):
            update(self.tap, "v0.9.9", "c" * 64)

    def test_rejects_missing_duplicate_or_unexpected_slots(self):
        for text in ["", self.original * 2, self.original.replace("darron/go-opentunnel/archive", "other/project/archive")]:
            self.path.write_text(text)
            with self.assertRaises(ValueError):
                update(self.tap, "v0.4.0", "b" * 64)
            self.assertEqual(self.path.read_text(), text)

    def test_rejects_symlink(self):
        self.path.rename(self.path.with_suffix(".backup"))
        self.path.symlink_to(self.path.with_suffix(".backup"))
        with self.assertRaises(ValueError):
            update(self.tap, "v0.4.0", "b" * 64)

    def test_embeds_verified_revision_and_rejects_bad_revision(self):
        text = self.original.replace('"build", "./cmd/otgo"', f'"build", "-ldflags", "-X main.buildRevision={"c" * 40}", "./cmd/otgo"')
        self.path.write_text(text)
        self.assertTrue(update(self.tap, "v0.4.0", "b" * 64, "d" * 40))
        self.assertIn("-X main.buildRevision=" + "d" * 40, self.path.read_text())
        self.assertFalse(update(self.tap, "v0.4.0", "b" * 64, "d" * 40))
        with self.assertRaises(ValueError):
            update(self.tap, "v0.4.0", "b" * 64)
        original = self.path.read_text()
        for revision in ["d" * 39, "D" * 40, "z" * 40, "sha -X main.other=value"]:
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                update(self.tap, "v0.4.0", "b" * 64, revision)
            self.assertEqual(self.path.read_text(), original)

    def test_revision_slot_must_be_unique(self):
        for text in [self.original, self.original.replace('"build", "./cmd/otgo"', f'"build", "-ldflags", "-X main.buildRevision={"c" * 40} -X main.buildRevision={"d" * 40}", "./cmd/otgo"')]:
            self.path.write_text(text)
            with self.assertRaises(ValueError):
                update(self.tap, "v0.4.0", "b" * 64, "d" * 40)
            self.assertEqual(self.path.read_text(), text)


if __name__ == "__main__":
    unittest.main()
