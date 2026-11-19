"""Every installed copy since 1.18 must be able to take the next release."""
import os
import re
import unittest

from tests import _env
from netscan import updater

# APP_TOP of the oldest updater in the field (1.18.0): an update zip may only contain these names.
LEGACY_APP_TOP = {"netscan", "netsentinel.py", "requirements.txt", "README.md", "EULA.txt", "sbom.json"}


def workflow():
    with open(os.path.join(_env.ROOT, ".github", "workflows", "build-windows-exe.yml"), encoding="utf-8") as fh:
        return fh.read()


class ReleaseCompatibility(unittest.TestCase):
    def test_app_zip_only_contains_names_old_copies_accept(self):
        top = re.search(r"top=\[([^\]]+)\]", workflow()).group(1)
        names = {x.strip().strip("'\"") for x in top.split(",")}
        self.assertTrue(names <= LEGACY_APP_TOP, names - LEGACY_APP_TOP)
        self.assertIn("netsentinel.py", names)          # the entry script name is part of the contract

    def test_current_updater_still_accepts_legacy_names(self):
        self.assertTrue(LEGACY_APP_TOP <= updater.APP_TOP)

    def test_updates_still_come_from_the_same_repository(self):
        self.assertEqual(updater.REPO, "RavindraBellur/NetSentinel")

    def test_release_asset_names_match_what_is_built_and_signed(self):
        wf = workflow()
        with open(os.path.join(_env.ROOT, "tools", "sign_release.py"), encoding="utf-8") as fh:
            signer = fh.read()
        for asset in re.findall(r'"(\w[\w.-]*\.(?:exe|zip))"', signer.split("ASSETS", 1)[1].split("\n", 1)[0]):
            self.assertIn(f"dist/{asset}", wf.replace("\\\\", "/"))

    def test_data_folder_unchanged(self):
        from netscan import settings
        self.assertTrue(settings.CONFIG_DIR.endswith(".netsentinel"))


if __name__ == "__main__":
    unittest.main()
