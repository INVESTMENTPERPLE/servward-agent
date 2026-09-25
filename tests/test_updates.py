"""cmd_updates: «0 actualizaciones» solo si se pudo mirar; si no, error o aviso.

Se sustituyen subprocess.run y shutil.which: no se ejecuta brew, softwareupdate ni apt.
Uso: python3 -m unittest discover -s tests -v
"""
import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NTFY_SERVER", "https://broker.invalid")
os.environ.setdefault("NTFY_TOKEN", "test")
os.environ.setdefault("SERVWARD_DIR", tempfile.mkdtemp(prefix="servward-test-"))

SU_NADA = "Software Update Tool\n\nFinding available software\nNo new software available.\n"
SU_UNA = ("Software Update found the following new or updated software:\n"
          "* Label: macOS Tahoe 26.7-25G229\n\tTitle: macOS Tahoe 26.7\n")
SU_SIN_RED = "Software Update Tool\n\nFinding available software\nCan't connect to the Apple Software Update server.\n"
APT_OK = ("Listing...\n"
          "alsa-ucm-conf/noble-updates 1.2.10 all [upgradable from: 1.2.9]\n"
          "openssl/noble-security 3.0.13 amd64 [upgradable from: 3.0.12]\n")


def fake_run(table):
    """table: nombre del programa → (returncode, stdout, stderr) o una excepción."""
    def run(argv, **_kw):
        r = table[argv[0]]
        if isinstance(r, Exception):
            raise r
        return SimpleNamespace(returncode=r[0], stdout=r[1], stderr=r[2])
    return run


class _Base:
    MODULE = ""

    def setUp(self):
        self.agent = importlib.import_module(self.MODULE)
        self._run, self._which = self.agent.subprocess.run, self.agent.shutil.which

    def tearDown(self):
        self.agent.subprocess.run, self.agent.shutil.which = self._run, self._which

    def call(self, table, have=("brew", "apt")):
        self.agent.subprocess.run = fake_run(table)
        self.agent.shutil.which = lambda name: f"/bin/{name}" if name in have else None
        return self.agent.cmd_updates({})


class AgentMac(_Base, unittest.TestCase):
    MODULE = "agent"

    def test_todo_bien(self):
        d = self.call({"brew": (0, "git\nnode\n", ""), "softwareupdate": (0, "", SU_NADA)})
        self.assertEqual((d.get("count"), d.get("error"), d.get("aviso")), ("2", None, None))

    def test_falla_brew_cuenta_macos_y_avisa(self):
        d = self.call({"brew": (1, "", "Error: sin permiso"), "softwareupdate": (0, SU_UNA, "")})
        self.assertEqual(d.get("count"), "1")
        self.assertIn("Homebrew", d.get("aviso", ""))

    def test_si_no_se_pudo_mirar_nada_es_error_y_no_cero(self):
        d = self.call({"brew": subprocess.TimeoutExpired("brew", 30), "softwareupdate": (0, "", SU_SIN_RED)})
        self.assertNotIn("count", d)
        self.assertIn("No se pudieron comprobar", d.get("error", ""))

    def test_sin_brew_y_sin_red_es_error(self):
        d = self.call({"softwareupdate": (0, "", SU_SIN_RED)}, have=())
        self.assertIn("error", d)


class AgentLinux(_Base, unittest.TestCase):
    MODULE = "agent_linux"

    def test_apt_bien(self):
        d = self.call({"apt": (0, APT_OK, "WARNING: apt does not have a stable CLI interface.")})
        self.assertEqual((d.get("count"), d.get("security")), ("2", "1"))

    def test_sin_apt_es_error_y_no_cero(self):
        d = self.call({}, have=())
        self.assertNotIn("count", d)
        self.assertIn("error", d)

    def test_apt_que_falla_es_error(self):
        d = self.call({"apt": (100, "", "E: Could not open lock file")})
        self.assertIn("error", d)
        self.assertNotIn("count", d)

    def test_apt_sin_listing_no_vale(self):
        d = self.call({"apt": (0, "", "")})
        self.assertIn("error", d)


if __name__ == "__main__":
    unittest.main()
