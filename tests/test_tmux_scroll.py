"""tmux_scroll copy=1: el historial de tmux por su modo copia, con su `mouse` apagado.

Usa un servidor tmux PROPIO (socket aparte, sin configuración) que se mata al acabar: nunca
toca las sesiones del usuario. Se salta si no hay tmux. Uso:
    python3 -m unittest discover -s tests -v
"""
import importlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NTFY_SERVER", "https://broker.invalid")
os.environ.setdefault("NTFY_TOKEN", "test")
os.environ.setdefault("SERVWARD_DIR", tempfile.mkdtemp(prefix="servward-test-"))
os.environ["ALLOW_CLAUDE_CONTROL"] = "1"

TMUX = shutil.which("tmux") or ("/opt/homebrew/bin/tmux" if os.path.exists("/opt/homebrew/bin/tmux") else None)
SOCK = f"swtest{os.getpid()}"


def tm(*args):
    return subprocess.run([TMUX, "-L", SOCK, "-f", "/dev/null", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


@unittest.skipUnless(TMUX, "tmux no instalado")
class _Base:
    MODULE = ""

    def setUp(self):
        self.agent = importlib.import_module(self.MODULE)
        self._blocked = self.agent._claude_control_blocked
        self.agent._claude_control_blocked = lambda: None
        self.agent.ALLOW_CLAUDE_CONTROL = True
        tm("new-session", "-d", "-s", "t", "-x", "80", "-y", "24")
        tm("set", "-g", "mouse", "off")
        tm("send-keys", "-t", "t", "for i in $(seq 1 300); do echo linea $i; done", "Enter")
        for _ in range(50):
            if int(tm("display", "-p", "-t", "t", "#{history_size}") or 0) > 200:
                break
            time.sleep(0.1)

    def tearDown(self):
        self.agent._claude_control_blocked = self._blocked
        subprocess.run([TMUX, "-L", SOCK, "kill-server"], capture_output=True, check=False)
        try:
            os.remove(os.path.join(os.environ.get("TMUX_TMPDIR") or "/tmp", f"tmux-{os.getuid()}", SOCK))
        except OSError:
            pass

    def _state(self):
        return tm("display", "-p", "-t", "t", "#{pane_in_mode} #{scroll_position}").split()

    def _scroll(self, direction, n, copy="1"):
        return self.agent.cmd_tmux_scroll({"target": "t:0.0", "socket": SOCK, "dir": direction,
                                           "n": str(n), "copy": copy})

    def test_subir_entra_en_modo_copia_y_desplaza(self):
        r = self._scroll("up", 10)
        self.assertEqual(r.get("via"), "copy", r)
        self.assertEqual(self._state(), ["1", "10"])

    def test_bajar_hasta_el_final_sale_del_modo_copia(self):
        self._scroll("up", 10)
        self._scroll("down", 10)
        self.assertEqual(self._state()[0], "0")

    def test_bajar_sin_estar_en_modo_copia_no_hace_nada(self):
        r = self._scroll("down", 5)
        self.assertEqual(r.get("via"), "copy", r)
        self.assertEqual(self._state()[0], "0")

    def test_sin_copy_se_comporta_como_antes(self):
        r = self._scroll("up", 6, copy="")
        self.assertEqual(r.get("via"), "keys", r)
        self.assertEqual(self._state()[0], "0")


class AgentMac(_Base, unittest.TestCase):
    MODULE = "agent"


class AgentLinux(_Base, unittest.TestCase):
    MODULE = "agent_linux"


if __name__ == "__main__":
    unittest.main()
