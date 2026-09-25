"""El «Sí» o la respuesta desde un aviso solo cae en la pregunta que se avisó.

Sin red ni tmux: se sustituyen el pane, `_tmux` y `send_push`. El estado de las sesiones se
escribe en una carpeta temporal, nunca en ~/.servward. Uso:
    python3 -m unittest discover -s tests -v
"""
import importlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NTFY_SERVER", "https://broker.invalid")
os.environ.setdefault("NTFY_TOKEN", "test")
os.environ.setdefault("SERVWARD_DIR", tempfile.mkdtemp(prefix="servward-test-"))


class _Base:
    MODULE = ""

    def setUp(self):
        a = self.agent = importlib.import_module(self.MODULE)
        self.tmp = tempfile.mkdtemp(prefix="servward-test-")
        self._saved = {k: getattr(a, k) for k in (
            "SERVWARD_DIR", "CLAUDE_ATTENTION_FILE", "_claude_control_blocked", "_claude_pane_for",
            "_tmux", "send_push", "_claude_push_enabled", "_can_alert", "_live_update",
            "_claude_session_label", "_pidmap_learn")}
        a.SERVWARD_DIR = self.tmp
        a.CLAUDE_ATTENTION_FILE = os.path.join(self.tmp, "session-state.json")
        a._ATTENTION.clear()
        self.keys = []
        self.pushes = []
        a._claude_control_blocked = lambda: None
        a._claude_pane_for = lambda ident: ("", "sess:0.0")
        a._tmux = lambda *args, socket="": self.keys.append(args)
        a.send_push = lambda title, body, data=None, category="SW_ALERT": self.pushes.append(data or {}) or True
        a._claude_push_enabled = lambda: True
        a._can_alert = lambda *args, **kw: True
        a._live_update = lambda *args, **kw: None
        a._claude_session_label = lambda sid, cwd: "sesión"
        a._pidmap_learn = lambda *args, **kw: None

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(self.agent, k, v)
        self.agent._ATTENTION.clear()

    def _ev(self, sid="s1"):
        # .get: contra un agente sin marcas el test debe FALLAR por teclear, no por la clave.
        return self.agent._ATTENTION[sid].get("ev", "sin-marca")

    def test_si_con_la_marca_del_aviso_pulsa_intro(self):
        self.agent._attention_set("s1", "needs_you", "¿Borro la carpeta?")
        r = self.agent.cmd_claude_answer({"id": "s1", "yes": "1", "ev": self._ev()})
        self.assertIn("ok", r)
        self.assertEqual(self.keys, [("send-keys", "-t", "sess:0.0", "Enter")])

    def test_si_de_un_aviso_viejo_no_aprueba_la_pregunta_siguiente(self):
        self.agent._attention_set("s1", "needs_you", "¿Borro la carpeta A?")
        viejo = self._ev()
        self.agent._attention_set("s1", "working", "sí")               # respondiste en el Mac
        self.agent._attention_set("s1", "needs_you", "¿Borro la carpeta B?")
        r = self.agent.cmd_claude_answer({"id": "s1", "yes": "1", "ev": viejo})
        self.assertEqual(r.get("stale"), "1")
        self.assertEqual(self.keys, [])

    def test_si_cuando_ya_no_espera_no_pulsa_nada(self):
        self.agent._attention_set("s1", "done", "Ha acabado")
        r = self.agent.cmd_claude_answer({"id": "s1", "yes": "1", "ev": self._ev()})
        self.assertEqual(r.get("stale"), "1")
        self.assertEqual(self.keys, [])

    def test_responder_texto_a_una_sesion_acabada_si_vale(self):
        self.agent._attention_set("s1", "done", "Ha acabado")
        r = self.agent.cmd_claude_answer({"id": "s1", "text": "ahora haz los tests", "ev": self._ev()})
        self.assertIn("ok", r)
        self.assertEqual(self.keys[-1], ("send-keys", "-t", "sess:0.0", "Enter"))

    def test_sin_marca_se_comporta_como_antes(self):
        self.agent._attention_set("s1", "working", "…")
        r = self.agent.cmd_claude_answer({"id": "s1", "yes": "1"})
        self.assertIn("ok", r)
        self.assertEqual(len(self.keys), 1)


class AgentMac(_Base, unittest.TestCase):
    MODULE = "agent"

    def test_el_aviso_lleva_la_marca_del_momento(self):
        ntype = min(self.agent._NEEDS_YOU_TYPES)
        self.agent._claude_handle_event({"ev": {"hook_event_name": "Notification", "session_id": "s2",
                                                "cwd": "/tmp", "notification_type": ntype,
                                                "message": "¿Puedo ejecutar rm?"}})
        self.assertEqual(len(self.pushes), 1)
        self.assertEqual(self.pushes[0].get("ev"), self._ev("s2"))
        self.assertTrue(self.pushes[0]["ev"])


class AgentLinux(_Base, unittest.TestCase):
    MODULE = "agent_linux"


if __name__ == "__main__":
    unittest.main()
