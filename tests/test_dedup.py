"""Órdenes repetidas: una orden de control con el mismo req_id se ejecuta UNA vez.

Sin red ni broker: se importa el agente, se sustituye `publish` por una lista y se meten
comandos falsos en COMMAND_MAP. Uso:  python3 -m unittest discover -s tests -v
"""
import importlib
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NTFY_SERVER", "https://broker.invalid")
os.environ.setdefault("NTFY_TOKEN", "test")


def _msg(req_id, cmd):
    return json.dumps({"id": req_id, "cmd": cmd, "args": {}, "device": "test", "scope": "rw"})


class _Base:
    MODULE = ""

    def setUp(self):
        self.agent = importlib.import_module(self.MODULE)
        self.published = []
        self.calls = []
        self._orig_publish = self.agent.publish
        self.agent.publish = lambda rid, st, data: self.published.append((rid, st, data))
        # getattr: contra un agente sin esta memoria el test debe FALLAR por ejecutar dos
        # veces, no dar error por que falte el atributo.
        getattr(self.agent, "_seen", {}).clear()

        def slow_ctl(_args):
            self.calls.append("ctl")
            time.sleep(0.3)
            return {"hecho": str(len(self.calls))}

        def failing_ctl(_args):
            self.calls.append("fail")
            raise RuntimeError("se rompió")

        def read(_args):
            self.calls.append("read")
            return {"cpu_pct": "1"}

        self._orig_map = dict(self.agent.COMMAND_MAP)
        self.agent.COMMAND_MAP["fake_ctl"] = slow_ctl
        self.agent.COMMAND_MAP["fake_fail"] = failing_ctl
        self.agent.COMMAND_MAP["check_status"] = read

    def tearDown(self):
        self.agent.publish = self._orig_publish
        self.agent.COMMAND_MAP.clear()
        self.agent.COMMAND_MAP.update(self._orig_map)

    def test_dos_a_la_vez_se_ejecuta_una(self):
        ts = [threading.Thread(target=self.agent.handle, args=(_msg("req_a", "fake_ctl"),)) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(self.calls, ["ctl"])
        self.assertEqual(self.published, [("req_a", "ok", {"hecho": "1"})])

    def test_repetida_tras_acabar_republica_sin_ejecutar(self):
        self.agent.handle(_msg("req_b", "fake_ctl"))
        self.agent.handle(_msg("req_b", "fake_ctl"))
        self.assertEqual(self.calls, ["ctl"])
        self.assertEqual(self.published, [("req_b", "ok", {"hecho": "1"})] * 2)

    def test_otro_req_id_si_se_ejecuta(self):
        self.agent.handle(_msg("req_c1", "fake_ctl"))
        self.agent.handle(_msg("req_c2", "fake_ctl"))
        self.assertEqual(self.calls, ["ctl", "ctl"])

    def test_error_repetido_republica_el_error(self):
        self.agent.handle(_msg("req_d", "fake_fail"))
        self.agent.handle(_msg("req_d", "fake_fail"))
        self.assertEqual(self.calls, ["fail"])
        self.assertEqual([p[1] for p in self.published], ["error", "error"])

    def test_las_lecturas_no_se_recuerdan(self):
        self.agent.handle(_msg("req_e", "check_status"))
        self.agent.handle(_msg("req_e", "check_status"))
        self.assertEqual(self.calls, ["read", "read"])
        self.assertNotIn("req_e", getattr(self.agent, "_seen", {}))

    def test_caduca_a_los_5_minutos(self):
        self.agent.handle(_msg("req_f", "fake_ctl"))
        self.agent._seen["req_f"][0] -= self.agent.DEDUP_TTL_S + 1
        self.agent.handle(_msg("req_f", "fake_ctl"))
        self.assertEqual(self.calls, ["ctl", "ctl"])


class AgentMac(_Base, unittest.TestCase):
    MODULE = "agent"


class AgentLinux(_Base, unittest.TestCase):
    MODULE = "agent_linux"


if __name__ == "__main__":
    unittest.main()
