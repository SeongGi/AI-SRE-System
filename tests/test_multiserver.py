import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mock external modules if not installed locally
class MockFlask:
    def __init__(self, *args, **kwargs):
        pass
    def route(self, *args, **kwargs):
        return lambda f: f
    def run(self, *args, **kwargs):
        pass

for mod in ["flask", "pydantic", "google", "google.genai", "google.genai.types"]:
    if mod not in sys.modules:
        m = MagicMock()
        if mod == "flask":
            m.Flask = MockFlask
            m.request = MagicMock()
            m.jsonify = lambda d: d
        elif mod == "pydantic":
            class MockBaseModel:
                def __init__(self, **kwargs):
                    for k, v in kwargs.items():
                        setattr(self, k, v)
            m.BaseModel = MockBaseModel
            m.Field = lambda description="": None
        sys.modules[mod] = m

class TestMultiServerLogic(unittest.TestCase):
    def test_env_defaults(self):
        with patch.dict(os.environ, {"SERVER_NAME": "test-oci-node", "ENABLE_TELEGRAM_POLLING": "false"}):
            import importlib
            import main
            importlib.reload(main)
            self.assertEqual(main.SERVER_NAME, "test-oci-node")
            self.assertFalse(main.ENABLE_TELEGRAM_POLLING)

    def test_send_telegram_alert_polling_disabled(self):
        with patch.dict(os.environ, {
            "SERVER_NAME": "test-oci-node",
            "ENABLE_TELEGRAM_POLLING": "false",
            "TELEGRAM_BOT_TOKEN": "mock-token",
            "TELEGRAM_CHAT_ID": "12345"
        }):
            import importlib
            import main
            importlib.reload(main)

            plan = main.RemediationPlan(
                needs_action=True,
                severity="HIGH",
                summary="High CPU load detected",
                analysis="Process runaway",
                command="top -b -n 1"
            )

            with patch("requests.post") as mock_post:
                mock_post.return_value.status_code = 200
                main.send_telegram_alert(plan, "kernel: CPU 100% load", "top -b -n 1", True, "act-123")
                
                self.assertTrue(mock_post.called)
                sent_json = mock_post.call_args[1]["json"]
                self.assertIn("test-oci-node", sent_json["text"])
                self.assertNotIn("reply_markup", sent_json)
                self.assertIn("[알림 전용 노드]", sent_json["text"])

    def test_send_telegram_alert_polling_enabled(self):
        with patch.dict(os.environ, {
            "SERVER_NAME": "test-ubuntu-node",
            "ENABLE_TELEGRAM_POLLING": "true",
            "TELEGRAM_BOT_TOKEN": "mock-token",
            "TELEGRAM_CHAT_ID": "12345"
        }):
            import importlib
            import main
            importlib.reload(main)

            plan = main.RemediationPlan(
                needs_action=True,
                severity="HIGH",
                summary="Service failure",
                analysis="Nginx crashed",
                command="systemctl restart nginx"
            )

            with patch("requests.post") as mock_post:
                mock_post.return_value.status_code = 200
                main.send_telegram_alert(plan, "nginx: fatal error", "systemctl restart nginx", True, "act-456")
                
                self.assertTrue(mock_post.called)
                sent_json = mock_post.call_args[1]["json"]
                self.assertIn("test-ubuntu-node", sent_json["text"])
                self.assertIn("reply_markup", sent_json)
                self.assertIn("inline_keyboard", sent_json["reply_markup"])

if __name__ == "__main__":
    unittest.main()
