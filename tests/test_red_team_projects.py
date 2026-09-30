import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nmap_explorer = load_module("nmap_explorer", "nmap-result-explorer/nmap_explorer.py")
endpoint_inventory = load_module(
    "endpoint_inventory",
    "web-endpoint-inventory/endpoint_inventory.py",
)
ctf_toolbox = load_module("ctf_toolbox", "ctf-toolbox/toolbox.py")
wordlist_lab = load_module("wordlist_lab", "wordlist-lab/wordlist_lab.py")
evidence = load_module("evidence", "evidence-organizer/evidence.py")


class NmapExplorerTests(unittest.TestCase):
    def test_sample_xml(self):
        result = nmap_explorer.parse_nmap_xml(
            ROOT / "nmap-result-explorer" / "sample.xml"
        )

        self.assertEqual(result["summary"]["hosts_up"], 1)
        self.assertEqual(result["summary"]["open_ports"], 2)
        self.assertEqual(result["summary"]["services"]["ssh"], 1)
        self.assertIn("lab-web.local", result["hosts"][0]["hostnames"])


class EndpointInventoryTests(unittest.TestCase):
    def test_har_inventory(self):
        entries = endpoint_inventory.parse_har(
            ROOT / "web-endpoint-inventory" / "sample.har"
        )
        deduped = endpoint_inventory.dedupe_entries(entries)
        report = endpoint_inventory.build_report(
            deduped,
            include_static=False,
        )

        self.assertEqual(report["summary"]["endpoints"], 2)
        self.assertEqual(report["summary"]["methods"]["GET"], 1)
        self.assertEqual(report["summary"]["methods"]["POST"], 1)
        self.assertIn("next", report["summary"]["parameters"])
        self.assertIn("username", report["summary"]["parameters"])


class CtfToolboxTests(unittest.TestCase):
    def test_encodings_and_hash_id(self):
        self.assertEqual(ctf_toolbox.b64_encode("hello"), "aGVsbG8=")
        self.assertEqual(ctf_toolbox.b64_decode("aGVsbG8="), "hello")
        self.assertEqual(ctf_toolbox.hex_decode("68656c6c6f"), "hello")
        self.assertIn(
            "MD5",
            ctf_toolbox.identify_hash(
                "5d41402abc4b2a76b9719d911017c592"
            ),
        )

    def test_jwt_decode_only(self):
        token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiJsYWItdXNlciJ9."
        )
        decoded = ctf_toolbox.decode_jwt(token)
        self.assertEqual(decoded["payload"]["sub"], "lab-user")
        self.assertFalse(decoded["signature_present"])


class WordlistLabTests(unittest.TestCase):
    def test_filters_transforms_and_cap(self):
        result = wordlist_lab.build_wordlist(
            ["Admin", "Admin", "lab"],
            min_length=3,
            max_length=12,
            modes=["lower"],
            suffixes=["2026"],
            max_output=20,
        )

        self.assertIn("admin", result)
        self.assertIn("Admin2026", result)
        self.assertEqual(len(result), len(set(result)))


class EvidenceOrganizerTests(unittest.TestCase):
    def test_add_and_verify(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "case"
            source = root / "proof.txt"
            source.write_text("evidence", encoding="utf-8")

            evidence.init_case(case, "Test Case", "lab only")
            item = evidence.add_evidence(
                case,
                source,
                note="test note",
                finding="F-01",
            )

            self.assertEqual(item["category"], "notes")
            verify = evidence.verify_case(case)
            self.assertEqual(verify[0]["status"], "ok")

            copied = case / item["path"]
            copied.write_text("changed", encoding="utf-8")
            verify = evidence.verify_case(case)
            self.assertEqual(verify[0]["status"], "changed")


if __name__ == "__main__":
    unittest.main()
