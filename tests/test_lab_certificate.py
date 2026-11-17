"""The disposable lab pins the certificate SAN rather than an unrelated CN."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from docker_lab_init import fetch_server_certificate  # noqa: E402


class LabCertificateTests(unittest.TestCase):
    def test_san_takes_precedence_over_common_name(self):
        info = {"subjectAltName": (("DNS", "Omada"),),
                "subject": ((("commonName", "localhost"),),)}
        with patch("docker_lab_init.ssl.get_server_certificate", return_value="synthetic-pem"), \
                patch("docker_lab_init.ssl._ssl._test_decode_cert", return_value=info):
            self.assertEqual(fetch_server_certificate("127.0.0.1", 18043), ("synthetic-pem", "Omada"))


if __name__ == "__main__":
    unittest.main()
