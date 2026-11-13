"""Pruebas unitarias de seguridad: Path Traversal, Symlinks, Basic Auth, PBKDF2 y CSRF."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from server.logging_setup import sanitize_log_field
from server.security import (
    CSRFTokenManager,
    SecurityViolationError,
    hash_password,
    is_path_protected,
    resolve_safe_path,
    verify_basic_auth,
    verify_password,
)


class TestSecurity(unittest.TestCase):
    """Verifica todos los controles de seguridad exigidos por la consigna."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.base_path = Path(self._tmpdir.name).resolve()
        self.doc_root = self.base_path / "www"
        self.doc_root.mkdir(parents=True, exist_ok=True)

        # Archivos de prueba dentro y fuera del DocumentRoot
        (self.doc_root / "index.html").write_text("<h1>Inicio</h1>", encoding="utf-8")
        (self.doc_root / "private").mkdir(exist_ok=True)
        (self.doc_root / "private" / "secret.html").write_text("Secreto", encoding="utf-8")
        self.outside_file = self.base_path / "outside_secret.txt"
        self.outside_file.write_text("FUERA_DEL_DOCUMENT_ROOT", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_normal_path_inside_document_root_allowed(self) -> None:
        resolved = resolve_safe_path(self.doc_root, "/index.html")
        self.assertEqual(resolved, (self.doc_root / "index.html").resolve())

        resolved_sub = resolve_safe_path(self.doc_root, "/private/secret.html")
        self.assertEqual(resolved_sub, (self.doc_root / "private" / "secret.html").resolve())

    def test_dot_dot_path_traversal_blocked(self) -> None:
        traversal_attempts = [
            "/../outside_secret.txt",
            "/../../etc/passwd",
            "/private/../../outside_secret.txt",
            "/..",
        ]
        for attempt in traversal_attempts:
            with self.subTest(attempt=attempt):
                with self.assertRaises(SecurityViolationError):
                    resolve_safe_path(self.doc_root, attempt)

    def test_encoded_path_traversal_blocked(self) -> None:
        encoded_attempts = [
            "/%2e%2e/outside_secret.txt",
            "/%2E%2E/%2E%2E/etc/passwd",
            "/%252e%252e/outside_secret.txt",
            "/..%2foutside_secret.txt",
            "/..%5coutside_secret.txt",
            "/\\..\\outside_secret.txt",
            "/index.html%00.txt",
        ]
        for attempt in encoded_attempts:
            with self.subTest(attempt=attempt):
                with self.assertRaises(SecurityViolationError):
                    resolve_safe_path(self.doc_root, attempt)

    def test_absolute_or_drive_paths_outside_document_root_blocked(self) -> None:
        abs_attempts = [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "/C:/Windows/win.ini",
            "\\\\server\\share\\file.txt",
        ]
        for attempt in abs_attempts:
            with self.subTest(attempt=attempt):
                with self.assertRaises(SecurityViolationError):
                    resolve_safe_path(self.doc_root, attempt)

    def test_symlink_pointing_outside_document_root_blocked(self) -> None:
        symlink_path = self.doc_root / "evil_link.txt"
        try:
            symlink_path.symlink_to(self.outside_file)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(
                f"El sistema operativo actual no permitió crear enlaces simbólicos sin privilegios elevados: {exc}"
            )

        with self.assertRaises(SecurityViolationError):
            resolve_safe_path(self.doc_root, "/evil_link.txt")

    def test_canonical_resolution_blocks_external_target_even_without_os_symlink_privilege(self) -> None:
        """Verifica la comprobación is_relative_to cuando Path.resolve() apunta fuera del DocumentRoot."""
        from unittest.mock import patch

        original_resolve = Path.resolve
        outside_resolved = original_resolve(self.outside_file)
        docroot_resolved = original_resolve(self.doc_root)

        def fake_resolve(path_obj: Path, *args: object, **kwargs: object) -> Path:
            if path_obj.name == "simulated_symlink.txt":
                return outside_resolved
            if path_obj == self.doc_root:
                return docroot_resolved
            return original_resolve(path_obj)

        with patch.object(Path, "resolve", autospec=True, side_effect=fake_resolve):
            with self.assertRaises(SecurityViolationError):
                resolve_safe_path(self.doc_root, "/simulated_symlink.txt")

    def test_protected_directory_matching(self) -> None:
        protected = ["/private"]
        self.assertTrue(is_path_protected("/private", protected))
        self.assertTrue(is_path_protected("/private/", protected))
        self.assertTrue(is_path_protected("/private/index.html", protected))
        self.assertTrue(is_path_protected("//private///confidential.html", protected))
        self.assertFalse(is_path_protected("/index.html", protected))
        self.assertFalse(is_path_protected("/private_other/index.html", protected))

    def test_password_hashing_and_verification(self) -> None:
        stored_hash = hash_password("ClaveSegura2026!")
        self.assertTrue(stored_hash.startswith("pbkdf2_sha256$"))
        self.assertNotIn("ClaveSegura2026!", stored_hash)
        self.assertTrue(verify_password("ClaveSegura2026!", stored_hash))
        self.assertFalse(verify_password("ClaveIncorrecta", stored_hash))
        self.assertFalse(verify_password("ClaveSegura2026!", "texto_plano_invalido"))

    def test_basic_auth_header_validation(self) -> None:
        pw_hash = hash_password("utn_redes_123")
        valid_token = base64.b64encode(b"admin:utn_redes_123").decode("ascii")
        wrong_pass_token = base64.b64encode(b"admin:otra_clave").decode("ascii")
        wrong_user_token = base64.b64encode(b"intruso:utn_redes_123").decode("ascii")

        self.assertTrue(verify_basic_auth(f"Basic {valid_token}", "admin", pw_hash))
        self.assertFalse(verify_basic_auth(None, "admin", pw_hash))
        self.assertFalse(verify_basic_auth("", "admin", pw_hash))
        self.assertFalse(verify_basic_auth(f"Basic {wrong_pass_token}", "admin", pw_hash))
        self.assertFalse(verify_basic_auth(f"Basic {wrong_user_token}", "admin", pw_hash))
        self.assertFalse(verify_basic_auth("Bearer token_invalido", "admin", pw_hash))
        self.assertFalse(verify_basic_auth("Basic @@@no_es_base64@@@", "admin", pw_hash))

    def test_csrf_token_generation_and_validation(self) -> None:
        csrf = CSRFTokenManager(ttl_seconds=60)
        token = csrf.generate_token("admin")
        self.assertTrue(csrf.validate_token(token, "admin"))
        self.assertFalse(csrf.validate_token(token, "otro_usuario"))
        self.assertFalse(csrf.validate_token(token + "a", "admin"))
        self.assertFalse(csrf.validate_token(None, "admin"))

    def test_log_injection_sanitization(self) -> None:
        malicious = "/index.html HTTP/1.1\"\r\n[FAKE_LOG] 127.0.0.1 \"GET /admin"
        sanitized = sanitize_log_field(malicious)
        self.assertNotIn("\r", sanitized)
        self.assertNotIn("\n", sanitized)
        self.assertIn("\\r\\n", sanitized)


if __name__ == "__main__":
    unittest.main()
