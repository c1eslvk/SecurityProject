from .base import RBACTestCase


class SecurityHeaderTests(RBACTestCase):
    def test_clickjacking_and_content_type_headers_present(self):
        res = self.client.get("/")
        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")

    def test_csp_header_present_and_locks_down_framing(self):
        res = self.client.get("/")
        csp = res.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)

    def test_referrer_policy_present(self):
        res = self.client.get("/")
        self.assertEqual(res.headers.get("Referrer-Policy"), "same-origin")
