import base64
import unittest

from wgsub.parse import parse_blob

PRIV = "knYNDw4VHQylar8b+Sv/h6pEt/o2WgE0ZRkiWD/6nQA="
PUB = "YZ/uzGTLqM40Z5pubNvSD9xi7cgq7bWSls9Nj2r2Vuc="

INI = f"""# Name = WG Noisy
[Interface]
PrivateKey = {PRIV}
Address = 172.16.0.2/32, 2606:4700:110:806a:17d6:1a21:54c5:1966/128
DNS = 8.8.8.8
MTU = 1280
Jc = 7
Jmin = 61
Jmax = 83
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 8.6.112.10:1701
PersistentKeepalive = 25
"""

INI_I1 = f"""[Interface]
PrivateKey = {PRIV}
Address = 10.0.0.2/32
Jc = 4
I1 = <r 2><b 0x0100>
[Peer]
PublicKey = {PUB}
Endpoint = [2001:db8::1]:51820
"""


class ParseTests(unittest.TestCase):
    def test_ini_keeps_obfuscation_and_does_not_invent_fields(self):
        profiles = parse_blob(INI)
        self.assertEqual(len(profiles), 1)
        uri = profiles[0].uri()
        self.assertTrue(uri.startswith("wireguard://"))
        self.assertIn("@8.6.112.10:1701?", uri)
        self.assertIn("jc=7", uri)
        self.assertIn("jmin=61", uri)
        self.assertIn("s1=0", uri)
        self.assertIn("h1=1", uri)
        self.assertIn("keepalive=25", uri)
        self.assertIn("mtu=1280", uri)
        self.assertIn("dns=8.8.8.8", uri)
        self.assertIn("%2F32", uri)
        self.assertNotIn("i1=", uri)
        self.assertNotIn("reserved=", uri)
        self.assertNotIn("raw.githubusercontent.com", uri)
        self.assertTrue(uri.endswith("#WG%20Noisy"))

    def test_ipv6_endpoint_and_i1(self):
        uri = parse_blob(INI_I1)[0].uri()
        self.assertIn("@[2001:db8::1]:51820?", uri)
        self.assertIn("i1=%3Cr%202%3E%3Cb%200x0100%3E", uri)

    def test_existing_uri_roundtrip_keeps_extra_keys(self):
        raw = (
            "wireguard://"
            "knYNDw4VHQylar8b%2BSv%2Fh6pEt%2Fo2WgE0ZRkiWD%2F6nQA%3D"
            "@engage.cloudflareclient.com:2408"
            "?publickey=YZ%2FuzGTLqM40Z5pubNvSD9xi7cgq7bWSls9Nj2r2Vuc%3D"
            "&address=172.16.0.2&reserved=178,19,18&jc=4&jmin=64&jmax=256"
            "&keepalive=15&mtu=1340&cfwarp=wg2#test"
        )
        uri = parse_blob(raw)[0].uri()
        self.assertIn("reserved=178%2C19%2C18", uri)
        self.assertIn("cfwarp=wg2", uri)
        self.assertIn("jc=4", uri)

    def test_mixed_blob_dedupes_and_skips_junk(self):
        blob = INI + "\n\nvless://not-wg\n" + INI
        self.assertEqual(len(parse_blob(blob)), 1)

    def test_base64_wrapped_conf(self):
        wrapped = base64.b64encode(INI.encode()).decode()
        self.assertEqual(len(parse_blob(wrapped)), 1)

    def test_rejects_short_key(self):
        bad = INI.replace(PRIV, "aaaa")
        self.assertEqual(parse_blob(bad), [])


if __name__ == "__main__":
    unittest.main()
