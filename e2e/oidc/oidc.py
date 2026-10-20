import base64, json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "http://oidc:8000"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key().public_numbers()
b64 = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
JWKS = {"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": b64(pub.n), "e": b64(pub.e)}]}

class H(BaseHTTPRequestHandler):
    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/.well-known/openid-configuration":
            return self._json({"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks", "authorization_endpoint": f"{ISSUER}/auth", "token_endpoint": f"{ISSUER}/token"})
        if u.path == "/jwks":
            return self._json(JWKS)
        if u.path == "/token":
            claims = json.loads(parse_qs(u.query).get("claims", ["{}"])[0])
            now = int(time.time())
            claims = {"iss": ISSUER, "sub": "test", "azp": "eodc-connect", "typ": "Bearer", "iat": now, "exp": now + 3600, **claims}
            return self._json({"access_token": jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})})
        self.send_response(404); self.end_headers()

ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
