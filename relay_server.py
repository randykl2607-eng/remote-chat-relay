from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, secrets, time, threading

HOSTS = {}  # code -> {token, queue, expires, attempts}
LOCK = threading.Lock()
TTL = 60 * 60

def reply(h, status, obj):
    raw = json.dumps(obj).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(raw)))
    h.end_headers(); h.wfile.write(raw)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return reply(self, 400, {"error":"bad json"})
        now = time.time()
        with LOCK:
            for c in list(HOSTS):
                if HOSTS[c]["expires"] < now: del HOSTS[c]
            if self.path == "/register":
                code, token = str(data.get("code","")), str(data.get("token",""))
                if len(code) != 6 or not code.isdigit() or len(token) < 32:
                    return reply(self, 400, {"error":"invalid registration"})
                HOSTS[code] = {"token":token,"queue":[],"expires":now+TTL,"attempts":0}
                return reply(self, 200, {"status":"registered"})
            if self.path == "/send":
                code, msg = str(data.get("code","")), str(data.get("message",""))
                rec = HOSTS.get(code)
                if not rec: return reply(self, 404, {"error":"invalid or expired API pairing code"})
                if not (1 <= len(msg) <= 256): return reply(self, 400, {"error":"message must be 1-256 characters"})
                if len(rec["queue"]) >= 50: return reply(self, 429, {"error":"queue full"})
                rec["queue"].append(msg); rec["expires"] = now+TTL
                return reply(self, 200, {"status":"SENT"})
            if self.path == "/poll":
                code, token = str(data.get("code","")), str(data.get("token",""))
                rec = HOSTS.get(code)
                if not rec or not secrets.compare_digest(rec["token"], token):
                    return reply(self, 403, {"error":"denied"})
                msgs = rec["queue"][:10]; del rec["queue"][:len(msgs)]; rec["expires"] = now+TTL
                return reply(self, 200, {"messages":msgs})
            if self.path == "/revoke":
                code, token = str(data.get("code","")), str(data.get("token",""))
                rec = HOSTS.get(code)
                if rec and secrets.compare_digest(rec["token"], token): del HOSTS[code]
                return reply(self, 200, {"status":"revoked"})
        reply(self, 404, {"error":"not found"})

if __name__ == "__main__":
    print("Remote Chat relay listening on 0.0.0.0:8080")
    print("For internet use, deploy behind HTTPS. Do not expose plain HTTP over the public internet.")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
