from __future__ import annotations
import hashlib, hmac, json, os, secrets
from datetime import datetime, timezone
import websockets
ALLOWED_ORIGINS = [x.strip().rstrip('/') for x in os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,https://app.example.com').split(',') if x.strip()]
class SessionManager:
    def __init__(self): self.sessions, self._secret = {}, secrets.token_bytes(32)
    def create_session(self, client_info):
        token, timestamp = secrets.token_urlsafe(32), datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        digest = hmac.new(self._secret, f"{client_info.get('ip','unknown')}:{timestamp}:{token}".encode(), hashlib.sha256).hexdigest()[:16]
        sid = f'sess_{digest}_{timestamp}_{token[:8]}'; self.sessions[sid] = {'created_at': datetime.now(timezone.utc), 'client_info': dict(client_info), 'data': {}}
        return {'id': sid, 'session_id': sid}
    def get_session(self, sid): return self.sessions.get(sid)
    def validate_session(self, sid, client_ip):
        s = self.sessions.get(sid); return bool(s and hmac.compare_digest(s['client_info'].get('ip', ''), client_ip))
    def update_session(self, sid, data):
        if sid in self.sessions: self.sessions[sid]['data'].update(data)
session_manager = SessionManager()
def validate_origin(websocket): return getattr(websocket, 'request_headers', {}).get('Origin', '').rstrip('/') in ALLOWED_ORIGINS
def get_client_ip(websocket):
    headers = getattr(websocket, 'request_headers', {}); forwarded = headers.get('X-Forwarded-For')
    if forwarded: return forwarded.split(',', 1)[0].strip()
    remote = getattr(websocket, 'remote_address', None); return remote[0] if remote else 'unknown'
async def handle_client(websocket, path=None):
    if not validate_origin(websocket): await websocket.close(code=1008, reason='Invalid origin'); return
    client_ip, session = get_client_ip(websocket), session_manager.create_session({'ip': get_client_ip(websocket)})
    await websocket.send(json.dumps({'type': 'session', 'session_id': session['session_id']}))
    try:
        async for message in websocket:
            try: data = json.loads(message)
            except (TypeError, json.JSONDecodeError): await websocket.send(json.dumps({'error': 'Invalid JSON'})); continue
            if not session_manager.validate_session(session['id'], client_ip): await websocket.send(json.dumps({'error': 'Session validation failed'})); continue
            action = data.get('action')
            if action == 'ping': response = {'type': 'pong'}
            elif action == 'get_data': response = {'type': 'data', 'data': session_manager.get_session(session['id'])['data']}
            else: response = {'error': 'Unknown action'}
            await websocket.send(json.dumps(response))
    finally: session_manager.sessions.pop(session['id'], None)
async def main():
    async with websockets.serve(handle_client, '0.0.0.0', 8765, origins=ALLOWED_ORIGINS): await __import__('asyncio').Future()
if __name__ == '__main__':
    import asyncio; asyncio.run(main())
