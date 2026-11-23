from __future__ import annotations

import html
import secrets
from flask import Flask, make_response, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
users = {"admin": {"password": "admin123", "role": "admin"}, "user1": {"password": "user123", "role": "user"}}

def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def validate_csrf_token(token: str | None) -> bool:
    expected = session.get("csrf_token")
    return bool(token and expected and secrets.compare_digest(token, expected))

@app.route("/")
def index():
    token = html.escape(generate_csrf_token())
    return f'''<h1>AI Research Platform</h1>
<form action="/login" method="POST"><input name="username"><input name="password" type="password"><input type="hidden" name="csrf_token" value="{token}"><button type="submit">Login</button></form>
<p><a href="/search?q=test">Search</a></p>'''

@app.route("/login", methods=["POST"])
def login():
    username, password = request.form.get("username", ""), request.form.get("password", "")
    user = users.get(username)
    if user and secrets.compare_digest(user["password"], password):
        session.clear(); session["username"], session["role"] = username, user["role"]
        generate_csrf_token()
        return make_response(f"Welcome {html.escape(username)}!")
    return "Invalid credentials", 401

@app.route("/search")
def search():
    query = html.escape(request.args.get("q", ""))
    return f"<!DOCTYPE html><html><head><title>Search</title></head><body><h1>Search Results for: {query}</h1><p>You searched for: {query}</p></body></html>"

@app.route("/change_email", methods=["POST"])
def change_email():
    if "username" not in session: return "Not authenticated", 401
    if not validate_csrf_token(request.form.get("csrf_token")): return "Invalid CSRF token", 403
    return f"Email changed to {html.escape(request.form.get('email', ''))} for user {html.escape(session['username'])}"

@app.route("/profile")
def profile():
    if "username" not in session: return "Not authenticated", 401
    return f"Profile of {html.escape(session['username'])}"

@app.route("/transfer", methods=["POST"])
def transfer():
    if "username" not in session: return "Not authenticated", 401
    if not validate_csrf_token(request.form.get("csrf_token")): return "Invalid CSRF token", 403
    return f"Transferred {html.escape(request.form.get('amount', ''))} to {html.escape(request.form.get('to', ''))}"

if __name__ == "__main__": app.run(debug=False)
