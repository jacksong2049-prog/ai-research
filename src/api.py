from __future__ import annotations
from flask import Flask, jsonify, request
from .auth import UserManager, normalize_email
app = Flask(__name__)
user_manager = UserManager()

def _credentials():
    payload = request.get_json(silent=True) or request.form
    return payload.get("email", ""), payload.get("password", "")

@app.post("/register")
def register():
    email, password = _credentials()
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400
    try: user = user_manager.create_user(normalize_email(email), password)
    except ValueError as exc: return jsonify({"error": str(exc)}), 400
    return jsonify({"message": "User registered successfully", "email": user.email}), 201

@app.post("/login")
def login():
    email, password = _credentials()
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400
    try: user = user_manager.authenticate(normalize_email(email), password)
    except ValueError: user = None
    if user is None: return jsonify({"error": "Invalid email or password"}), 401
    return jsonify({"message": "Login successful", "email": user.email})

if __name__ == "__main__": app.run(debug=False)
