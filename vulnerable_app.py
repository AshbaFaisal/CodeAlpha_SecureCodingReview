"""
Simple Student Portal - Web Application
A basic Flask-based student management system.
NOTE: This file contains intentional security vulnerabilities for educational review.
"""

import sqlite3
import os
import pickle
import subprocess
import hashlib
from flask import Flask, request, render_template_string, session, redirect

app = Flask(__name__)
app.secret_key = "admin123"  # VULN-01: Hardcoded weak secret key

# Database setup
def get_db():
    conn = sqlite3.connect("students.db")
    return conn

# VULN-02: SQL Injection — user input directly embedded in query
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # Insecure: direct string interpolation into SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query)
    user = cur.fetchone()

    if user:
        session["user"] = username
        return redirect("/dashboard")
    return "Login failed", 401


# VULN-03: Storing passwords as plain MD5 (weak hashing)
@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # Insecure: MD5 is cryptographically broken for passwords
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(f"INSERT INTO users VALUES ('{username}', '{hashed}')")
    conn.commit()
    return "Registered!", 200


# VULN-04: Cross-Site Scripting (XSS) — unsanitized user input in HTML
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Insecure: user input rendered directly into HTML without escaping
    html = f"""
    <html><body>
    <h2>Search results for: {query}</h2>
    </body></html>
    """
    return render_template_string(html)


# VULN-05: Insecure Deserialization — pickle with user-supplied data
@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = request.form.get("profile_data")
    # Insecure: deserializing untrusted data with pickle allows remote code execution
    profile = pickle.loads(bytes.fromhex(data))
    return str(profile)


# VULN-06: Command Injection — user input passed to shell
@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Insecure: user-controlled input in shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


# VULN-07: Path Traversal — arbitrary file read
@app.route("/download")
def download():
    filename = request.args.get("file")
    # Insecure: no validation, allows reading any file on the server
    filepath = os.path.join("/var/app/uploads", filename)
    with open(filepath, "r") as f:
        return f.read()


# VULN-08: Sensitive data in URL / no authentication check
@app.route("/student/<student_id>/grades")
def get_grades(student_id):
    # Insecure: no check that the logged-in user owns this student_id (IDOR)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM grades WHERE student_id={student_id}")
    return str(cur.fetchall())


# VULN-09: Debug mode enabled in production
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")  # VULN-09: debug=True exposes debugger; host=0.0.0.0 exposes to all interfaces
