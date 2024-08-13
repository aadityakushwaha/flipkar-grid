from flask import Flask, request, jsonify, send_file
import sqlite3
import os

app = Flask(__name__)

# In-memory database setup
DATABASE = 'vulnerable.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/login', methods=['POST'])
def login():
    """Vulnerable login endpoint with SQL Injection."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # SQL Injection vulnerability
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/upload', methods=['POST'])
def upload_file():
    """Vulnerable file upload endpoint."""
    file = request.files.get('file')
    if file:
        file.save(os.path.join('/tmp', file.filename))  # Unsafe file saving
        return jsonify({"message": "File uploaded successfully"}), 200
    return jsonify({"message": "No file uploaded"}), 400

@app.route('/read-file', methods=['GET'])
def read_file():
    """Path Traversal vulnerability."""
    filename = request.args.get('filename')
    try:
        with open(os.path.join('/tmp', filename), 'r') as f:
            content = f.read()
        return jsonify({"content": content}), 200
    except FileNotFoundError:
        return jsonify({"message": "File not found"}), 404

@app.route('/redirect', methods=['GET'])
def redirect_vulnerable():
    """Open Redirect vulnerability."""
    redirect_url = request.args.get('url')
    return jsonify({"redirect_url": redirect_url}), 302

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """Arbitrary File Download."""
    return send_file(os.path.join('/tmp', filename), as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5003)
