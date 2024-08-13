from flask import Flask, request, jsonify, render_template_string
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os
import requests

app = Flask(__name__)

# Define the fixed base URL
BASE_URL = "http://localhost:5003"  # Change this to your fixed base URL

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///api_security.db')
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()

# API Model
class API(Base):
    __tablename__ = 'apis'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    endpoint = Column(String(200), nullable=False)
    method = Column(String(10), nullable=False)
    created_at = Column(DateTime, default=func.current_timestamp())
    security_checks = relationship('SecurityCheck', back_populates='api')

# SecurityCheck Model
class SecurityCheck(Base):
    __tablename__ = 'security_checks'
    id = Column(Integer, primary_key=True)
    api_id = Column(Integer, ForeignKey('apis.id'), nullable=False)
    check_name = Column(String(100), nullable=False)
    result = Column(String(50))
    resolution = Column(String(500))  # Added column for resolution
    created_at = Column(DateTime, default=func.current_timestamp())
    api = relationship('API', back_populates='security_checks')

# Create the tables in the database
Base.metadata.create_all(engine)

@app.route('/api/inventory', methods=['POST'])
def add_api():
    data = request.get_json()
    new_api = API(name=data['name'], endpoint=data['endpoint'], method=data['method'])
    session.add(new_api)
    session.commit()
    return jsonify(new_api.id), 201

@app.route('/api/security-checks', methods=['POST'])
def perform_security_check():
    data = request.get_json()
    api_id = data.get('api_id')
    if not api_id:
        return jsonify({'error': 'API ID is required'}), 400

    api = session.query(API).get(api_id)
    if not api:
        return jsonify({'error': 'API not found'}), 404

    url = f"{BASE_URL}/{api.endpoint}"
    checks = [
        ('SQL Injection', check_sql_injection(url)),
        ('Path Traversal', check_path_traversal(url)),
        ('File Upload', check_file_upload(url)),
        ('Open Redirect', check_open_redirect(url)),
        ('Arbitrary File Download', check_file_download(url)),
    ]

    results = []
    for check_name, (result, resolution) in checks:
        security_check = SecurityCheck(api_id=api_id, check_name=check_name, result=result, resolution=resolution)
        session.add(security_check)
        results.append({'api_name': api.name, 'url': url, 'check_name': check_name, 'result': result, 'resolution': resolution})
    
    session.commit()

    return jsonify(results), 201

@app.route('/dashboard')
def dashboard():
    apis = session.query(API).all()
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>API Inventory Dashboard</title>
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="mb-4">API Inventory Dashboard</h1>
            <table class="table table-bordered table-striped">
                <thead class="thead-dark">
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Endpoint</th>
                        <th>Method</th>
                        <th>Created At</th>
                    </tr>
                </thead>
                <tbody>
                    {% for api in apis %}
                    <tr>
                        <td>{{ api.id }}</td>
                        <td>{{ api.name }}</td>
                        <td>{{ api.endpoint }}</td>
                        <td>{{ api.method }}</td>
                        <td>{{ api.created_at }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(template, apis=apis)

# Security check functions with enhanced security and resolutions

def check_sql_injection(url):
    payload = {'username': 'admin', 'password': "' OR '1'='1"}
    try:
        response = requests.post(url, json=payload)
        if 'Login successful' in response.text:
            return 'Vulnerable', 'Use parameterized queries or ORM to prevent SQL injection.'
        else:
            return 'Secure', None
    except requests.RequestException:
        return 'Failed to reach URL', None

def check_path_traversal(url):
    try:
        payload = {'filename': '../../etc/passwd'}
        response = requests.get(url, params=payload)
        if 'root' in response.text:
            return 'Vulnerable', 'Validate and sanitize file paths to prevent directory traversal.'
        else:
            return 'Secure', None
    except requests.RequestException:
        return 'Failed to reach URL', None

def check_file_upload(url):
    try:
        files = {'file': ('malicious.php', '<?php phpinfo(); ?>')}
        response = requests.post(url, files=files)
        if 'File uploaded successfully' in response.text:
            return 'Vulnerable', 'Restrict allowed file types and validate uploaded files.'
        else:
            return 'Secure', None
    except requests.RequestException:
        return 'Failed to reach URL', None

def check_open_redirect(url):
    try:
        payload = {'url': 'http://malicious.com'}
        response = requests.get(url, params=payload, allow_redirects=False)
        if response.status_code == 302 and 'redirect_url' in response.json():
            return 'Vulnerable', 'Validate and restrict URL redirects to prevent open redirects.'
        else:
            return 'Secure', None
    except requests.RequestException:
        return 'Failed to reach URL', None

def check_file_download(url):
    try:
        filename = 'malicious.php'
        response = requests.get(f"{url}/{filename}")
        if response.status_code == 200 and 'phpinfo()' in response.text:
            return 'Vulnerable', 'Restrict file download paths and validate file names.'
        else:
            return 'Secure', None
    except requests.RequestException:
        return 'Failed to reach URL', None

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
