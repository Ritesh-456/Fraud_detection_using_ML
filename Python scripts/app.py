import io
import sys
import os
import time

# Add the project root to the sys.path to import modules from helpers and Notebook
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir) # Go up one level from 'Python scripts'
# Assuming 'helpers', 'Notebook', 'CSS', and 'Script' are directly under project_root
sys.path.append(project_root)


from PIL import Image
import pyzbar.pyzbar
# Import send_from_directory to serve static files
from flask import Flask, request, jsonify, redirect, url_for, session, send_from_directory
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Import database handler and logger
from helpers.db import handler as db_handler
from helpers.log import logger as log

# Import the fraud detection model
from Notebook.fraud_detection_model_ import HybridFraudDetector

import qrcode
import base64
import json


app = Flask(__name__)
# IMPORTANT: Replace with a real secret key in production!
# Use the secret key you generated and placed here in the previous step
# Ensure this key is UNIQUE and SECRET for security.
app.config['SECRET_KEY'] = 'a25c29160c03ba0aae322a3b20ce454d44276466c3cf4b30' # <--- MAKE SURE THIS IS YOUR REAL SECRET KEY
CORS(app) # Be mindful of CORS in production, restrict origins if needed

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
# login_manager.login_view = 'login' # We handle 401/redirects in frontend now


# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, username):
        self.id = id
        self.email = email
        self.username = username

    def get_id(self):
        return str(self.id)

# User loader function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user_data = db_handler.find_user_by_id(user_id)
    if user_data and 'email' in user_data and 'username' in user_data:
        return User(user_data['id'], user_data['email'], user_data['username'])
    return None


# --- Fraud Detector Initialization ---
detector = HybridFraudDetector()


# --- Route to serve the index.html file ---
# Define the directory where index.html is located (project root)
root_dir = os.path.join(project_root) # This is the main directory containing index.html, CSS, Script


@app.route('/')
def serve_index():
    """Serves the index.html file from the project root directory."""
    print(f"[INFO] Serving index.html from {root_dir}", file=sys.stderr)
    return send_from_directory(root_dir, 'index.html')

# --- Routes to serve static CSS and JS files ---
# Use <path:filename> to handle potential subdirectories if needed
@app.route('/CSS/<path:filename>')
def serve_css(filename):
    """Serves CSS files from the CSS directory in the project root."""
    css_dir = os.path.join(root_dir, 'CSS')
    print(f"[INFO] Serving CSS file: {filename} from {css_dir}", file=sys.stderr)
    return send_from_directory(css_dir, filename)

@app.route('/Script/<path:filename>')
def serve_script(filename):
    """Serves JavaScript files from the Script directory in the project root."""
    script_dir = os.path.join(root_dir, 'Script')
    print(f"[INFO] Serving Script file: {filename} from {script_dir}", file=sys.stderr)
    return send_from_directory(script_dir, filename)


# --- Helper function to generate QR Image Data URL ---
def create_qr_image_data_url(url):
    """Generates a data URL for a QR code image."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4,
            border=1,
        )
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_io = io.BytesIO()
        img.save(img_io, format="PNG")
        img_base64 = base64.b64encode(img_io.getvalue()).decode()
        data_url = f"data:image/png;base64,{img_base64}"
        return data_url
    except Exception as e:
        log.log_error(f"Error generating QR image: {e}", "create_qr_image_data_url")
        return None


# --- Authentication Routes ---

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not email or not username or not password:
        print("[ERROR] Registration attempt with missing email, username, or password", file=sys.stderr)
        return jsonify({'error': 'Email, username, and password are required'}), 400

    if db_handler.find_user_by_email(email):
        print(f"[ERROR] Registration attempt for existing email: {email}", file=sys.stderr)
        return jsonify({'error': 'Email already exists'}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    user_id = db_handler.create_user(email, username, hashed_password)

    if user_id:
        print(f"[INFO] User registered successfully: {email} ({username}) (ID: {user_id})", file=sys.stderr)
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201
    else:
        print(f"[ERROR] Failed to create user in database: {email}", file=sys.stderr)
        return jsonify({'error': 'Failed to register user. Username or email might already exist.'}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        print("[ERROR] Login attempt with missing email or password", file=sys.stderr)
        return jsonify({'error': 'Email and password are required'}), 400

    user_data = db_handler.find_user_by_email(email)

    if user_data and 'id' in user_data and 'email' in user_data and 'username' in user_data and 'password_hash' in user_data:
         if check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['email'], user_data['username'])
            login_user(user)
            print(f"[INFO] User logged in successfully: {user.email} ({user.username}) (ID: {user.id})", file=sys.stderr)
            return jsonify({'success': True, 'message': 'Logged in successfully', 'email': user.email, 'username': user.username}), 200
         else:
            print(f"[ERROR] Failed login attempt for email: {email} (incorrect password)", file=sys.stderr)
            return jsonify({'error': 'Invalid email or password'}), 401
    else:
        print(f"[ERROR] Failed login attempt: User with email {email} not found", file=sys.stderr)
        return jsonify({'error': 'Invalid email or password'}), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user_email = current_user.email
    user_id = current_user.id
    logout_user()
    print(f"[INFO] User logged out: {user_email} (ID: {user_id})", file=sys.stderr)
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/status', methods=['GET'])
def status():
    """Check if the user is logged in and return user info."""
    if current_user.is_authenticated:
        # Return username and email
        return jsonify({'is_logged_in': True, 'email': current_user.email, 'username': current_user.username}), 200
    else:
        return jsonify({'is_logged_in': False}), 200


# --- Analysis Routes (Modified to Save History) ---

@app.route('/analyze-url', methods=['POST'])
@login_required
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            print("[ERROR] Analyze URL request missing URL", file=sys.stderr)
            return jsonify({'error': 'URL is required'}), 400

        result = detector.analyze_url(url)

        if result:
            user_id = current_user.id
            save_success = db_handler.save_analysis_result(user_id, 'url', url, result)
            if not save_success:
                 print(f"[ERROR] Failed to save URL analysis result for user {user_id}", file=sys.stderr)

            return jsonify(result)
        else:
            print(f"[ERROR] Failed to analyze URL: {url}", file=sys.stderr)
            return jsonify({'error': 'Failed to analyze URL'}), 500

    except Exception as e:
        print(f"[ERROR] Error during URL analysis: {e}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500

@app.route('/analyze-qr', methods=['POST'])
@login_required
def analyze_qr():
    try:
        if 'file' not in request.files:
            print("[ERROR] Analyze QR request missing file", file=sys.stderr)
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
             print("[ERROR] Analyze QR request received empty file", file=sys.stderr)
             return jsonify({'error': 'No selected file'}), 400

        img = Image.open(file)
        qr_codes = pyzbar.pyzbar.decode(img)

        if not qr_codes:
            print("[ERROR] No QR code found in uploaded image", file=sys.stderr)
            return jsonify({'error': 'No QR code found'}), 400

        url = qr_codes[0].data.decode('utf-8')

        result = detector.analyze_url(url)

        if result:
             result['url'] = url

             user_id = current_user.id
             item_data = f"{file.filename} ({url})" if url else file.filename
             save_success = db_handler.save_analysis_result(user_id, 'qr', item_data, result)
             if not save_success:
                  print(f"[ERROR] Failed to save QR analysis result for user {user_id}", file=sys.stderr)

             return jsonify(result)
        else:
             print(f"[ERROR] Failed to analyze decoded QR URL: {url}", file=sys.stderr)
             return jsonify({'error': 'Failed to analyze QR content'}), 500

    except Exception as e:
        print(f"[ERROR] Error during QR analysis: {e}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500


# --- History Routes ---

@app.route('/history', methods=['GET'])
@login_required
def get_history():
    try:
        user_id = current_user.id
        history_items = db_handler.get_user_history(user_id)
        history_items = history_items if isinstance(history_items, list) else []
        return jsonify(history_items), 200
    except Exception as e:
        print(f"[ERROR] Error fetching history for user {current_user.id}: {e}", file=sys.stderr)
        return jsonify({'error': 'Failed to fetch history'}), 500

@app.route('/delete-history-item/<int:item_id>', methods=['DELETE'])
@login_required
def delete_history_item(item_id):
    try:
        user_id = current_user.id
        success = db_handler.delete_history_item(item_id, user_id)
        if success:
            return jsonify({'success': True, 'message': 'History item deleted'}), 200
        else:
            return jsonify({'error': 'History item not found or could not be deleted'}), 404
    except Exception as e:
        print(f"[ERROR] Error deleting history item {item_id} for user {current_user.id}: {e}", file=sys.stderr)
        return jsonify({'error': 'Failed to delete history item'}), 500

@app.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    try:
        user_id = current_user.id
        success = db_handler.clear_user_history(user_id)
        if success:
            return jsonify({'success': True, 'message': 'History cleared'}), 200
        else:
            return jsonify({'error': 'Failed to clear history'}), 500
    except Exception as e:
        print(f"[ERROR] Error clearing history for user {current_user.id}: {e}", file=sys.stderr)
        return jsonify({'error': 'Failed to clear history'}), 500


# --- QR Code Generation Endpoint ---
@app.route('/generate-qr', methods=['POST'])
def generate_qr():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        qr_data_url = create_qr_image_data_url(url)
        if qr_data_url:
            return jsonify({'data': qr_data_url})
        else:
            return jsonify({'error': 'Failed to generate QR code'}), 500
    except Exception as e:
        print(f"[ERROR] Error during QR generation: {e}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500


# --- Main Execution Block ---
if __name__ == '__main__':
    print("Initializing Fraud Detector Model...")
    if detector.train_model():
         print("Model training successful.")
    else:
         print("Model training failed. Application may not function correctly.")

    print("Starting Flask App...")
    app.run(debug=True) # debug=True is useful for development