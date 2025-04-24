import io
import sys
import os # Import os to access environment variables
import qrcode
import base64
import json
import time

# Import load_dotenv from python-dotenv
from dotenv import load_dotenv

# Determine the path to the project root from the location of app.py
# app.py is in 'Python scripts'. Project root is one directory up.
current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_script_dir)

# Load environment variables from the .env file located at the project root
dotenv_path = os.path.join(project_root, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    print(f"Warning: .env file not found at {dotenv_path}. Secrets must be set in the environment.", file=sys.stderr)


# Add the project root to the sys.path to import modules from helpers and Notebook
# This is already correctly calculated above
sys.path.append(project_root)


from PIL import Image
import pyzbar.pyzbar
# Import send_from_directory to serve static files
from flask import Flask, request, jsonify, redirect, url_for, session, send_from_directory
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Import database handler and logger
# Assuming helpers is directly under project_root
from helpers.db import handler as db_handler
from helpers.log import logger as log

# Import the fraud detection model
# Assuming Notebook is directly under project_root
from Notebook.fraud_detection_model_ import HybridFraudDetector


app = Flask(__name__)
# IMPORTANT: Read SECRET_KEY from environment variable
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') # <--- Read SECRET_KEY from environment

# Add a check and exit if SECRET_KEY is not set (crucial for security)
if not app.config['SECRET_KEY']:
    print("Error: SECRET_KEY is not set. Application cannot run securely without it.", file=sys.stderr)
    print("Please set SECRET_KEY in your .env file or environment variables.", file=sys.stderr)
    sys.exit(1) # Exit if SECRET_KEY is missing


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
        # Make sure the keys in user_data match what User expects ('id', 'email', 'username')
        return User(user_data.get('id'), user_data.get('email'), user_data.get('username'))
    return None


# --- Fraud Detector Initialization ---
# This assumes the Notebook path is correctly added to sys.path
detector = HybridFraudDetector()


# --- Route to serve the index.html file ---
# Define the directory where index.html is located (project root)
# project_root is already correctly calculated above
root_dir = project_root


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
    # print(f"[INFO] Serving CSS file: {filename} from {css_dir}", file=sys.stderr) # Uncomment for debugging
    return send_from_directory(css_dir, filename)

@app.route('/Script/<path:filename>')
def serve_script(filename):
    """Serves JavaScript files from the Script directory in the project root."""
    script_dir = os.path.join(root_dir, 'Script')
    # print(f"[INFO] Serving Script file: {filename} from {script_dir}", file=sys.stderr) # Uncomment for debugging
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

    # Check if user already exists using the database handler
    if db_handler.find_user_by_email(email):
        print(f"[ERROR] Registration attempt for existing email: {email}", file=sys.stderr)
        return jsonify({'error': 'Email already exists'}), 409

    # Hash the password before storing
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Create the user in the database using the handler
    user_id = db_handler.create_user(email, username, hashed_password)

    if user_id:
        print(f"[INFO] User registered successfully: {email} ({username}) (ID: {user_id})", file=sys.stderr)
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201
    else:
        # db_handler.create_user returns None on failure (e.g., duplicate username/email caught in handler)
        print(f"[ERROR] Failed to create user in database for email: {email}", file=sys.stderr)
        return jsonify({'error': 'Failed to register user. Username or email might already exist.'}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        print("[ERROR] Login attempt with missing email or password", file=sys.stderr)
        return jsonify({'error': 'Email and password are required'}), 400

    # Find the user by email using the database handler
    user_data = db_handler.find_user_by_email(email)

    # Check if user exists and verify password
    if user_data and 'id' in user_data and 'email' in user_data and 'username' in user_data and 'password_hash' in user_data:
         # Verify the hashed password using werkzeug
         if check_password_hash(user_data['password_hash'], password):
            # Log in the user using Flask-Login
            user = User(user_data['id'], user_data['email'], user_data['username'])
            login_user(user)
            print(f"[INFO] User logged in successfully: {user.email} ({user.username}) (ID: {user.id})", file=sys.stderr)
            return jsonify({'success': True, 'message': 'Logged in successfully', 'email': user.email, 'username': user.username}), 200
         else:
            # Password does not match
            print(f"[ERROR] Failed login attempt for email: {email} (incorrect password)", file=sys.stderr)
            return jsonify({'error': 'Invalid email or password'}), 401
    else:
        # User not found
        print(f"[ERROR] Failed login attempt: User with email {email} not found", file=sys.stderr)
        return jsonify({'error': 'Invalid email or password'}), 401


@app.route('/logout', methods=['POST'])
@login_required # Requires user to be logged in to access this route
def logout():
    # Log out the current user using Flask-Login
    user_email = current_user.email
    user_id = current_user.id
    logout_user()
    print(f"[INFO] User logged out: {user_email} (ID: {user_id})", file=sys.stderr)
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/status', methods=['GET'])
def status():
    """Check if the user is logged in and return user info."""
    if current_user.is_authenticated:
        # Return username and email if the user is authenticated
        return jsonify({'is_logged_in': True, 'email': current_user.email, 'username': current_user.username}), 200
    else:
        # Return not logged in if the user is anonymous
        return jsonify({'is_logged_in': False}), 200


# --- Analysis Routes (Uses Fraud Detector and Saves History) ---

@app.route('/analyze-url', methods=['POST'])
@login_required # Requires user to be logged in to use this feature
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            print("[ERROR] Analyze URL request missing URL", file=sys.stderr)
            return jsonify({'error': 'URL is required'}), 400

        # Use the fraud detector model
        result = detector.analyze_url(url)

        if result:
            # Save the analysis result to the database history
            user_id = current_user.id
            save_success = db_handler.save_analysis_result(user_id, 'url', url, result)
            if not save_success:
                 print(f"[ERROR] Failed to save URL analysis result for user {user_id}", file=sys.stderr)

            return jsonify(result)
        else:
            print(f"[ERROR] Failed to analyze URL: {url}", file=sys.stderr)
            # Return a more specific error if analysis failed
            return jsonify({'error': 'Failed to analyze URL', 'details': 'Model returned no result'}), 500

    except Exception as e:
        # Catch any unexpected errors during analysis
        print(f"[ERROR] Error during URL analysis: {e}", file=sys.stderr)
        return jsonify({'error': 'An error occurred during URL analysis', 'details': str(e)}), 500

@app.route('/analyze-qr', methods=['POST'])
@login_required # Requires user to be logged in to use this feature
def analyze_qr():
    try:
        # Check if the request contains a file
        if 'file' not in request.files:
            print("[ERROR] Analyze QR request missing file", file=sys.stderr)
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        # Check if a file was actually selected
        if file.filename == '':
             print("[ERROR] Analyze QR request received empty file", file=sys.stderr)
             return jsonify({'error': 'No selected file'}), 400

        # Read the image file and decode QR codes
        img = Image.open(file)
        qr_codes = pyzbar.pyzbar.decode(img)

        # Check if any QR codes were found
        if not qr_codes:
            print("[ERROR] No QR code found in uploaded image", file=sys.stderr)
            return jsonify({'error': 'No QR code found'}), 400

        # Assume the first found QR code contains the URL
        url = qr_codes[0].data.decode('utf-8')
        print(f"[INFO] Decoded QR code URL: {url}", file=sys.stderr)

        # Use the fraud detector to analyze the decoded URL
        result = detector.analyze_url(url)

        if result:
             # Add the decoded URL to the result for the frontend
             result['url'] = url

             # Save the analysis result to the database history
             user_id = current_user.id
             # Include filename and URL in item_data for history
             item_data = f"{file.filename} ({url})" if url else file.filename
             save_success = db_handler.save_analysis_result(user_id, 'qr', item_data, result)
             if not save_success:
                  print(f"[ERROR] Failed to save QR analysis result for user {user_id}", file=sys.stderr)

             return jsonify(result)
        else:
             print(f"[ERROR] Failed to analyze decoded QR URL: {url}", file=sys.stderr)
             # Return a more specific error if analysis failed
             return jsonify({'error': 'Failed to analyze QR content', 'details': 'Model returned no result'}), 500

    except Exception as e:
        # Catch any unexpected errors during QR analysis
        print(f"[ERROR] Error during QR analysis: {e}", file=sys.stderr)
        return jsonify({'error': 'An error occurred during QR analysis', 'details': str(e)}), 500


# --- History Routes (Requires Login) ---

@app.route('/history', methods=['GET'])
@login_required # Requires user to be logged in
def get_history():
    try:
        # Fetch history for the current logged-in user
        user_id = current_user.id
        history_items = db_handler.get_user_history(user_id)
        # Ensure history_items is a list even if the handler returns None or other type on error
        history_items = history_items if isinstance(history_items, list) else []
        # print(f"[INFO] Returning {len(history_items)} history items for user {user_id}", file=sys.stderr) # Uncomment for debugging
        return jsonify(history_items), 200
    except Exception as e:
        # Catch any unexpected errors during history fetch
        print(f"[ERROR] Error fetching history for user {current_user.id}: {e}", file=sys.stderr)
        return jsonify({'error': 'Failed to fetch history'}), 500

@app.route('/delete-history-item/<int:item_id>', methods=['DELETE'])
@login_required # Requires user to be logged in
def delete_history_item(item_id):
    try:
        # Delete a specific history item for the current logged-in user
        user_id = current_user.id
        success = db_handler.delete_history_item(item_id, user_id)
        if success:
            print(f"[INFO] Deleted history item {item_id} for user {user_id}", file=sys.stderr)
            return jsonify({'success': True, 'message': 'History item deleted'}), 200
        else:
            # Return 404 if the item was not found or didn't belong to the user
            print(f"[WARNING] Attempted to delete non-existent or non-owned history item {item_id} for user {user_id}", file=sys.stderr)
            return jsonify({'error': 'History item not found or could not be deleted'}), 404
    except ValueError:
        print(f"[ERROR] Invalid item ID format for delete request: {item_id}", file=sys.stderr)
        return jsonify({'error': 'Invalid item ID format'}), 400
    except Exception as e:
        # Catch any unexpected errors during deletion
        print(f"[ERROR] Error deleting history item {item_id} for user {current_user.id}: {e}", file=sys.stderr)
        return jsonify({'error': 'Failed to delete history item'}), 500

@app.route('/clear-history', methods=['POST'])
@login_required # Requires user to be logged in
def clear_history():
    try:
        # Clear all history for the current logged-in user
        user_id = current_user.id
        success = db_handler.clear_user_history(user_id)
        if success:
            print(f"[INFO] Cleared history for user {user_id}", file=sys.stderr)
            return jsonify({'success': True, 'message': 'History cleared'}), 200
        else:
            print(f"[ERROR] Failed to clear history for user {user_id}", file=sys.stderr)
            return jsonify({'error': 'Failed to clear history'}), 500
    except Exception as e:
        # Catch any unexpected errors during clearing
        print(f"[ERROR] Error clearing history for user {current_user.id}: {e}", file=sys.stderr)
        return jsonify({'error': 'Failed to clear history'}), 500


# --- QR Code Generation Endpoint ---
@app.route('/generate-qr', methods=['POST'])
# This endpoint doesn't necessarily require login if you want anyone to generate QRs
def generate_qr():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            print("[ERROR] Generate QR request missing URL", file=sys.stderr)
            return jsonify({'error': 'URL is required'}), 400

        # Use the helper function to generate the QR data URL
        qr_data_url = create_qr_image_data_url(url)
        if qr_data_url:
            print(f"[INFO] Generated QR code for URL: {url[:50]}...", file=sys.stderr) # Print truncated URL
            return jsonify({'data': qr_data_url})
        else:
            print(f"[ERROR] Failed to generate QR code for URL: {url}", file=sys.stderr)
            return jsonify({'error': 'Failed to generate QR code'}), 500
    except Exception as e:
        # Catch any unexpected errors during QR generation
        print(f"[ERROR] Error during QR generation: {e}", file=sys.stderr)
        return jsonify({'error': 'An error occurred during QR generation', 'details': str(e)}), 500


# --- Main Execution Block ---
if __name__ == '__main__':
    # The SECRET_KEY check is now done at the top after loading dotenv

    print("Initializing Fraud Detector Model...")
    # Train the fraud detection model
    if detector.train_model():
         print("Model training successful.")
    else:
         print("Model training failed. Application may not function correctly.")

    print("Starting Flask App...")
    # Run the Flask development server
    # debug=True is useful for development, disable in production
    app.run(debug=True)