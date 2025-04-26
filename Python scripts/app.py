import io
import sys
import os
import qrcode
import base64
import json
import time
import csv
import traceback
from flask import Flask, request, jsonify, redirect, url_for, session, send_from_directory, Response
from datetime import timedelta # Import timedelta

# Add the project root to the sys.path to import modules from helpers and Notebook
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir) # Go up one level from 'Python scripts'
# Assuming 'helpers', 'Notebook', 'CSS', and 'Script' are directly under project_root
sys.path.append(project_root)

# Import load_dotenv
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from PIL import Image
import pyzbar.pyzbar
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Import database handler and logger
from helpers.db import handler as db_handler
from helpers.log import logger as log

# Import the fraud detection model
from Notebook.fraud_detection_model_ import HybridFraudDetector


app = Flask(__name__)

# IMPORTANT: Load SECRET_KEY from environment variables!
# Ensure SECRET_KEY is set in your .env file
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# --- ADDED: Configure Permanent Session Lifetime ---
# Set the session to last for 31 days (example duration)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)
# --- END ADDED ---


# Check if SECRET_KEY is loaded
if not app.config['SECRET_KEY']:
    print("[CRITICAL] SECRET_KEY not set in environment variables or .env file!", file=sys.stderr)
    print("Please set SECRET_KEY in your .env file for security.", file=sys.stderr)
    # In a production app, you might want to exit here or raise an error
    # For development, we'll proceed but warn the user.

# --- ADDED: Debugging SECRET_KEY ---
print(f"[DEBUG] App SECRET_KEY: {app.config['SECRET_KEY']}", file=sys.stderr)
# --- END ADDED ---


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
    # Added logging to help diagnose why a user might not be loaded
    # print(f"[DEBUG] Attempting to load user with ID: {user_id}", file=sys.stderr) # Verbose debug
    user_data = db_handler.find_user_by_id(user_id)
    if user_data and 'email' in user_data and 'username' in user_data:
        # print(f"[DEBUG] User loaded successfully: {user_id}", file=sys.stderr) # Verbose debug
        return User(user_data['id'], user_data['email'], user_data['username'])
    else:
        # This happens if the user_id in the session is invalid or user was deleted
        if user_id is not None:
             log.log_warning(f"User ID {user_id} found in session but user data not found in database.", "load_user")
        # print(f"[DEBUG] Failed to load user by ID: {user_id}", file=sys.stderr) # Verbose debug
    return None


# --- Fraud Detector Initialization ---
detector = HybridFraudDetector()


# --- Route to serve the index.html file ---
# Define the directory where index.html is located (project root)
root_dir = os.path.join(project_root) # This is the main directory containing index.html, CSS, Script


@app.route('/')
def serve_index():
    """Serves the index.html file from the project root directory."""
    # print(f"[INFO] Serving index.html from {root_dir}", file=sys.stderr) # Keep logging minimal unless debugging
    # --- ADDED: Debugging session on page load ---
    # print(f"[DEBUG] Session on / load: {dict(session)}", file=sys.stderr)
    # if current_user.is_authenticated:
    #      print(f"[DEBUG] User authenticated on / load: {current_user.id}", file=sys.stderr)
    # else:
    #      print("[DEBUG] User NOT authenticated on / load", file=sys.stderr)
    # --- END ADDED ---
    return send_from_directory(root_dir, 'index.html')

# --- Routes to serve static CSS and JS files ---
# Use <path:filename> to handle potential subdirectories if needed
@app.route('/CSS/<path:filename>')
def serve_css(filename):
    """Serves CSS files from the CSS directory in the project root."""
    css_dir = os.path.join(root_dir, 'CSS')
    # print(f"[INFO] Serving CSS file: {filename} from {css_dir}", file=sys.stderr) # Keep logging minimal unless debugging
    return send_from_directory(css_dir, filename)

@app.route('/Script/<path:filename>')
def serve_script(filename):
    """Serves JavaScript files from the Script directory in the project root."""
    script_dir = os.path.join(root_dir, 'Script')
    # print(f"[INFO] Serving Script file: {filename} from {script_dir}", file=sys.stderr) # Keep logging minimal unless debugging
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
        log.log_error("Registration attempt with missing email, username, or password", "register")
        return jsonify({'error': 'Email, username, and password are required'}), 400

    if db_handler.find_user_by_email(email):
        log.log_error(f"Registration attempt for existing email: {email}", "register")
        return jsonify({'error': 'Email already exists'}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    user_id = db_handler.create_user(email, username, hashed_password)

    if user_id:
        print(f"[INFO] User registered successfully: {email} ({username}) (ID: {user_id})", file=sys.stderr) # Keep success logs
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201
    else:
        log.log_error(f"Failed to create user in database: {email}", "register")
        return jsonify({'error': 'Failed to register user. Username or email might already exist.'}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        log.log_error("Login attempt with missing email or password", "login")
        return jsonify({'error': 'Email and password are required'}), 400

    user_data = db_handler.find_user_by_email(email)

    if user_data and 'id' in user_data and 'email' in user_data and 'username' in user_data and 'password_hash' in user_data:
        if check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['email'], user_data['username'])
            # --- ADDED: Make the session permanent BEFORE login_user ---
            session.permanent = True
            # --- END ADDED ---
            login_user(user)
            # --- ADDED: Debugging session after login ---
            print(f"[DEBUG] Session after login: {dict(session)}", file=sys.stderr)
            # --- END ADDED ---
            print(f"[INFO] User logged in successfully: {user.email} ({user.username}) (ID: {user.id})", file=sys.stderr) # Keep success logs
            return jsonify({'success': True, 'message': 'Logged in successfully', 'email': user.email, 'username': user.username}), 200
        else:
            log.log_error(f"Failed login attempt for email: {email} (incorrect password)", "login")
            return jsonify({'error': 'Invalid email or password'}), 401
    else:
        log.log_error(f"Failed login attempt: User with email {email} not found", "login")
        return jsonify({'error': 'Invalid email or password'}), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user_email = current_user.email
    user_id = current_user.id
    logout_user()
    print(f"[INFO] User logged out: {user_email} (ID: {user_id})", file=sys.stderr) # Keep success logs
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/status', methods=['GET'])
def status():
    """Check if the user is logged in and return user info."""
    # --- ADDED: Debugging session on status check ---
    # print(f"[DEBUG] Session on /status check: {dict(session)}", file=sys.stderr)
    # --- END ADDED ---
    if current_user.is_authenticated:
        # Return username and email
        # print(f"[DEBUG] User authenticated on /status: {current_user.id}", file=sys.stderr) # Verbose debug
        return jsonify({'is_logged_in': True, 'email': current_user.email, 'username': current_user.username}), 200
    else:
        # print("[DEBUG] User NOT authenticated on /status", file=sys.stderr) # Verbose debug
        return jsonify({'is_logged_in': False}), 200


# --- Analysis Routes (Modified to Save History) ---

# Inside Python scripts/app.py, find analyze_url function

@app.route('/analyze-url', methods=['POST'])
@login_required
def analyze_url():
    # --- ADDED DEBUG LOGGING ---
    print(f"[DEBUG] Inside analyze-url route.", file=sys.stderr)
    print(f"[DEBUG] analyze-url - User authenticated: {current_user.is_authenticated}", file=sys.stderr)
    if current_user.is_authenticated:
        print(f"[DEBUG] analyze-url - User ID: {current_user.id}, Email: {current_user.email}, Username: {current_user.username}", file=sys.stderr)
    else:
         print(f"[DEBUG] analyze-url - User is NOT authenticated despite @login_required?", file=sys.stderr) # This shouldn't happen with login_required
    # --- END ADDED DEBUG LOGGING ---
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            log.log_error("Analyze URL request missing URL", "analyze_url")
            return jsonify({'error': 'URL is required'}), 400

        result = detector.analyze_url(url)

        if not result:
            log.log_error(f"Analysis failed for URL: {url}", "analyze_url")
            return jsonify({'error': 'Failed to analyze URL'}), 500 # Or a more specific status like 422 Unprocessable Entity


        # --- MODIFIED: Handle saving explicitly ---
        # user_id = current_user.id # Already got this in debug logging, but use it
        if not current_user.is_authenticated:
             log.log_error("analyze_url called but current_user is not authenticated!", "analyze_url")
             return jsonify({'error': 'Authentication required'}), 401 # Should not reach here if login_required works

        user_id = current_user.id
        save_success = db_handler.save_analysis_result(user_id, 'url', url, result)

        if not save_success:
            # If saving failed, log and return an error status to the frontend
            log.log_error(f"Failed to save URL analysis result for user {user_id}: {url}", "analyze_url")
            # Return the analysis result, but signal a partial failure (e.g., status 207 Multi-Status)
            # Or return an error. Returning 500 might be simpler if saving is mandatory.
            # Let's return the result but add an error flag for the frontend.
            result['save_error'] = True
            log.log_warning(f"Analysis successful for URL {url} but saving failed.", "analyze_url")
            # We could return 200 with a flag, or 500 error. Let's return 200 for now but log the save failure.
            return jsonify(result), 200
            # Alternatively, to force frontend error handling:
            # return jsonify({'error': 'Analysis successful but failed to save history.'}), 500

        # If saving was successful, return the analysis result with 200 OK
        print(f"[DEBUG] URL analysis and save successful for user {user_id}", file=sys.stderr)
        return jsonify(result), 200
        # --- END MODIFIED ---

    except Exception as e:
        import traceback
        log.log_error(f"Error during URL analysis: {e}\n{traceback.format_exc()}", "analyze_url")
        return jsonify({'error': 'An internal error occurred during analysis.'}), 500 # Generic error message


# Inside Python scripts/app.py, find analyze_qr function

@app.route('/analyze-qr', methods=['POST'])
@login_required
def analyze_qr():
    # --- ADDED DEBUG LOGGING ---
    print(f"[DEBUG] Inside analyze-qr route.", file=sys.stderr)
    print(f"[DEBUG] analyze-qr - User authenticated: {current_user.is_authenticated}", file=sys.stderr)
    if current_user.is_authenticated:
        print(f"[DEBUG] analyze-qr - User ID: {current_user.id}, Email: {current_user.email}, Username: {current_user.username}", file=sys.stderr)
    else:
         print(f"[DEBUG] analyze-qr - User is NOT authenticated despite @login_required?", file=sys.stderr) # This shouldn't happen with login_required
    # --- END ADDED DEBUG LOGGING ---
    try:
        if 'file' not in request.files:
            log.log_error("Analyze QR request missing file", "analyze_qr")
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
             log.log_error("Analyze QR request received empty file", "analyze_qr")
             return jsonify({'error': 'No selected file'}), 400

        img = Image.open(file)
        qr_codes = pyzbar.pyzbar.decode(img)

        if not qr_codes:
            log.log_error("No QR code found in uploaded image", "analyze_qr")
            return jsonify({'error': 'No QR code found'}), 400

        url = qr_codes[0].data.decode('utf-8')

        result = detector.analyze_url(url) # Analyze the decoded URL

        if not result:
            log.log_error(f"Analysis failed for decoded QR URL: {url}", "analyze_qr")
            return jsonify({'error': 'Failed to analyze QR content'}), 500 # Or 422


        # --- MODIFIED: Handle saving explicitly ---
        result['url'] = url # Add the decoded URL to the result before saving/returning

        # user_id = current_user.id # Already got this in debug logging, but use it
        if not current_user.is_authenticated:
             log.log_error("analyze_qr called but current_user is not authenticated!", "analyze_qr")
             return jsonify({'error': 'Authentication required'}), 401 # Should not reach here if login_required works

        user_id = current_user.id
        # Use the decoded URL as item_data for clarity in history, or filename+URL
        item_data = f"QR Code ({url})" if url else file.filename
        save_success = db_handler.save_analysis_result(user_id, 'qr', item_data, result)

        if not save_success:
            # If saving failed, log and signal to the frontend
             log.log_error(f"Failed to save QR analysis result for user {user_id}: {item_data}", "analyze_qr")
             result['save_error'] = True
             log.log_warning(f"QR analysis successful for {item_data} but saving failed.", "analyze_qr")
             return jsonify(result), 200
             # Alternatively:
             # return jsonify({'error': 'QR Analysis successful but failed to save history.'}), 500


        # If saving was successful
        print(f"[DEBUG] QR analysis and save successful for user {user_id}", file=sys.stderr)
        return jsonify(result), 200
        # --- END MODIFIED ---

    except Exception as e:
        import traceback
        log.log_error(f"Error during QR analysis: {e}\n{traceback.format_exc()}", "analyze_qr")
        return jsonify({'error': 'An internal error occurred during QR analysis.'}), 500 # Generic error message
# --- History Routes (Modified to implement filtering logic) ---

# In app.py, find the get_history function

@app.route('/history', methods=['GET'])
@login_required
def get_history():
    try:
        user_id = current_user.id

        # Initialize filters dictionary to be passed to db_handler
        active_filters = {}

        # --- MODIFIED: Get filter parameters from the request query string based on what frontend sends ---
        item_type_filter = request.args.get('type')
        is_fraud_param = request.args.get('is_fraud') # 'true' or 'false' string
        risk_level_param = request.args.get('risk_level') # e.g., 'Critical', 'Medium', 'Safe'
        search_term_filter = request.args.get('search')

        # Apply item type filter if present and not empty/all
        # Check for lower() != '' because the default option value is ''
        if item_type_filter and item_type_filter.lower() != '' and item_type_filter.lower() != 'all':
             active_filters['item_type'] = item_type_filter

        # Apply risk_level filter if present and not empty/all
        # Check for lower() != '' because the default option value is ''
        if risk_level_param and risk_level_param.lower() != '' and risk_level_param.lower() != 'all':
             active_filters['risk_level'] = risk_level_param
             # --- REMOVED THE LINE THAT WAS HERE ---
             # active_filters['is_fraud'] = False # <<< THIS LINE SHOULD NOT BE HERE
             # Specific risk level filters should NOT implicitly add is_fraud=False

        # Apply is_fraud filter if the parameter was explicitly sent ('true' or 'false')
        # Check if the parameter EXISTS, not just if it has a truthy value
        if is_fraud_param is not None: # Check if the parameter was present in the request
            # Convert string 'true'/'false' to Python boolean True/False for handler
            if is_fraud_param.lower() == 'true':
                active_filters['is_fraud'] = True
            elif is_fraud_param.lower() == 'false':
                 active_filters['is_fraud'] = False
            # If the value is something else, it will not add the filter


        # Apply search term filter if present
        if search_term_filter:
             active_filters['search_term'] = search_term_filter
        # --- END MODIFIED ---


        print(f"[INFO] Fetching history for user {user_id} with applied filters: {active_filters}", file=sys.stderr)

        # Fetch history items from the database handler using the constructed filters
        history_items = db_handler.get_user_history(user_id, active_filters)

        # ... (rest of the function remains the same) ...
        # Ensure history_items is a list before returning
        history_items = history_items if isinstance(history_items, list) else []

        if not history_items:
             print(f"[INFO] No history found for user {user_id} matching filters: {active_filters}", file=sys.stderr)
             return jsonify([]), 200

        return jsonify(history_items), 200

    except Exception as e:
        import traceback
        log.log_error(f"Error fetching history for user {current_user.id}: {e}\n{traceback.format_exc()}", "get_history")
        return jsonify({'error': 'Failed to fetch history due to an internal server error.'}), 500

# Route for exporting history (Modified to use the same filtering logic)
@app.route('/export-history', methods=['GET']) # Changed route to /export-history for clarity based on frontend
@login_required
def export_history():
    try:
        user_id = current_user.id

        # Initialize filters dictionary
        active_filters = {}

        # Get filter parameters from the request query string (same logic as get_history)
        item_type_filter = request.args.get('type')
        risk_filter_value = request.args.get('risk')
        search_term_filter = request.args.get('search')

        # Apply item type filter
        if item_type_filter and item_type_filter.lower() != 'all':
            active_filters['item_type'] = item_type_filter

        # Apply risk filter based on the selected value from the frontend
        if risk_filter_value and risk_filter_value.lower() != 'all':
            if risk_filter_value.lower() == 'fraudulent':
                active_filters['is_fraud'] = True
            else:
                active_filters['risk_level'] = risk_filter_value
                active_filters['is_fraud'] = False # Exclude fraudulent items

        # Apply search term filter
        if search_term_filter:
             active_filters['search_term'] = search_term_filter

        print(f"[INFO] Exporting history for user {user_id} with filters: {active_filters}", file=sys.stderr)

        # Fetch filtered history data using the constructed filters
        history_items = db_handler.get_user_history(user_id, active_filters)
        history_items = history_items if isinstance(history_items, list) else []

        if not history_items:
            # Return 204 No Content if no data matches filters for export
            print(f"[INFO] No history found for user {user_id} with filters {active_filters} to export.", file=sys.stderr)
            return Response(status=204) # No Content

        # Prepare data for CSV
        csv_data = io.StringIO()
        # Define CSV headers, mapping to keys in the history item dictionaries
        # Including flattened analysis result fields
        fieldnames = ['id', 'item_type', 'item_data', 'analyzed_at', 'is_fraud', 'confidence', 'risk_level', 'risk_factors']
        writer = csv.DictWriter(csv_data, fieldnames=fieldnames)

        writer.writeheader()
        for item in history_items:
            # Flatten the analysis_result JSON into top-level keys for CSV row
            analysis_result = item.get('analysis_result', {}) # Get analysis_result safely
            row = {
                'id': item.get('id'),
                'item_type': item.get('item_type'),
                'item_data': item.get('item_data', ''), # Ensure item_data is not None
                'analyzed_at': item.get('analyzed_at', ''), # Ensure analyzed_at is not None
                'is_fraud': analysis_result.get('is_fraud', False), # Default to False if missing
                'confidence': analysis_result.get('confidence', 0), # Default to 0 if missing
                'risk_level': analysis_result.get('risk_level', 'Unknown'), # Default to 'Unknown' if missing
                # Convert risk_factors list to a string for CSV, default to empty list if missing
                'risk_factors': ", ".join(analysis_result.get('risk_factors', []))
            }
            writer.writerow(row)

        # Create a Flask Response for file download
        response = Response(csv_data.getvalue(), mimetype='text/csv')
        # Set Content-Disposition header to suggest a filename
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f'fraud_detection_history_export_{timestamp}.csv'
        response.headers.set('Content-Disposition', 'attachment', filename=filename)

        print(f"[INFO] Successfully exported history for user {user_id} with filters {active_filters}", file=sys.stderr)
        return response

    except Exception as e:
        log.log_error(f"Error exporting history for user {current_user.id}: {e}", "export_history")
        # Return a generic error message for security reasons
        return jsonify({'error': 'Failed to export history due to an internal server error.'}), 500


@app.route('/delete-history-item/<int:item_id>', methods=['DELETE'])
@login_required
def delete_history_item(item_id):
    try:
        user_id = current_user.id
        success = db_handler.delete_history_item(item_id, user_id)
        if success:
            print(f"[INFO] History item {item_id} deleted by user {user_id}", file=sys.stderr) # Keep success logs
            return jsonify({'success': True, 'message': 'History item deleted'}), 200
        else:
            # If delete_history_item returns False, it means the item wasn't found or didn't belong to the user
            log.log_error(f"Failed to delete history item {item_id} for user {user_id} (not found or not owned)", "delete_history_item")
            return jsonify({'error': 'History item not found or could not be deleted'}), 404 # Use 404 if not found/not owned
    except Exception as e:
        log.log_error(f"Error deleting history item {item_id} for user {current_user.id}: {e}", "delete_history_item")
        # Return a generic error message for security reasons
        return jsonify({'error': 'Failed to delete history item due to an internal server error.'}), 500

@app.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    try:
        user_id = current_user.id
        success = db_handler.clear_user_history(user_id)
        if success:
            print(f"[INFO] History cleared for user {user_id}", file=sys.stderr) # Keep success logs
            return jsonify({'success': True, 'message': 'History cleared'}), 200
        else:
            log.log_error(f"Failed to clear history for user {user_id} in db_handler", "clear_history")
            return jsonify({'error': 'Failed to clear history'}), 500 # Assuming failure means a DB issue or similar
    except Exception as e:
        log.log_error(f"Error clearing history for user {current_user.id}: {e}", "clear_history")
        # Return a generic error message for security reasons
        return jsonify({'error': 'Failed to clear history due to an internal server error.'}), 500


# --- QR Code Generation Endpoint ---
# Note: This endpoint is not login_required in the original code.
# Decide if you want QR generation to require login.
@app.route('/generate-qr', methods=['POST'])
def generate_qr():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            log.log_error("Generate QR request missing URL", "generate_qr")
            return jsonify({'error': 'URL is required'}), 400

        qr_data_url = create_qr_image_data_url(url)
        if qr_data_url:
            return jsonify({'data': qr_data_url})
        else:
            log.log_error(f"Failed to generate QR code for URL: {url}", "generate_qr")
            return jsonify({'error': 'Failed to generate QR code'}), 500
    except Exception as e:
        log.log_error(f"Error during QR generation: {e}", "generate_qr")
        return jsonify({'error': str(e)}), 500


# --- Main Execution Block ---
if __name__ == '__main__':
    print("Initializing Fraud Detector Model...")
    # Consider moving model training outside the main run block
    # for production environments, or ensure it only runs once.
    # For development, retraining on each run is acceptable.
    # Ensure your db_handler is initialized before training if the model uses DB data
    if detector.train_model():
         print("Model training successful.")
    else:
         print("Model training failed. Application may not function correctly.")

    print("Starting Flask App...")
    # In production, use a production WSGI server like Gunicorn or uWSGI
    # app.run(debug=True) # debug=True is useful for development
    # Use debug=False for production
    app.run(debug=True, port=5000) # Explicitly set port for clarity