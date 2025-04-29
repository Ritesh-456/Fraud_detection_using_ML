# D:\Projects\Fraud Detection using ML\Fraud_detection_using_ML\Python scripts\app.py

# This script is the Flask backend API for the Fraud Detection System.
# It handles user authentication, analysis requests, history management,
# and data visualization statistics.

# --- Standard Library Imports ---
import io # Used for handling bytes streams (e.g., for QR code images)
import sys # Used for system-specific parameters and functions
import os # Used for interacting with the operating system (paths, environment variables)
import qrcode # Used for generating QR codes (optional endpoint)
import base64 # Used for encoding/decoding base64 data (e.g., for QR image data URLs)
import json # Used for working with JSON data (analysis results, request bodies)
import time # Used for time-related operations (e.g., timestamps in export filenames)
import csv # Used for working with CSV data (export)
import traceback # Used for printing detailed error information in logs
from datetime import timedelta # Used for defining session lifetime

# --- Third-Party Library Imports ---
# Ensure these are in your pyproject.toml and installed (uv sync or uv pip install .)
# Flask and extensions
from flask import Flask, request, jsonify, redirect, url_for, session, send_from_directory, Response # The Flask framework
from flask_cors import CORS # Flask-CORS for handling Cross-Origin Resource Sharing
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # Flask-Login for user session management
# Security for passwords
from werkzeug.security import generate_password_hash, check_password_hash
# Model saving/loading (used by the detector module)
import joblib # Imported here as it's used indirectly via the detector initialization/loading
# Image handling for QR codes
from PIL import Image # Import the Image object from Pillow
import pyzbar.pyzbar # Import the pyzbar module for decoding QR codes
# Environment variable loading
from dotenv import load_dotenv # Used to load variables from a .env file


# --- Internal/Project Module Imports ---
# Add the project root directory to the Python path so we can import modules like helpers and Notebook
current_dir = os.path.dirname(os.path.abspath(__file__)) # Directory where this app.py file is located
project_root = os.path.dirname(current_dir) # Go up one level from 'Python scripts' to get the project root
# Add the project root to sys.path. This allows importing `helpers.db` and `Notebook.fraud_detection_model_`.
sys.path.append(project_root)

# Import the database handler module
# This module contains functions for connecting to the DB and performing operations (users, history, stats, append_training_data).
from helpers.db import handler as db_handler

# Import the fraud detection model module and specific variables/classes from it.
# We need HybridFraudDetector class and the MODEL_DIR variable for logging.
from Notebook.fraud_detection_model_ import HybridFraudDetector, MODEL_DIR # <-- ADDED MODEL_DIR import here


# --- Standard Logging Configuration ---
# Configure Python's built-in logging module.
# This basic config sets up logging to the console (stderr) with a specific format and level.
import logging # Import the logging module
# Corrected typo 'loggging' to 'logging' in the basicConfig line
logging.basicConfig(level=logging.INFO, # Set the minimum logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') # Define log message format
# Get a logger instance specifically for this module (__name__ is 'Python scripts.app')
logger = logging.getLogger(__name__)


# --- Flask Application Setup ---
app = Flask(__name__)

# IMPORTANT: Configure Flask's SECRET_KEY from environment variables for session security!
# This key is essential for signing session cookies. Ensure SECRET_KEY is set in your .env file.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configure Flask sessions to be permanent and set their lifetime.
# Permanent sessions mean cookies are stored in the browser beyond the current tab/window.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31) # Example: Session lasts for 31 days

# Check if the SECRET_KEY was loaded. Log a critical error if not, as this is a major security risk.
if not app.config['SECRET_KEY']:
    logger.critical("SECRET_KEY environment variable is not set! Session security is compromised.")
    logger.critical("Please set SECRET_KEY in your .env file.")


# Configure Flask-CORS. By default, this allows cross-origin requests from any origin (*).
# In a production environment, you should restrict this to only allow your frontend's origin(s).
CORS(app)

# --- Flask-Login Setup ---
# Initialize Flask-Login extension
login_manager = LoginManager()
login_manager.init_app(app)
# login_manager.login_view = 'login' # We handle redirection/401 responses on the frontend now


# User class for Flask-Login, integrates with the database user structure.
# This class must implement the UserMixin interface.
class User(UserMixin):
    def __init__(self, id, email, username):
        # Store user properties fetched from the database.
        self.id = id # User ID (must be unique and hashable)
        self.email = email
        self.username = username

    def get_id(self):
        # Required by UserMixin: Return a unique string identifier for the user.
        return str(self.id)

# Flask-Login user loader function.
# This function is called by Flask-Login on each request to load a user from the session cookie.
# It takes the user_id (as returned by get_id()) and should return the User object or None if the user is not found.
@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database based on user_id for Flask-Login."""
    # The db_handler handles database connection and potential errors during user lookup.
    user_data = db_handler.find_user_by_id(user_id)
    # If user data is found and contains the necessary information, return a User object.
    if user_data and 'id' in user_data and 'email' in user_data and 'username' in user_data:
        return User(user_data['id'], user_data['email'], user_data['username'])
    else:
        # If user data is not found (e.g., user deleted, invalid session ID), return None.
        # The db_handler logs specific lookup errors internally.
        pass # No need to log again here unless debugging load_user specifically
    return None


# --- Fraud Detector Initialization ---
# Initialize the HybridFraudDetector instance when the application module is loaded.
# The model training/loading happens later in the __main__ block or via separate script.
detector = HybridFraudDetector()


# --- Favicon Route ---
# Keeping this route might be useful if Streamlit or other services expect a favicon.
# Adjust the path based on where your favicon is located.
@app.route('/favicon.ico')
def serve_favicon():
    """Serves the favicon.ico file from the project root."""
    # Assuming favicon.ico is directly in the project root directory.
    # If it's in a subdirectory like 'static', adjust `directory` argument.
    root_dir = os.path.join(project_root)
    logger.debug("Serving favicon.ico route triggered.")
    # Check if the file exists before attempting to serve it
    favicon_path = os.path.join(root_dir, 'favicon.ico')
    if os.path.exists(favicon_path):
         return send_from_directory(root_dir, 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    else:
         logger.warning(f"Favicon not found at expected location: {favicon_path}")
         return '', 404 # Return 404 Not Found if the file doesn't exist


# --- Helper function to generate QR Image Data URL (Used by generate-qr endpoint) ---
# This function might still be useful if your Streamlit app needs to generate QR codes *via the backend*.
def create_qr_image_data_url(url):
    """Generates a data URL for a QR code image."""
    try:
        # Create QR code object
        qr = qrcode.QRCode(
            version=1, # QR code version (1 to 40)
            error_correction=qrcode.constants.ERROR_CORRECT_L, # Error correction level
            box_size=4, # Size of each box in the QR code grid
            border=1, # Border size around the QR code
        )
        qr.add_data(url) # Add the URL data to the QR code
        qr.make(fit=True) # Generate the QR code matrix

        # Create an image from the QR code matrix
        img = qr.make_image(fill_color="black", back_color="white")
        # Save the image to a bytes buffer in PNG format
        img_io = io.BytesIO()
        img.save(img_io, format="PNG")
        # Get the bytes and encode them in Base64
        img_base64 = base64.b64encode(img_io.getvalue()).decode()
        # Construct the data URL string
        data_url = f"data:image/png;base64,{img_base64}"
        return data_url
    except Exception as e:
        # Log error during QR image generation
        logger.error(f"Error generating QR image for URL: {url[:100]}... Error: {e}", exc_info=True)
        return None


# --- Authentication Endpoints (API for Streamlit) ---

@app.route('/register', methods=['POST'])
def register():
    """API endpoint for user registration."""
    logger.debug("Received registration request.")
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    # Basic validation for required fields
    if not email or not username or not password:
        logger.warning("Registration attempt with missing email, username, or password.")
        return jsonify({'error': 'Email, username, and password are required'}), 400 # Bad Request

    # Delegate user creation to the database handler. Handler logs specific DB errors (e.g., integrity errors).
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    user_id = db_handler.create_user(email, username, hashed_password)

    # db_handler.create_user returns user_id (int) on success, None on failure.
    if user_id:
        logger.info(f"User registered successfully: {email} (ID: {user_id})")
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201 # Created
    else:
        # If user creation failed in the DB, it's likely due to integrity constraints (email/username exists)
        # or a database error (logged in db_handler).
        # Return appropriate error response.
        logger.error(f"Failed to create user in database: email='{email}'")
        return jsonify({'error': 'Failed to register user. Email or username might already exist.'}), 409 # Conflict (if email/username exists)


@app.route('/login', methods=['POST'])
def login():
    """API endpoint for user login."""
    logger.debug("Received login request.")
    data = request.get_json()
    email = data.get('email') # Assuming login is by email
    password = data.get('password')

    # Basic validation for required fields
    if not email or not password:
        logger.warning("Login attempt with missing email or password.")
        return jsonify({'error': 'Email and password are required'}), 400 # Bad Request

    # Delegate user lookup to the database handler. Handler logs errors/not found internally.
    user_data = db_handler.find_user_by_email(email)

    # Check if user was found and password hash is available
    # Safely access keys using .get() with default None
    if user_data and user_data.get('id') and user_data.get('password_hash'):
        # Verify the provided password against the stored hash
        if check_password_hash(user_data['password_hash'], password):
            # If password is correct, create a Flask-Login User object
            user = User(user_data['id'], user_data.get('email', ''), user_data.get('username', '')) # Use get() for safety
            # Log the user in using Flask-Login. This sets the session cookie.
            # Make the session permanent before logging in.
            session.permanent = True
            login_user(user)
            logger.info(f"User logged in successfully: {user.email} (ID: {user.id})")
            # Return success response with user info (username) for the frontend.
            return jsonify({'success': True, 'message': 'Logged in successfully', 'email': user.email, 'username': user.username}), 200 # OK
        else:
            # Log failed attempt with incorrect password
            logger.warning(f"Failed login attempt for email: {email} (incorrect password).")
            return jsonify({'error': 'Invalid email or password'}), 401 # Unauthorized
    else:
        # Log failed attempt where user was not found or data was incomplete
        logger.warning(f"Failed login attempt: User with email {email} not found or data incomplete from DB.")
        return jsonify({'error': 'Invalid email or password'}), 401 # Unauthorized


@app.route('/logout', methods=['POST'])
@login_required # Ensures user must be logged in to log out
def logout():
    """API endpoint for user logout."""
    # Get user info before logging out for logging purposes
    user_email = current_user.email
    user_id = current_user.id
    # Log the user out using Flask-Login. This clears the session.
    logout_user()
    logger.info(f"User logged out: {user_email} (ID: {user_id})")
    # Return success response.
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200 # OK

@app.route('/status', methods=['GET'])
def status():
    """API endpoint to check if the user is logged in and return user info."""
    # current_user is provided by Flask-Login, indicates the logged-in user or an anonymous user.
    logger.debug("Received status check request.")
    if current_user.is_authenticated:
        # If authenticated, return true status and user details.
        logger.debug(f"Status check: User ID {current_user.id} authenticated.")
        return jsonify({'is_logged_in': True, 'email': current_user.email, 'username': current_user.username}), 200 # OK
    else:
        # If not authenticated, return false status.
        logger.debug("Status check: User not authenticated.")
        return jsonify({'is_logged_in': False}), 200 # OK


# --- Analysis Endpoints (API for Streamlit) ---
# These endpoints call the ML model and save results to the database.

@app.route('/analyze-url', methods=['POST'])
@login_required # Requires user to be logged in to perform analysis
def analyze_url():
    """API endpoint to analyze a URL for potential fraud."""
    logger.debug(f"Received analyze-url request for user ID: {current_user.id}")
    try:
        # Get URL from the JSON request body sent by the frontend
        data = request.get_json()
        url = data.get('url', '')

        # Validate input URL
        if not url:
            logger.warning(f"Analyze URL request from user {current_user.id} missing URL.")
            return jsonify({'error': 'URL is required'}), 400 # Bad Request

        # Call the fraud detector's analysis method.
        # The detector handles feature extraction, scaling, prediction, and interpretation.
        # The detector logs its own errors internally and returns a specific error structure.
        result = detector.analyze_url(url)

        # Check if the detector's analysis failed (it returns a dictionary with 'Error' risk_level).
        if not result or result.get('risk_level') == 'Error':
             logger.error(f"URL analysis failed for user {current_user.id}, URL: {url[:100]}... Detector result: {result}")
             # Extract a user-friendly error message from the detector's result if possible.
             error_msg = result.get('risk_factors', ["Analysis failed to produce a valid result."])[0] if result and result.get('risk_factors') else "Analysis failed to produce a valid result."
             return jsonify({'error': error_msg}), 500 # Internal Server Error (since detector failed)


        # Save the analysis result to the database history for the logged-in user.
        user_id = current_user.id
        # db_handler.save_analysis_result returns the new history item ID on success, False on failure.
        # It also logs save success/failure internally.
        save_success_id = db_handler.save_analysis_result(user_id, 'url', url, result)

        # Check if saving the result to history was successful.
        if not save_success_id:
            # If saving failed, log a warning and inform the frontend by adding a flag to the result.
            # The analysis itself was successful, so we still return the result data.
            result['save_error'] = True # Add flag for frontend
            logger.warning(f"Analysis successful for URL {url[:100]}... but saving history failed for user {user_id}.")
            return jsonify(result), 200 # OK (analysis succeeded, saving partially failed)
        else:
             # If saving was successful, add the history item ID to the result for frontend reference.
             result['db_id'] = save_success_id # Add DB ID to result dict
             logger.info(f"URL analysis result saved to history (ID: {save_success_id}) for user {user_id}. URL: {url[:100]}...")
             return jsonify(result), 200 # OK (analysis and saving succeeded)

    except Exception as e:
        # Catch any unexpected exceptions during the route handling (e.g., problems with request.get_json).
        # Detector's internal errors are caught and handled within the detector itself.
        logger.exception(f"Unexpected error during analyze-url route for user {current_user.id}, URL: {url[:100]}...") # Log error with traceback
        return jsonify({'error': 'An internal server error occurred during analysis.'}), 500 # Generic error response


@app.route('/analyze-qr', methods=['POST'])
@login_required # Requires user to be logged in
def analyze_qr():
    """API endpoint to analyze a QR code image for potential fraud."""
    logger.debug(f"Received analyze-qr request for user ID: {current_user.id}")
    try:
        # Check if a file named 'file' is present in the request (expected from FormData).
        if 'file' not in request.files:
            logger.warning(f"Analyze QR request from user {current_user.id} missing file part.")
            return jsonify({'error': 'No file part'}), 400 # Bad Request

        # Get the file from the request
        file = request.files['file']

        # Check if the file is empty
        if file.filename == '':
             logger.warning(f"Analyze QR request from user {current_user.id} received empty file.")
             return jsonify({'error': 'No selected file'}), 400 # Bad Request

        # Read the image file using Pillow and attempt to decode QR codes.
        img = Image.open(file)
        # Optionally convert image mode if pyzbar/cv2 has specific requirements (e.g., 'RGB', 'L')
        # if img.mode not in ['RGB', 'L', 'GRAY']:
        #     img = img.convert('RGB')

        qr_codes = pyzbar.pyzbar.decode(img) # Decode QR codes in the image

        # Check if any QR codes were found in the image.
        if not qr_codes:
            logger.warning(f"No QR code found in uploaded image for user {current_user.id}, filename: {file.filename}.")
            return jsonify({'error': 'No QR code found in the image.'}), 400 # Bad Request

        # Assume the first decoded QR code contains the relevant data (URL).
        # Decode the data (bytes) to a string (assuming UTF-8).
        url = qr_codes[0].data.decode('utf-8')

        logger.debug(f"Decoded QR code for user {current_user.id}, filename {file.filename}: {url[:100]}...")

        # Analyze the decoded URL using the fraud detector.
        # The detector's analyze_url method handles its own errors and returns a specific format.
        result = detector.analyze_url(url) # Analyze the decoded URL

        # Check if the detector's analysis failed.
        if not result or result.get('risk_level') == 'Error':
             logger.error(f"QR analysis failed for user {current_user.id}, decoded URL: {url[:100]}... Detector result: {result}")
             # Extract a user-friendly error message from the detector's result if possible.
             error_msg = result.get('risk_factors', ["Analysis of QR content failed."])[0] if result and result.get('risk_factors') else "Analysis of QR content failed."
             return jsonify({'error': error_msg}), 500 # Internal Server Error


        # Add the decoded URL to the result dictionary before saving/returning (useful for frontend).
        result['url'] = url

        # Save the analysis result to database history.
        user_id = current_user.id
        # Use the decoded URL or filename as item_data for history display.
        item_data = f"QR Code ({url[:100]}...)" if url else f"QR Code from {file.filename}" # Truncate long URLs for history item data string
        # db_handler.save_analysis_result returns ID on success, False on failure. It logs internally.
        save_success_id = db_handler.save_analysis_result(user_id, 'qr', item_data, result)

        # Check if saving was successful.
        if not save_success_id:
             # If saving failed, log a warning and signal to frontend.
             result['save_error'] = True # Add flag
             logger.warning(f"QR analysis successful for {item_data[:100]}... but saving history failed for user {user_id}.")
             return jsonify(result), 200 # OK (analysis succeeded, saving partially failed)
        else:
            # If saving was successful, add the history item ID to the result for frontend reference.
             result['db_id'] = save_success_id # Add DB ID to result dict
             logger.info(f"QR analysis result saved to history (ID: {save_success_id}) for user {user_id}. Item: {item_data[:100]}...")
             return jsonify(result), 200 # OK (analysis and saving succeeded)

    except Exception as e:
        # Catch any unexpected exceptions during the route handling (e.g., Pillow errors, pyzbar errors).
        logger.exception(f"Unexpected error during analyze-qr route for user {current_user.id}, filename: {file.filename if 'file' in locals() else 'N/A'}.") # Log with traceback
        return jsonify({'error': 'An internal server error occurred during QR analysis.'}), 500 # Generic error response


# --- History Endpoints (API for Streamlit) ---
# These endpoints provide user history and stats, filtered and formatted for the frontend.

@app.route('/history', methods=['GET'])
@login_required # Requires user to be logged in
def get_history():
    """API endpoint to fetch user's analysis history with filtering."""
    user_id = current_user.id
    logger.debug(f"Received get-history request for user ID: {user_id}.")

    try:
        # Initialize filters dictionary based on request query parameters.
        active_filters = {}

        # Get filter parameters from the request query string.
        # Frontend sends: type, is_fraud, risk_level, search (match Streamlit requests)
        item_type_filter = request.args.get('type')
        is_fraud_param = request.args.get('is_fraud') # Expected 'true' or 'false' string from frontend
        risk_level_param = request.args.get('risk_level') # Expected risk level string (e.g., 'Critical', 'Safe')
        search_term_filter = request.args.get('search') # Search term for item data


        # Add filters to the dictionary if they are present and not empty/default ('', 'all').
        if item_type_filter and item_type_filter.lower() not in ['', 'all']:
             active_filters['item_type'] = item_type_filter
             logger.debug(f"History filter: Type='{item_type_filter}'")


        # Add risk_level filter if present and not empty/all.
        # The db_handler's get_user_history logic correctly handles applying this filter.
        if risk_level_param and risk_level_param.lower() not in ['', 'all']:
              active_filters['risk_level'] = risk_level_param
              logger.debug(f"History filter: Risk_level='{risk_level_param}'")


        # Add is_fraud filter if the parameter was explicitly sent ('true' or 'false').
        # This filter applies independently of the risk_level filter.
        # Check if the parameter key is present in the request arguments
        if is_fraud_param is not None:
             # Convert string 'true'/'false' from request to Python boolean True/False for db_handler.
             if is_fraud_param.lower() == 'true':
                 active_filters['is_fraud'] = True
                 logger.debug("History filter: Is_fraud=True")
             elif is_fraud_param.lower() == 'false':
                  active_filters['is_fraud'] = False
                  logger.debug("History filter: Is_fraud=False")
             else:
                  logger.warning(f"Received unexpected value for is_fraud filter: '{is_fraud_param}'. Ignoring.")
            # Ignore if is_fraud_param is present but has an unexpected value.


        # Add search_term filter if present.
        if search_term_filter:
             active_filters['search_term'] = search_term_filter
             logger.debug(f"History filter: Search='{search_term_filter[:50]}...'")


        logger.info(f"Fetching history for user {user_id} with filters: {active_filters}")

        # Delegate history fetching to the database handler.
        # db_handler's get_user_history applies the filters and handles DB errors, logging them.
        history_items = db_handler.get_user_history(user_id, active_filters)

        # Ensure the result is a list before returning (db_handler returns list or []/None on failure).
        history_items = history_items if isinstance(history_items, list) else []

        # Check if any history items were found.
        if not history_items:
             logger.info(f"No history found for user {user_id} matching filters.")
             return jsonify([]), 200 # OK, but return empty list (frontend displays "No history found")

        # Return the list of history items as JSON.
        # db_handler already parses the JSON result and includes DB ID.
        return jsonify(history_items), 200 # OK

    except Exception as e:
        # Catch any unexpected errors during route handling. db_handler errors are logged internally.
        logger.exception(f"Unexpected error during get-history route for user {current_user.id}.") # Log with traceback
        return jsonify({'error': 'Failed to fetch history due to an internal server error.'}), 500 # Generic error response


# API endpoint for exporting user's analysis history to CSV.
# Uses the same filtering logic as get_history.
@app.route('/export-history', methods=['GET'])
@login_required # Requires user to be logged in
def export_history():
    """API endpoint to export user's filtered analysis history as CSV."""
    user_id = current_user.id
    logger.debug(f"Received export-history request for user ID: {user_id}.")
    try:
        # Initialize filters dictionary based on request query parameters.
        active_filters = {}

        # Get filter parameters from the request query string (same logic as get_history).
        item_type_filter = request.args.get('type')
        is_fraud_param = request.args.get('is_fraud')
        risk_level_param = request.args.get('risk_level')
        search_term_filter = request.args.get('search')

        # Add filters if present and not empty/default.
        if item_type_filter and item_type_filter.lower() not in ['', 'all']:
            active_filters['item_type'] = item_type_filter
        if risk_level_param and risk_level_param.lower() not in ['', 'all']:
            active_filters['risk_level'] = risk_level_param
        if is_fraud_param is not None:
             if is_fraud_param.lower() == 'true':
                 active_filters['is_fraud'] = True
             elif is_fraud_param.lower() == 'false':
                  active_filters['is_fraud'] = False
        if search_term_filter:
             active_filters['search_term'] = search_term_filter


        logger.info(f"Fetching history for user {user_id} with filters for export: {active_filters}")

        # Fetch filtered history data from the database handler using the constructed filters.
        # db_handler.get_user_history logs DB errors and returns []/None on failure.
        history_items = db_handler.get_user_history(user_id, active_filters)
        history_items = history_items if isinstance(history_items, list) else []

        # If no items found after filtering, return 204 No Content.
        if not history_items:
            logger.info(f"No history found for user {user_id} with filters to export (204 No Content).")
            return Response(status=204) # No Content response

        # Prepare data for CSV export.
        csv_data = io.StringIO() # Use StringIO to write CSV to an in-memory buffer
        # Define the CSV headers, matching keys in the history item dictionaries after JSON parsing.
        fieldnames = ['id', 'item_type', 'item_data', 'analyzed_at', 'is_fraud', 'confidence', 'risk_level', 'risk_factors']
        writer = csv.DictWriter(csv_data, fieldnames=fieldnames) # Create a CSV writer

        writer.writeheader() # Write the header row
        for item in history_items:
            # Flatten the 'analysis_result' JSON dictionary into top-level keys for the CSV row.
            # Use .get() with defaults for safety against missing keys/nulls.
            analysis_result = item.get('analysis_result', {})
            row = {
                'id': item.get('id'),
                'item_type': item.get('item_type', ''), # Ensure default empty string
                'item_data': item.get('item_data', ''), # Ensure default empty string
                'analyzed_at': item.get('analyzed_at', ''), # Ensure default empty string
                # Safely get analysis result details, providing defaults
                'is_fraud': analysis_result.get('is_fraud', False),
                'confidence': analysis_result.get('confidence', 0),
                'risk_level': analysis_result.get('risk_level', 'Unknown'),
                # Convert the list of risk_factors to a comma-separated string for the CSV cell.
                'risk_factors': ", ".join(analysis_result.get('risk_factors', [])) # Default to empty list if missing
            }
            writer.writerow(row) # Write the row to the CSV buffer

        # Create a Flask Response object for the file download.
        response = Response(csv_data.getvalue(), mimetype='text/csv') # Get buffer content and set MIME type
        # Set the Content-Disposition header to make the browser download the content as a file.
        timestamp = time.strftime('%Y%m%d_%H%M%S') # Generate a timestamp for the filename
        filename = f'fraud_detection_history_export_{timestamp}.csv' # Suggested filename
        response.headers.set('Content-Disposition', 'attachment', filename=filename) # Set the header

        logger.info(f"Successfully prepared history export for user {user_id}.")
        return response # Return the response for download

    except Exception as e:
        # Catch any unexpected errors during the export process.
        logger.exception(f"Unexpected error during export-history route for user {current_user.id}.") # Log with traceback
        return jsonify({'error': 'Failed to export history due to an internal server error.'}), 500 # Generic error response


@app.route('/delete-history-item/<int:item_id>', methods=['DELETE'])
@login_required # Requires user to be logged in
def delete_history_item(item_id):
    """API endpoint to delete a specific history item for the logged-in user."""
    user_id = current_user.id
    logger.debug(f"Received delete-history-item request for user ID: {user_id}, item ID: {item_id}.")
    try:
        # Delegate deletion to the database handler.
        # db_handler ensures the item belongs to the user and logs results.
        # db_handler returns True on successful deletion, False if item not found for this user.
        success = db_handler.delete_history_item(item_id, user_id)

        if success:
            logger.info(f"History item with ID {item_id} deleted successfully by user {user_id}.")
            return jsonify({'success': True, 'message': 'History item deleted'}), 200 # OK
        else:
            # If deletion failed (item not found or not owned), return 404 Not Found.
            # db_handler logs the reason for failure.
            logger.warning(f"Attempted to delete history item ID {item_id} for user {user_id} (item not found or not owned as per db_handler).")
            return jsonify({'error': 'History item not found or could not be deleted'}), 404 # Not Found
    except ValueError:
        # Handle case where item_id is not a valid integer (Flask converts via <int:item_id>, but still good practice).
        logger.warning(f"Invalid history item ID format received for deletion from user {user_id}: '{item_id}'.")
        return jsonify({'error': 'Invalid history item ID.'}), 400 # Bad Request
    except Exception as e:
        # Catch any unexpected errors. db_handler errors are logged internally.
        logger.exception(f"Unexpected error during delete-history-item route for user {current_user.id}, item ID: {item_id}.") # Log with traceback
        return jsonify({'error': 'Failed to delete history item due to an internal server error.'}), 500 # Generic error response


@app.route('/clear-history', methods=['POST'])
@login_required # Requires user to be logged in
def clear_history():
    """API endpoint to clear all history items for the logged-in user."""
    user_id = current_user.id
    logger.debug(f"Received clear-history request for user ID: {user_id}.")
    try:
        # Delegate clearing history to the database handler.
        # db_handler returns True if the operation completed, False on DB error.
        # It also logs success, failure, and cases where there was no history to clear.
        success = db_handler.clear_user_history(user_id)

        if success:
            # If the database operation completed successfully (even if no rows were deleted), return 200 OK.
            # db_handler logs whether rows were deleted.
            logger.info(f"History clearing operation completed for user {user_id}.")
            return jsonify({'success': True, 'message': 'History cleared'}), 200 # OK
        else:
            # If db_handler returned False, it indicates a database error during the operation.
            logger.error(f"Failed to clear history for user {user_id} (db_handler reported failure).")
            return jsonify({'error': 'Failed to clear history due to a database issue.'}), 500 # Internal Server Error
    except Exception as e:
        # Catch any unexpected errors during the route handling.
        logger.exception(f"Unexpected error during clear-history route for user {current_user.id}.") # Log with traceback
        return jsonify({'error': 'Failed to clear history due to an internal server error.'}), 500 # Generic error response


# --- QR Code Generation Endpoint (Optional for Streamlit Frontend) ---
# This endpoint could be used by Streamlit to generate a QR code image data URL via the backend API.
# Decide if you want this specific endpoint to require login using @login_required.
@app.route('/generate-qr', methods=['POST'])
# @login_required # Uncomment this line if QR generation requires authentication
def generate_qr():
    """API endpoint to generate a QR code image (as data URL) from a given URL."""
    # Log user ID if login is required
    # if current_user.is_authenticated: logger.debug(f"Received generate-qr request from user ID: {current_user.id}.")
    # else: logger.debug("Received generate-qr request from anonymous user.") # Log if not required

    try:
        # Get URL from the JSON request body
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            logger.warning("Generate QR request missing URL.")
            return jsonify({'error': 'URL is required'}), 400 # Bad Request

        # Call the helper function to create the QR image data URL.
        qr_data_url = create_qr_image_data_url(url)

        # Check if QR code generation was successful.
        if qr_data_url:
            logger.debug(f"QR code generated successfully for URL: {url[:100]}...")
            return jsonify({'data': qr_data_url}), 200 # OK, return data URL in JSON
        else:
            # create_qr_image_data_url logs the specific error if it fails.
            logger.error(f"Failed to generate QR code for URL: {url[:100]}... (helper function failed).")
            return jsonify({'error': 'Failed to generate QR code image.'}), 500 # Internal Server Error

    except Exception as e:
        # Catch any unexpected errors during route handling.
        logger.exception("Unexpected error during generate-qr route.") # Log with traceback
        return jsonify({'error': 'An internal server error occurred during QR code generation.'}), 500 # Generic error response


# --- Data Visualization Endpoints (API for Streamlit) ---
# These endpoints provide aggregated analysis statistics for charts.

@app.route('/analysis-stats', methods=['GET'])
@login_required # Requires user to be logged in to see their stats
def get_analysis_stats():
    """API endpoint to fetch aggregated analysis statistics (risk levels) for the logged-in user."""
    user_id = current_user.id
    logger.debug(f"Received get-analysis-stats (risk level) request for user ID: {user_id}.")
    try:
        # Call the database handler function to get risk level counts.
        # db_handler.get_risk_level_counts logs errors internally.
        stats_data = db_handler.get_risk_level_counts(user_id)

        # Check if the handler returned a dictionary (expected format).
        if isinstance(stats_data, dict):
             logger.info(f"Analysis risk level stats fetched for user {user_id}: {stats_data}")
             return jsonify(stats_data), 200 # OK, return stats dictionary
        else:
             # Log unexpected return type from handler.
             logger.error(f"db_handler.get_risk_level_counts returned unexpected data type for user {user_id}: {type(stats_data)}")
             return jsonify({'error': 'Failed to fetch analysis statistics due to a data format issue.'}), 500 # Internal Server Error

    except Exception as e:
        # Catch any unexpected errors during route handling.
        logger.exception(f"Unexpected error during analysis-stats route for user {current_user.id}.") # Log with traceback
        return jsonify({'error': 'Failed to fetch analysis statistics due to an internal server error.'}), 500 # Generic error response


@app.route('/analysis-type-stats', methods=['GET'])
@login_required # Requires user to be logged in
def get_analysis_type_stats():
    """API endpoint to fetch analysis counts by type (URL/QR) for the logged-in user."""
    user_id = current_user.id
    logger.debug(f"Received get-analysis-type-stats request for user ID: {user_id}.")
    try:
        # Call the database handler function to get analysis type counts.
        # db_handler.get_type_counts logs errors internally.
        stats_data = db_handler.get_type_counts(user_id)

        # Check if the handler returned a dictionary (expected format {'url': count, 'qr': count}).
        if isinstance(stats_data, dict):
             logger.info(f"Analysis type stats fetched for user {user_id}: {stats_data}")
             return jsonify(stats_data), 200 # OK, return stats dictionary
        else:
             # Log unexpected return type from handler.
             logger.error(f"db_handler.get_type_counts returned unexpected data type for user {user_id}: {type(stats_data)}")
             return jsonify({'error': 'Failed to fetch analysis type statistics due to a data format issue.'}), 500 # Internal Server Error

    except Exception as e:
        # Catch any unexpected errors during route handling.
        logger.exception(f"Unexpected error during analysis-type-stats route for user {current_user.id}.") # Log with traceback
        return jsonify({'error': 'Failed to fetch analysis type statistics due to an internal server error.'}), 500 # Generic error response

# --- ADDED: API Endpoint for Submitting User Feedback ---
@app.route('/submit-feedback', methods=['POST'])
@login_required # Requires user to be logged in to submit feedback
def submit_feedback():
    """API endpoint to receive user feedback (correct label) and append it to the training data file."""
    user_id = current_user.id
    logger.debug(f"Received submit-feedback request from user ID: {user_id}.")

    try:
        # Get feedback data from the JSON request body.
        data = request.get_json()
        item_data = data.get('item_data') # The URL or QR content string
        label = data.get('label')       # The correct label (0 or 1)

        # Validate received data
        if not item_data or label is None or label not in [0, 1]:
            logger.warning(f"Submit feedback request from user {user_id} missing or invalid data: item_data='{item_data}', label='{label}'.")
            return jsonify({'error': 'Invalid feedback data provided (item_data and label 0/1 are required).'}), 400 # Bad Request

        # Define the path to the training data file. This path must match the path used in fraud_detection_model_.py
        # when it attempts to load real data.
        # The path should be relative to the project root.
        # Assuming app.py is in 'Python scripts' and the data file is in 'Notebook'.
        # Construct the path by going up one level from app.py's directory to project_root, then into 'Notebook'.
        training_data_file_path = os.path.join(project_root, 'Notebook', 'your_real_data.csv')

        # Call the function in the database handler to append the feedback data to the file.
        # This function handles file operations and logs file writing errors internally.
        success = db_handler.append_training_data(training_data_file_path, item_data, label)

        if success:
            logger.info(f"User feedback saved to training data file '{os.path.basename(training_data_file_path)}' for user {user_id}. Item: '{item_data[:50]}...', Label: {label}")
            return jsonify({'success': True, 'message': 'Feedback submitted and saved.'}), 200 # OK
        else:
            # If db_handler function returns False, it failed to write to the file (error logged internally).
            logger.error(f"Failed to save user feedback to training data file '{training_data_file_path}' for user {user_id}.")
            return jsonify({'error': 'Failed to save feedback to training data file.'}), 500 # Internal Server Error (file writing issue)

    except Exception as e:
        # Catch any unexpected errors during route handling.
        logger.exception(f"Unexpected error during submit-feedback route for user {current_user.id}.") # Log with traceback
        return jsonify({'error': 'An internal server error occurred while submitting feedback.'}), 500 # Generic error response

# --- END ADDED ---


# --- Main Execution Block ---
# This code runs only when app.py is executed directly (e.g., `python app.py`).
# It sets up logging, loads/trains the model, and starts the Flask development server.
if __name__ == '__main__':
    # Logging configuration is already done at the top of the file.

    # --- Implement Model Loading/Training/Saving on App Startup ---
    # Initialize the detector (already done globally when module is loaded).

    # Flag to track if a usable model is available.
    model_ready = False

    # Attempt to load an existing trained model and scaler from disk.
    logger.info("Attempting to load the fraud detection model and scaler.")
    if detector.load_model():
        # If loading is successful, the model is ready for analysis.
        logger.info("Successfully loaded existing model and scaler.")
        model_ready = True
    else:
        # If loading failed (e.g., files missing, corrupted), attempt to train a new model.
        logger.warning("Existing model or scaler not found or loading failed. Proceeding to model training.")
        # --- Configure training data source for app startup ---
        # For the running application, we want it to train from the real data file IF IT EXISTS,
        # otherwise fall back to synthetic data.
        # Construct the path to the real data file relative to the project root.
        real_data_file_path_for_app = os.path.join(project_root, 'Notebook', 'your_real_data.csv') # Path relative to project root

        if os.path.exists(real_data_file_path_for_app):
             logger.info(f"Found real-world data file at '{real_data_file_path_for_app}'. Training using real data.")
             # Pass the file path to train_model. train_model calls load_real_data internally.
             if detector.train_model(data_path=real_data_file_path_for_app):
                 logger.info("Model training with real data completed successfully.")
                 if detector.save_model():
                      logger.info("Trained model and scaler saved successfully.")
                      model_ready = True
                 else:
                      logger.error("Model training successful, but failed to save the trained model! Analysis may still work for this session.")
                      model_ready = True # Model is in memory
             else:
                 logger.critical("Model training with real data failed. Fraud analysis functionality will be unavailable.")
                 model_ready = False
        else:
             # If no real data file found at the specified path, fall back to synthetic data training
             logger.warning(f"Real-world data file not found at '{real_data_file_path_for_app}'. Falling back to synthetic data training.")
             synthetic_samples_for_training = 10000
             logger.info(f"Starting synthetic data training with {synthetic_samples_for_training} samples.")
             if detector.train_model(n_samples=synthetic_samples_for_training): # Train with synthetic data
                 logger.info("Synthetic data training completed successfully.")
                 logger.info(f"Attempting to save the newly trained model and scaler to '{MODEL_DIR}'.")
                 if detector.save_model():
                      logger.info("Trained model and scaler saved successfully.")
                      model_ready = True
                 else:
                      logger.error("Model training successful, but failed to save the trained model! Analysis may still work for this session.")
                      model_ready = True
             else:
                 logger.critical("Synthetic data training failed. Fraud analysis functionality will be unavailable.")
                 model_ready = False
        # --- End Training Logic for App Startup ---


    # Check the model_ready flag before starting the Flask server.
    # If the model is not ready, log a critical warning. The application might still run,
    # but analysis endpoints will return errors as implemented in analyze_url/analyze_qr.
    if not model_ready:
        logger.critical("Application starting without a functional fraud detection model.")
        # Optional: Exit the application if a model is strictly required to run.
        # sys.exit(1)

    # --- Start the Flask Development Server ---
    logger.info("Starting Flask development server...")
    # Use debug=True for development, which provides helpful error messages and auto-reloading.
    # Set the port explicitly (standard is 5000).
    # In production, you would use a production WSGI server (like Gunicorn, uWSGI) instead of app.run().
    app.run(debug=True, port=5000)