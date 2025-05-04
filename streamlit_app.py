# This script creates the Streamlit user interface for the Fraud Detection System.
# It acts as a client that communicates with the Flask backend API (app.py)
# to perform analysis, manage history, and fetch statistics.

# --- Standard Library Imports ---
import json # Used for handling JSON data sent/received from the backend API
import os # Used for accessing environment variables (though less common in Streamlit apps calling APIs)
import io # Used for handling bytes streams (e.g., for file uploads)

# --- Third-Party Library Imports ---
# Ensure these are in your pyproject.toml and installed (uv sync or uv pip install .)
import streamlit as st # The Streamlit framework for building the UI
import requests # For making HTTP requests to the Flask backend API
import pandas as pd # Useful for displaying data in tables (like history)
# Required for charting
import altair as alt # Powerful charting library integrated with Streamlit
import logging # Import logging for potential debug messages


# --- Configuration and API Endpoints ---
# Define the base URL for your running Flask backend API.
# Ensure your Flask app (app.py) is running BEFORE starting this Streamlit app.
BACKEND_API_URL = "http://127.0.0.1:5000" # Default local Flask server address on port 5000

# Define the specific API endpoints the Streamlit app will call as constants.
# This makes the code cleaner and easier to maintain if endpoint paths change.
LOGIN_ENDPOINT = f"{BACKEND_API_URL}/login" # Endpoint for user login (POST)
REGISTER_ENDPOINT = f"{BACKEND_API_URL}/register" # Endpoint for user registration (POST)
LOGOUT_ENDPOINT = f"{BACKEND_API_URL}/logout" # Endpoint for user logout (POST)
STATUS_ENDPOINT = f"{BACKEND_API_URL}/status" # Endpoint to check login status and get user info (GET)
ANALYZE_URL_ENDPOINT = f"{BACKEND_API_URL}/analyze-url" # Endpoint for URL analysis (POST)
ANALYZE_QR_ENDPOINT = f"{BACKEND_API_URL}/analyze-qr" # Endpoint for QR code analysis (POST with file)
HISTORY_ENDPOINT = f"{BACKEND_API_URL}/history" # Used to fetch history data with filters (GET)
EXPORT_HISTORY_ENDPOINT = f"{BACKEND_API_URL}/export-history" # Used to trigger CSV export (GET with params)
CLEAR_HISTORY_ENDPOINT = f"{BACKEND_API_URL}/clear-history" # Used to clear history (POST)
ANALYZE_STATS_ENDPOINT = f"{BACKEND_API_URL}/analysis-stats" # Used to fetch risk level stats (risk distribution) (GET)
ANALYZE_TYPE_STATS_ENDPOINT = f"{BACKEND_API_URL}/analysis-type-stats" # Used to fetch analysis type stats (URL vs QR) (GET)
# GENERATE_QR_ENDPOINT = f"{BACKEND_API_URL}/generate-qr" # Optional: if Streamlit needs to generate QRs via backend (POST)

# --- ADDED: Endpoint for submitting feedback/labeling data ---
SUBMIT_FEEDBACK_ENDPOINT = f"{BACKEND_API_URL}/submit-feedback" # Endpoint to submit user feedback on analysis (POST)
# --- END ADDED ---


# --- Streamlit Page Configuration ---
# Configure the title, icon, and layout of the Streamlit page.
# This must be the first Streamlit command used.
st.set_page_config(
    page_title="Fraud Detection System", # Title displayed in the browser tab
    page_icon="🔍", # Emoji or path to an icon file
    layout="wide", # Use a wide layout for better use of horizontal screen space
    initial_sidebar_state="auto" # Initial state of the sidebar ('auto', 'expanded', 'collapsed')
)

# --- Custom CSS Injection for Styling Fixes ---
# Inject custom CSS into the Streamlit app using st.markdown with unsafe_allow_html=True.
# This is used for minor styling adjustments that cannot be done directly with Streamlit's components
# or via the .streamlit/config.toml theming file.
st.markdown("""
<style>
/* Fix for overlapping text ('Press Enter...') and the eye icon in Streamlit password input within forms. */
/* This targets the container that holds the eye icon and the 'Press Enter' text inside a password input within a form. */
/* We use data-testid attributes which are more stable internal Streamlit selectors than CSS classes. */
div[data-testid="stForm"] div[data-testid="stTextInput-inline-label-container"] > div > div:last-child > div[data-testid="stTextInput-After"] {
    /* Add padding to the left of this container to push the text away from the eye icon */
    padding-left: 10px !important; /* Adjust value as needed. !important helps ensure this style is applied. */
}

/* Optional: Further refine spacing or target the text span directly if needed */
/* div[data-testid="stForm"] div[data-testid="stTextInput-inline-label-container"] > div > div:last-child > div[data-testid="stTextInput-After"] span {
    padding-right: 5px !important;
} */

/* Add some space below Streamlit elements like forms and buttons */
/* This helps create visual separation between sections */
div.stForm {
    margin-bottom: 1.5rem;
    padding-bottom: 1.5rem; /* Add padding inside the form area itself */
    border: 1px solid rgba(0,0,0,0.1); /* Optional: Add a subtle border to forms */
    border-radius: 5px; /* Optional: Rounded corners for forms */
    padding: 1rem; /* Optional: Padding inside the form border */
}

/* Target specific elements to add vertical spacing consistently */
/* For example, add space below headers */
h1, h2, h3, h4 {
    margin-bottom: 1rem; /* Space below headings */
    padding-bottom: 0.5rem; /* Optional: Padding if you want a border below */
    /* border-bottom: 1px solid #eee; /* Optional: Border below headings */
}

/* Space below Streamlit elements within columns */
/* This can be tricky to apply generically, but sometimes useful */
/* div[data-testid="stVerticalBlock"] > div > div {
    margin-bottom: 1rem;
} */


/* Reduce default top margin on some input groups if they follow a subheader immediately */
/* This might be too specific, test carefully */
/* div[data-testid="stTextInput"] {
    margin-top: 0.5rem;
} */


/* Optional: Style for the dataframe display if needed */
/* .stDataFrame {
    border: 1px solid var(--border-color, #d1d5db);
    border-radius: 5px;
    padding: 5px;
} */

/* Target the image element within Streamlit's image component if specific sizing is needed */
/* This is less reliable than the width parameter in st.image but included for reference */
/* img {
    max-height: 300px; // Example: Limit max height for all images rendered by st.image
    width: auto !important; // Maintain aspect ratio
} */

</style>
""", unsafe_allow_html=True) # unsafe_allow_html=True is required to inject HTML/style tags


# --- Streamlit Session State Management ---
# Use st.session_state to persist variables across reruns.
# Streamlit reruns the script from top to bottom on each user interaction (button click, input change, etc.).
# Variables initialized here will persist across reruns if stored in st.session_state.

# Authentication state variables: track user login status and details.
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False # Boolean flag: True if user is logged in

if 'user_info' not in st.session_state:
    st.session_state['user_info'] = None # Stores user details dictionary

# Store a requests.Session object to handle cookies and maintain the session with the Flask backend.
# This object will persist across reruns and automatically handle session cookies for Flask-Login.
# Creating a new session object is necessary only when the app first starts or after explicit logout/session clear.
if 'requests_session' not in st.session_state:
    st.session_state['requests_session'] = requests.Session()

# Application data state variables for the logged-in sections: store fetched data for display.
if 'last_analysis_result' not in st.session_state:
    st.session_state['last_analysis_result'] = None # Stores the dictionary result of the most recent analysis

# State variables for History and Stats sections data
if 'history_data' not in st.session_state:
    st.session_state['history_data'] = [] # Stores fetched history items (list of dicts). Initialize as empty list.

if 'history_filters' not in st.session_state:
     st.session_state['history_filters'] = {} # Stores the dictionary of currently applied history filter values. Initialize as empty dict.

if 'risk_level_stats' not in st.session_state:
     st.session_state['risk_level_stats'] = None # Stores aggregated risk level counts (dict). Initialize as None or {}.

if 'type_stats' not in st.session_state:
     st.session_state['type_stats'] = None # Stores analysis type counts (dict). Initialize as None or {}.

# State variable for managing the "Clear History" confirmation step UI flow
if 'awaiting_clear_confirm' not in st.session_state:
     st.session_state['awaiting_clear_confirm'] = False # Flag to show confirmation buttons. Default to False.

# State variable for storing exported CSV data before download (needed for st.download_button)
if 'export_csv_data' not in st.session_state:
     st.session_state['export_csv_data'] = None # Stores the raw CSV bytes from the backend for the download button. Default to None.

# State variable to track if the last analysis was QR Code
if 'last_analysis_was_qr' not in st.session_state:
     st.session_state['last_analysis_was_qr'] = False # Default to False

# --- ADDED: State variable for feedback form ---
if 'show_feedback_form' not in st.session_state:
     st.session_state['show_feedback_form'] = False # Flag to show feedback form after analysis

if 'feedback_item' not in st.session_state:
     st.session_state['feedback_item'] = None # Stores the item data (URL) for which feedback is being submitted
# --- END ADDED ---

# --- Logging Configuration for Streamlit App ---
# Although not a backend, basic logging can be useful for debugging the Streamlit app itself
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamlit_logger = logging.getLogger(__name__)


# --- Backend API Interaction Helper Function ---
# IMPORTANT: This function must be defined *before* any other function that calls it.
# It's a general utility to make requests to the Flask backend using the persistent session.
def call_backend_api(endpoint, method="GET", json_data=None, files=None, params=None):
    """
    Makes an HTTP request to the specified backend API endpoint using the
    persistent requests.Session object stored in Streamlit's session state.
    Automatically handles session cookies via the session object.
    Displays common API error messages using Streamlit components.
    Args:
        endpoint (str): The full URL of the API endpoint (e.g., http://127.0.0.1:5000/login).
        method (str): The HTTP method ('GET', 'POST', 'DELETE').
        json_data (dict, optional): A dictionary to be sent as a JSON body (for POST requests). Defaults to None.
        files (dict, optional): A dictionary of files to upload (for file upload requests like analyze-qr). Defaults to None.
        params (dict, optional): A dictionary of URL query parameters (for GET requests like history). Defaults to None.
    Returns:
        tuple: (response_data, status_code) on success (status_code is 2xx and data is usually JSON dict/list),
               (None, status_code) on API error (status_code is 4xx or 5xx),
               (None, None) on network connection error.
               Note: For 204 No Content, response_data is None but status_code is 204.
    """
    try:
        # Use the requests.Session object stored in session state to make the request.
        # The session object automatically manages cookies for this session across different calls within a rerun.
        response = st.session_state['requests_session'].request(
            method,
            endpoint,
            json=json_data, # Send data as JSON body if json_data is provided
            files=files, # Send files if files dictionary is provided
            params=params # Send parameters in the URL query string if params dictionary is provided
        )

        # Handle common API error responses (non-2xx status codes)
        # These status codes are returned by the backend API on specific errors.
        if response.status_code == 401:
            # If 401 Unauthorized, it means authentication failed or session expired.
            streamlit_logger.warning(f"API call to {endpoint} returned 401 Unauthorized.")
            st.error("Authentication required. Your session may have expired. Please log in.")
            # Reset login state and trigger a UI rerun to show the login forms.
            st.session_state['logged_in'] = False
            st.session_state['user_info'] = None
            # Create a *new* requests session to discard any invalid cookies.
            st.session_state['requests_session'] = requests.Session()
            st.rerun() # Trigger a fresh rerun from the top to update UI
            return None, response.status_code # Indicate failure to the caller

        # Handle any other non-successful status codes (4xx or 5xx) returned by the backend.
        # Note: 204 No Content is handled as a successful status by requests, but has no body.
        if not response.ok and response.status_code != 204:
            try:
                # Try to get a specific error message from the backend's JSON response if available.
                error_detail = response.json().get('error', response.text)
            except json.JSONDecodeError:
                # If the response body is not valid JSON, use the raw response text as the error detail.
                error_detail = response.text
            streamlit_logger.error(f"API Error {response.status_code} from {endpoint}: {error_detail}")
            st.error(f"API Error {response.status_code}: {error_detail}") # Display error message to the user using Streamlit
            return None, response.status_code # Indicate failure to the caller (return None for data)

        # If response status code is OK (2xx, including 204), parse and return the data if available.
        if response.status_code == 204:
             streamlit_logger.debug(f"API call to {endpoint} returned 204 No Content.")
             return None, response.status_code # No content to return for 204
        else:
             try:
                # Attempt to parse the response body as JSON. This is expected for most API endpoints.
                data = response.json()
                streamlit_logger.debug(f"API call to {endpoint} successful, status {response.status_code}. Data (truncated): {json.dumps(data)[:200]}...")
                return data, response.status_code
             except json.JSONDecodeError:
                # Handle cases where a 2xx response was expected to contain JSON but did not (e.g., empty body, invalid JSON).
                streamlit_logger.error(f"API Error: Received valid status code ({response.status_code}) but invalid JSON response from {endpoint}. Response text: {response.text[:200]}...")
                st.error(f"API Error: Received valid status code ({response.status_code}) but invalid JSON response from {endpoint}")
                return None, response.status_code # Indicate failure (invalid response format)


    except requests.exceptions.ConnectionError:
        # Handle network errors where the backend server cannot be reached at all (e.g., server is down).
        streamlit_logger.critical(f"Connection error: Could not connect to backend API at {BACKEND_API_URL}.")
        st.error("Connection error: Could not connect to the backend API at {}. Please ensure the Flask server is running.".format(BACKEND_API_URL))
        return None, None # Indicate network failure (no status code from response)
    except Exception as e:
        # Catch any other unexpected exceptions that occur during the request process (e.g., issues with input data).
        streamlit_logger.exception(f"An unexpected error occurred during API call to {endpoint}.")
        st.error(f"An unexpected error occurred during API call to {endpoint}: {e}")
        return None, None # Indicate general error


# --- Authentication Functions using the API ---
# These functions handle user login, registration, and logout by calling the backend API.

# Checks the login status by calling the backend status endpoint.
# This function is called on every Streamlit rerun (at the top of the script)
# to update the UI based on the current session cookie.
def check_api_status():
    """Checks user authentication status with the backend API and updates session state."""
    # Call the backend status endpoint using the helper function.
    data, status_code = call_backend_api(STATUS_ENDPOINT, method="GET")
    # If the call was successful (status 200 OK) and the response data indicates logged_in: true...
    if status_code == 200 and data and data.get('is_logged_in'):
        st.session_state['logged_in'] = True # Set logged_in flag to True
        # Store user information received from the backend response. Use .get() for safety.
        st.session_state['user_info'] = {'email': data.get('email'), 'username': data.get('username')}
        # Avoid displaying a "Welcome back" success message on every rerun triggered by this status check.

    else:
        # If backend reports not logged in or if there was an API error (handled by call_backend_api),
        # ensure the logged_in state is False and user info is cleared.
        st.session_state['logged_in'] = False
        st.session_state['user_info'] = None


# Attempts to log in the user by sending credentials to the backend login endpoint.
# This function is called when the login form is submitted.
def login_user(email, password):
    """Attempts user login via backend API and updates session state."""
    # Prepare the data to be sent in the POST request body as JSON.
    json_data = {'email': email, 'password': password}
    # Call the backend login endpoint using the helper function.
    data, status_code = call_backend_api(LOGIN_ENDPOINT, method="POST", json_data=json_data)
    # If the API call was successful (status 200 OK) and the response data indicates success: true, and includes username...
    if status_code == 200 and data and data.get('success') and data.get('username'):
        st.session_state['logged_in'] = True # Set logged_in flag to True
        # Store user information from the backend response.
        st.session_state['user_info'] = {'email': data.get('email'), 'username': data.get('username')}
        st.success("Login successful!") # Display a success message to the user
        st.rerun() # Trigger a rerun to immediately display the logged-in sections of the UI.

    # Error messages for failed login attempts (e.g., 401 Invalid credentials)
    # are handled and displayed automatically by the call_backend_api helper function.


# Attempts to register a new user by sending data to the backend registration endpoint.
# This function is called when the registration form is submitted.
def register_user(email, username, password, confirm_password):
    """Attempts user registration via backend API."""
    # Client-side password validation before sending data to the API.
    if password != confirm_password:
        st.warning("Passwords do not match.") # Display a warning message
        return # Stop execution if validation fails
    if len(password) < 6: # Example minimum length validation
         st.warning("Password must be at least 6 characters long.") # Display a warning
         return
     # Add other client-side validation (e.g., basic email format check) if needed.

    # Prepare the data to be sent in the POST request body as JSON.
    json_data = {'email': email, 'username': username, 'password': password}
    # Call the backend registration endpoint using the helper function.
    data, status_code = call_backend_api(REGISTER_ENDPOINT, method="POST", json_data=json_data)
    # If the API call was successful (status 201 Created) and the response data indicates success...
    if status_code == 201 and data and data.get('success'):
        st.success("Registration successful! You can now log in using the form on the left.") # Display success message
        # Optional: Clear the registration form fields after successful registration.
        # This might involve resetting the specific session state keys used for the form inputs if they are set to persist input values.
        # Example: del st.session_state['reg_email_input'] # Requires using keys for persistence in text_input
    # Error messages for registration failures (e.g., 409 Conflict, 400 Bad Request)
    # are handled and displayed by the call_backend_api helper function.


# Attempts to log out the current user by calling the backend logout endpoint.
# This function is called when the logout button is clicked.
def logout_user():
    """Attempts user logout via backend API and updates session state."""
    # Call the backend logout endpoint using the helper function.
    data, status_code = call_backend_api(LOGOUT_ENDPOINT, method="POST")
    # Backend should return 200 OK on successful logout.
    if status_code == 200 and data and data.get('success'):
        st.success("Logged out successfully.") # Display success message
        # Clear all relevant session state variables upon successful logout.
        st.session_state['logged_in'] = False
        st.session_state['user_info'] = None
        st.session_state['last_analysis_result'] = None # Clear previous analysis result display
        st.session_state['history_data'] = [] # Clear history data
        st.session_state['history_filters'] = {} # Clear history filters
        st.session_state['risk_level_stats'] = None # Clear stats data
        st.session_state['type_stats'] = None # Clear stats data
        st.session_state['awaiting_clear_confirm'] = False # Clear confirmation flag
        st.session_state['export_csv_data'] = None # Clear export data
        st.session_state['last_analysis_was_qr'] = False # Clear QR analysis flag
        st.session_state['show_feedback_form'] = False # Clear feedback form state
        st.session_state['feedback_item'] = None # Clear feedback item state
        # Create a *new* requests.Session object to ensure no old cookies are retained for future logins.
        st.session_state['requests_session'] = requests.Session()
        st.rerun() # Trigger a rerun to immediately display the logged-out (login/register) UI


    # Error messages for logout failures are handled by call_backend_api (less common).


# --- Functions to Interact with Analysis Endpoints ---
# These functions call backend API for analysis and update session state with results.

# Calls the backend API to analyze a URL and updates the analysis result in session state.
def analyze_url_api(url):
    """Calls the backend API to analyze a URL and updates the analysis result in session state."""
    # Display a temporary message indicating analysis is in progress.
    st.info(f"Analyzing URL: {url[:50]}{'...' if len(url) > 50 else ''}...") # Display truncated URL

    # Call the backend API's analyze-url endpoint using the helper function.
    analysis_response_data, status_code = call_backend_api(ANALYZE_URL_ENDPOINT, method="POST", json_data={'url': url})

    # Check if the API call was successful (status 2xx).
    if analysis_response_data: # Data is None if call_backend_api displayed an error
        st.session_state['last_analysis_result'] = analysis_response_data # Store the analysis result dictionary in session state.
        st.session_state['last_analysis_was_qr'] = False # Set flag: last analysis was NOT QR
        st.session_state['show_feedback_form'] = True # Show feedback form after analysis
        st.session_state['feedback_item'] = url # Store the analyzed item for feedback

        # Check for a 'save_error' flag from the backend, which indicates analysis was OK but saving history failed.
        if analysis_response_data.get('save_error'):
             st.warning("Analysis complete, but results could not be saved to history.")
        else:
             st.success("Analysis complete and saved to history.")
             # If analysis was successful AND saving was successful, reload history and stats
             # to include the new item in the displayed list and charts.
             # Need to call these functions to fetch updated data after a successful save.
             load_history_api(st.session_state['history_filters']) # Reload history with current filters
             load_stats_api() # Reload stats

    else: # If API call failed (status 4xx or 5xx), call_backend_api already displayed the error message.
        st.session_state['last_analysis_result'] = None # Clear any previous result on error.
        st.session_state['last_analysis_was_qr'] = False # Set flag: last analysis was NOT QR (error occurred)
        st.session_state['show_feedback_form'] = False # Don't show feedback on error
        st.session_state['feedback_item'] = None

    st.rerun() # Trigger a rerun to update the UI and display the analysis result or clear the result area on error.


# Calls the backend API to analyze a QR code image file and updates the analysis result in session state.
# Requires the uploaded file object from st.file_uploader.
def analyze_qr_api(uploaded_file):
    """Calls the backend API to analyze a QR code image file and updates the analysis result in session state."""
    # Display a temporary message indicating analysis is in progress.
    st.info(f"Analyzing QR code from file: {uploaded_file.name}...")

    try:
        # Prepare the file data for sending in the 'files' parameter of the requests call.
        # The format is a dictionary mapping the expected backend field name ('file') to a tuple:
        # ('filename', file_content_as_bytes, 'content_type').
        # uploaded_file.getvalue() reads the file's content as bytes. uploaded_file.type gets the MIME type.
        files_to_send = {'file': (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}

        # Call the backend API's analyze-qr endpoint using the helper function, sending the file.
        analysis_response_data, status_code = call_backend_api(ANALYZE_QR_ENDPOINT, method="POST", files=files_to_send)

        # Check if the API call was successful (status 2xx).
        if analysis_response_data: # Data is None if call_backend_api displayed an error
            st.session_state['last_analysis_result'] = analysis_response_data # Store the analysis result dictionary.
            st.session_state['last_analysis_was_qr'] = True # Set flag: last analysis WAS QR
            st.session_state['show_feedback_form'] = True # Show feedback form after analysis
            # Store the decoded URL (if available) or filename for feedback.
            st.session_state['feedback_item'] = analysis_response_data.get('url', analysis_response_data.get('item_data', 'N/A'))

             # Check for a 'save_error' flag from the backend.
            if analysis_response_data.get('save_error'):
                 st.warning("Analysis complete, but results could not be saved to history.")
            else:
                 st.success("Analysis complete and saved to history.")
                 # If analysis was successful AND saving was successful, reload history and stats.
                 load_history_api(st.session_state['history_filters'])
                 load_stats_api()

        else: # If API call failed (status 4xx or 5xx), call_backend_api displayed the error message.
            st.session_state['last_analysis_result'] = None # Clear previous result on error.
            st.session_state['last_analysis_was_qr'] = False # Set flag: last analysis was NOT QR (error occurred)
            st.session_state['show_feedback_form'] = False # Don't show feedback on error
            st.session_state['feedback_item'] = None

    except Exception as e:
        # Catch any errors specifically during file reading or preparing data for the API call.
        st.error(f"Error preparing QR file '{uploaded_file.name}' for analysis: {e}")
        st.session_state['last_analysis_result'] = None # Clear result on error.
        st.session_state['last_analysis_was_qr'] = False # Set flag: last analysis was NOT QR (error occurred)
        st.session_state['show_feedback_form'] = False # Don't show feedback on error
        st.session_state['feedback_item'] = None

    st.rerun() # Trigger a rerun to update the UI and display the results or clear the result area on error.


# --- Functions to Interact with History Endpoints ---
# These functions call backend API for history data and actions.

# Calls the backend API to fetch user's analysis history with filters and updates session state.
def load_history_api(filters):
    """Calls the backend API to fetch user's analysis history with filters and updates session state."""
    # Display a loading message (optional)
    # st.info("Loading history...") # Optional loading message

    # Call the backend history endpoint using the helper function.
    # Pass the filters dictionary as URL query parameters.
    data, status_code = call_backend_api(HISTORY_ENDPOINT, method="GET", params=filters)

    # Check if the API call was successful (status 200 OK) and the data received is a list (expected format).
    if status_code == 200 and isinstance(data, list):
        st.session_state['history_data'] = data # Store the fetched history data (list of dicts) in session state.
        streamlit_logger.debug(f"Loaded {len(data)} history items.") # Log count
        # st.success(f"Loaded {len(data)} history items.") # Avoid success message on every history load

    elif status_code == 204: # Backend returned 204 No Content (indicates no history found matching filters)
         st.session_state['history_data'] = [] # Set history data to an empty list.
         streamlit_logger.debug("History load returned 204 No Content (no items).")
         # st.info("No history found matching filters.") # Message handled by UI display logic below based on empty list.

    else: # API call failed (error message displayed by call_backend_api).
        st.session_state['history_data'] = [] # Clear history data on error.
        streamlit_logger.warning("History load failed or returned non-list data.")


    # Note: No explicit st.rerun() needed within this function if it's called *before* the history list is rendered
    # in the main script loop (e.g., on initial logged-in display or by the Apply Filters button).
    # The functions calling load_history_api should trigger reruns if needed after calling this.


# Calls the backend API to clear user's entire history.
# This function is called when the "Yes, Confirm Clear History" button is clicked.
def clear_history_api():
    """Calls the backend API to clear user's history."""
    # Display a message indicating the clearing process is underway.
    st.info("Clearing all history...")

    # Call the backend clear history endpoint using the helper function (POST request).
    # No JSON data or files are needed for this endpoint based on the backend implementation.
    data, status_code = call_backend_api(CLEAR_HISTORY_ENDPOINT, method="POST")

    # If the API call was successful (status 200 OK) and backend reports success...
    if status_code == 200 and data and data.get('success'):
        st.success("All history cleared successfully.") # Display success message.
        streamlit_logger.info("History cleared successfully via API.")
        # Clear history data and stats in session state upon successful backend clear.
        # This updates the displayed history list and charts on the next rerun.
        st.session_state['history_data'] = []
        st.session_state['risk_level_stats'] = None # Stats are cleared as history is gone
        st.session_state['type_stats'] = None # Stats are cleared as history is gone
        st.session_state['awaiting_clear_confirm'] = False # Reset confirmation flag
        st.session_state['export_csv_data'] = None # Clear export data
        st.session_state['last_analysis_result'] = None # Clear analysis result too? (Depends on desired UI flow)
        st.session_state['last_analysis_was_qr'] = False # Clear QR flag
        st.session_state['show_feedback_form'] = False # Clear feedback form state
        st.session_state['feedback_item'] = None # Clear feedback item state
        st.rerun() # Trigger a rerun to update UI (display empty history list, no charts).

    else:
         streamlit_logger.error(f"History clear API failed with status {status_code}.")
    # Error message handled by call_backend_api for failure status codes.


# Calls the backend API to export filtered history as a CSV file.
# This function fetches the data and stores it in session state for the download button.
def export_history_api(filters):
    """Fetches filtered history data as CSV from backend API and stores it for download."""
    st.info("Fetching export data...") # Display temporary message

    try:
        # Use the requests.Session object directly for more control over non-JSON response type (CSV).
        # Use GET method and pass filters as URL parameters.
        # The /export-history endpoint is designed to return raw CSV bytes.
        response = st.session_state['requests_session'].get(EXPORT_HISTORY_ENDPOINT, params=filters)

        # Check for common Streamlit-handled errors first (like 401)
        # Manual handling needed here as call_backend_api assumes JSON response on success.
        if response.status_code == 401:
             streamlit_logger.warning(f"Export history request returned 401 Unauthorized.")
             # call_backend_api handles 401 and triggers rerun, but direct request needs its own handling.
             st.error("Authentication required to export history. Your session may have expired. Please log in.")
             st.session_state['logged_in'] = False
             st.session_state['user_info'] = None
             st.session_state['requests_session'] = requests.Session() # New session
             st.rerun()
             st.session_state['export_csv_data'] = None # Clear export data
             return # Stop here

        if not response.ok and response.status_code != 204: # Handle other API errors (e.g., 400, 500). 204 is successful No Content.
             try: # Attempt to get error details from backend if response is JSON (unlikely for export, but defensive)
                 error_detail = response.json().get('error', response.text)
             except json.JSONDecodeError: # If not JSON, use raw text
                 error_detail = response.text
             streamlit_logger.error(f"API Error {response.status_code} during export fetch: {error_detail}")
             st.error(f"API Error {response.status_code}: Failed to fetch export data: {error_detail}")
             st.session_state['export_csv_data'] = None # Clear any previous export data
             return # Stop here

        # If response is OK (status 200) or 204 (No Content)
        if response.status_code == 204: # Backend returned 204 No Content (no history found matching filters)
             streamlit_logger.info("Export history returned 204 No Content (no items).")
             st.info("No history found matching filters to export.")
             st.session_state['export_csv_data'] = None # Ensure no previous export data is available for download
        elif response.status_code == 200: # Backend returned CSV data (status 200 OK with body)
             streamlit_logger.info("Export history data fetched successfully.")
             # Store the raw CSV content (bytes) in session state.
             st.session_state['export_csv_data'] = response.content
             st.success("Export data generated. Click 'Download CSV' below.")
             # No explicit rerun needed here, the presence of st.session_state['export_csv_data'] triggers the download button display.
        else:
            # Handle any other unexpected 2xx statuses (unlikely for this endpoint)
            streamlit_logger.error(f"Unexpected status code {response.status_code} received during export fetch.")
            st.error(f"Unexpected status code {response.status_code} received during export fetch.")
            st.session_state['export_csv_data'] = None

    except requests.exceptions.ConnectionError:
         streamlit_logger.critical(f"Connection error: Could not connect to backend API for export at {BACKEND_API_URL}.")
         st.error("Connection error: Could not connect to the backend API for export. Please ensure the Flask server is running.")
         st.session_state['export_csv_data'] = None # Clear export data
    except Exception as e:
         streamlit_logger.exception(f"An unexpected error occurred during export data fetch.")
         st.error(f"An unexpected error occurred during export data fetch: {e}")
         st.session_state['export_csv_data'] = None


# --- Functions to Interact with Statistics Endpoints ---
# These functions call backend API for stats data and update session state.

# Calls backend API to fetch analysis statistics (risk levels and type counts) and updates session state.
# This function is called when the logged-in section is first displayed or after history changes (analysis save, clear).
def load_stats_api():
    """Calls backend API to fetch analysis statistics (risk levels and types) and updates session state."""
    # Display loading message (optional)
    # st.info("Loading statistics...")

    # --- Fetch Risk Level Stats ---
    # Call the backend endpoint for risk level stats using the helper function.
    risk_stats_data, risk_status_code = call_backend_api(ANALYZE_STATS_ENDPOINT, method="GET")
    # Check if the API call was successful (status 200 OK) and the data received is a dictionary (expected format).
    if risk_status_code == 200 and isinstance(risk_stats_data, dict):
        st.session_state['risk_level_stats'] = risk_stats_data # Store the stats dictionary
        streamlit_logger.debug(f"Fetched risk level stats: {risk_stats_data}") # Log fetched data
        # st.success("Risk level stats loaded.")
    else: # If API call failed (status 4xx/5xx) or data format is wrong, call_backend_api displays error.
        st.session_state['risk_level_stats'] = None # Clear stats on error.


    # --- Fetch Analysis Type Stats ---
    # Call the backend endpoint for analysis type stats.
    type_stats_data, type_status_code = call_backend_api(ANALYZE_TYPE_STATS_ENDPOINT, method="GET")
    # Check if the API call was successful (status 200 OK) and the data is a dictionary (expected format).
    if type_status_code == 200 and isinstance(type_stats_data, dict):
        st.session_state['type_stats'] = type_stats_data # Store the stats dictionary
        streamlit_logger.debug(f"Fetched type stats: {type_stats_data}") # Log fetched data
        # st.success("Type stats loaded.")
    else: # If API call failed or data format is wrong, call_backend_api displays error.
        st.session_state['type_stats'] = None # Clear stats on error.

    # Note: No explicit st.rerun() needed within this function if it's called *before* the stats section is displayed,
    # as the main script loop will render it with the updated session state.


# --- ADDED: Function to Submit User Feedback on Analysis ---
def submit_feedback_api(item_data, correct_label):
    """Calls the backend API to submit user feedback (correct label) for an analyzed item."""
    st.info(f"Submitting feedback for '{item_data[:50]}{'...' if len(item_data) > 50 else ''}': {'Fraudulent' if correct_label == 1 else 'Legitimate'}...")
    # Prepare JSON data with the item data (URL/QR content) and the correct label (0 or 1).
    json_data = {'item_data': item_data, 'label': correct_label}
    # Call the new backend endpoint using the helper function.
    data, status_code = call_backend_api(SUBMIT_FEEDBACK_ENDPOINT, method="POST", json_data=json_data)

    # Check if the API call was successful (e.g., 200 OK).
    if status_code == 200 and data and data.get('success'):
        st.success("Feedback submitted successfully! Thank you for helping improve the model.")
        # Clear the feedback form state after submission
        st.session_state['show_feedback_form'] = False
        st.session_state['feedback_item'] = None
    # Error message handled by call_backend_api for failure status codes.

    st.rerun() # Trigger a rerun to update UI (hide feedback form, show success/error messages).
# --- END ADDED ---


# --- Main Application UI Layout ---

# Check the user's authentication status with the backend API on each script rerun.
# This function calls the /status endpoint and updates st.session_state['logged_in'] and 'user_info'.
# This ensures the correct UI (logged-in vs. logged-out) is displayed on each rerun.
check_api_status()

# Set the main title for the application page.
st.title("Fraud Detection System")

# Conditional rendering: Display different content based on the user's login status.
if st.session_state['logged_in']:
    # --- Content displayed when the user is logged in ---

    user_info = st.session_state['user_info']
    # Display a welcome message showing the logged-in username. Use .get() for safety.
    st.write(f"Welcome, **{user_info.get('username', 'User')}**!")

    # Add a logout button. Using a form prevents unintended reruns when interacting
    # with other widgets on the page. The button click triggers the logout function.
    with st.form("logout_form", clear_on_submit=False):
        st.write(" ") # Add a small vertical space above the button for layout
        # The submit button for the form. When clicked, the code inside the 'with' block reruns.
        if st.form_submit_button("Logout"):
            logout_user() # Call the logout function when the button is clicked

    # --- Main sections for logged-in users (Analysis, History, Statistics) ---
    # These sections are displayed below the welcome message and logout button.

    st.header("Analysis Tools")
    # Section containing UI elements for performing URL and QR code analysis.

    st.subheader("Analyze URL")
    # Text input widget for the user to enter a URL. Use a unique key for the widget.
    url_input = st.text_input("Enter URL to analyze:", key="url_input_key")

    # Button to trigger URL analysis.
    if st.button("Analyze URL"):
        if url_input:
             # Call the function that handles the backend API call for URL analysis.
             analyze_url_api(url_input) # This function updates session state and triggers rerun
        else:
            st.warning("Please enter a URL to analyze.") # Display warning if input is empty


    st.subheader("Analyze QR Code")
    # File uploader widget for selecting a QR code image file from the user's computer.
    # Restrict accepted file types to common image formats. Use a unique key.
    uploaded_file = st.file_uploader("Upload QR code image:", type=["png", "jpg", "jpeg"], key="qr_uploader_key")

    # --- Logic to clear the analysis result when the QR uploader is cleared ---
    # Check if the 'qr_uploader_key' widget exists in session state (meaning it was displayed in the previous rerun)
    # AND if the current value of the uploader is None (meaning the user cleared it by clicking the 'x')
    # AND if the last analysis performed was a QR code analysis.
    # Streamlit updates widget state *before* running the script, so uploaded_file is None if cleared this rerun.
    if 'qr_uploader_key' in st.session_state and st.session_state['qr_uploader_key'] is None and st.session_state.get('last_analysis_was_qr', False):
         # If these conditions are met, clear the last analysis result from session state.
         st.session_state['last_analysis_result'] = None
         st.session_state['last_analysis_was_qr'] = False # Reset the flag
         st.session_state['show_feedback_form'] = False # Hide feedback form if QR cleared
         st.session_state['feedback_item'] = None
         # Streamlit will automatically rerun because the uploader widget state changed to None.
         # An explicit st.rerun() is typically not needed here, but can be added if necessary.
         st.info("QR code image and analysis result cleared.") # Display feedback


    # Display a preview of the uploaded image if a file has been selected.
    if uploaded_file is not None:
        # The file content is available as bytes via uploaded_file.getvalue().
        # Use the 'width' parameter to control the displayed size of the image preview in pixels.
        st.image(uploaded_file, caption=f"Uploaded QR Code: {uploaded_file.name}", width=300) # Display image with fixed width


        # Add an Analyze QR Code button below the image preview.
        # This button press will trigger the analysis process for the uploaded file.
        if st.button("Analyze QR Code"):
            # Call the function that handles the backend API call for QR code analysis.
             analyze_qr_api(uploaded_file) # This function updates session state and triggers rerun


    st.subheader("Analysis Results")
    # Display the result of the most recent analysis performed.
    # The analysis result dictionary is stored in st.session_state['last_analysis_result'].
    # Check if there is a result stored before attempting to display it.
    if st.session_state['last_analysis_result']: # Check if the result is not None
        result = st.session_state['last_analysis_result']
        # Safely get results, providing defaults
        is_fraud = result.get('is_fraud', False)
        risk_level = result.get('risk_level', 'Unknown')
        confidence = result.get('confidence', 0)
        risk_factors = result.get('risk_factors', [])
        analyzed_item_data = result.get('url', result.get('item_data', 'N/A')) # Get the item data for feedback


        # --- IMPROVED UI DISPLAY FOR ANALYSIS RESULTS ---
        # Use a Streamlit container to group analysis results visually.
        with st.container(border=True): # Add a border around the results for clarity
            st.write(f"**Analyzed Item:** {analyzed_item_data}") # Display the analyzed data (URL or QR content)

            # Display the main status (Fraudulent/Not Fraudulent) using a colored message box for clarity.
            if is_fraud:
                st.error(f"**Status:** Fraudulent") # Red box for fraudulent status
            else:
                st.success(f"**Status:** Not Fraudulent") # Green box for not fraudulent status

            # Display Risk Level and Confidence below the main status.
            st.write(f"**Risk Level:** {risk_level}")
            st.write(f"**Confidence:** {confidence:.2f}%") # Format confidence as percentage

            # Display risk factors if the list is not empty.
            if risk_factors:
                 st.write("**Risk Factors:**")
                 # Format the list of factors as bullet points using Streamlit's Markdown support.
                 st.markdown("- " + "\n- ".join(risk_factors))
            else:
                 st.write("**Risk Factors:** No specific factors identified by heuristics.") # Default message if list is empty

            # --- ADDED: User Feedback Form ---
            # Show this form only if the flag is set after a successful analysis.
            if st.session_state.get('show_feedback_form', False):
                 st.write("---") # Horizontal rule for visual separation
                 st.write("Was this analysis correct?")
                 # Use radio buttons to get the correct label feedback.
                 feedback_label = st.radio(
                     "Correct Label:",
                     ["Select one", "Legitimate", "Fraudulent"], # Options for feedback
                     index=0, # Default to "Select one"
                     key="feedback_label_radio" # Unique key for the widget
                 )

                 # Button to submit feedback.
                 # Only show the submit button if a label is selected (not "Select one").
                 if feedback_label in ["Legitimate", "Fraudulent"]:
                      # Add a unique key to the button
                      if st.button("Submit Feedback", key="submit_feedback_button"):
                           # Map "Legitimate" to label 0 and "Fraudulent" to label 1.
                           correct_label_value = 1 if feedback_label == "Fraudulent" else 0
                           # Call the function to submit feedback to the backend API.
                           submit_feedback_api(st.session_state['feedback_item'], correct_label_value)
                           # submit_feedback_api handles hiding the form and showing success/error.
            # --- END ADDED: User Feedback Form ---


    else:
        # Display a message prompting the user to perform an analysis when no result is available.
        st.info("Submit a URL or QR code image for analysis. Results will appear here.")


    st.header("History and Statistics")
    # Section for viewing analysis history and overview statistics (charts).

    st.subheader("Analysis History")

    # --- History Filtering UI ---
    # Use Streamlit columns to arrange filter controls horizontally within this section.
    # Adjust the column width ratios [2, 2, 3, 1] as needed to fit the content.
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([2, 2, 3, 1])

    with filter_col1:
         # Select box widget for filtering history by item type (URL or QR Code).
         type_filter_value = st.selectbox(
             "Type:", # Label for the select box
             ["All", "URL", "QR Code"], # Options for filtering
             key="history_type_filter_sb" # Use a unique key for the widget
         )
         # Map the selected display string to the parameter string expected by the backend API.
         type_filter_param = "url" if type_filter_value == "URL" else ("qr" if type_filter_value == "QR Code" else "all")


    with filter_col2:
         # Select box widget for filtering history by risk level.
         risk_filter_value = st.selectbox(
             "Risk:", # Label
             ["All", "Fraudulent", "Not Fraudulent", "Critical", "High", "Medium", "Low", "Safe", "Unknown", "Error", "Invalid Result"], # Options matching backend levels/flags + new ones
             key="history_risk_filter_sb" # Unique key
         )
         # Map the selected display string to the parameter dictionary expected by the backend API.
         # This mapping should match the logic in the backend's get_history route.
         risk_filter_param = None # Initialize parameter dictionary to None
         if risk_filter_value == "Fraudulent":
              # If "Fraudulent" is selected, set the 'is_fraud' parameter to 'true' string.
              risk_filter_param = {'is_fraud': 'true'}
         elif risk_filter_value == "Not Fraudulent":
              # If "Not Fraudulent" is selected, set the 'is_fraud' parameter to 'false' string.
              risk_filter_param = {'is_fraud': 'false'}
         elif risk_filter_value != "All":
              # If a specific risk level is selected (not "All" or the fraud flags),
              # set the 'risk_level' parameter.
              # Check if the selected value is one of the valid risk level strings
              valid_risk_levels = ["Critical", "High", "Medium", "Low", "Safe", "Unknown", "Error", "Invalid Result"] # Match values from backend/frontend display
              if risk_filter_value in valid_risk_levels:
                risk_filter_param = {'risk_level': risk_filter_value}
              else:
                  # Handle unexpected risk filter value, treat as 'All' or log warning
                  streamlit_logger.warning(f"Received unexpected risk filter value in UI: '{risk_filter_value}'. Treating as 'All'.")
                  risk_filter_param = None


    with filter_col3:
        # Text input widget for searching within history item data.
        search_term_value = st.text_input(
            "Search in data:", # Label for search input
            key="history_search_term_ti" # Unique key
        )
        # Prepare the search parameter dictionary if a search term is entered.
        search_filter_param = {'search': search_term_value} if search_term_value else None


    # Combine the current filter values from the widgets into the session state dictionary.
    # This ensures st.session_state['history_filters'] always reflects the current UI state.
    # Note: Filter values update session state on EVERY rerun caused by ANY widget interaction.
    # The 'Apply Filters' button click then uses the *current* state of this dictionary.
    st.session_state['history_filters'] = {} # Reset the dictionary each rerun (based on current filter values)
    if type_filter_param != "all":
         st.session_state['history_filters']['type'] = type_filter_param
    if risk_filter_param:
        st.session_state['history_filters'].update(risk_filter_param) # Use update() to merge the risk/is_fraud parameter dictionary into the main filters dictionary.
    if search_filter_param:
         st.session_state['history_filters'].update(search_filter_param) # Use update() to merge the search parameter dictionary into the main filters dictionary.


    with filter_col4:
         # Add a button to explicitly apply the filters.
         # Placing it in a separate column can help with layout.
         st.write(" ") # Add vertical space to align the button with inputs if needed
         # The button triggers the history loading process when clicked.
         # This is a standard button outside any specific form for this section.
         if st.button("Apply Filters"):
              # Call the function to load history data with the current filters.
              load_history_api(st.session_state['history_filters'])
              # Trigger a rerun to update the displayed history list.
              st.rerun() # Use st.rerun()


    # --- Display History List ---
    st.subheader("History Items")

    # Load initial history data when the logged-in section is first displayed,
    # but only if the history data is not already loaded in session state.
    # This prevents re-fetching history on every single widget interaction that causes a rerun.
    # The "Apply Filters" button handles subsequent re-fetching.
    # Check if history_data is None (initial state before first load attempt) or empty AND logged in AND NO filters set.
    # If filters ARE set on initial load, we only load when 'Apply Filters' is clicked.
    if (st.session_state['history_data'] is None or (not st.session_state['history_data'] and not st.session_state['history_filters'])) and st.session_state['logged_in']:
         # Load history with current (initial or previously set by filters) filters.
         load_history_api(st.session_state['history_filters'])
         # Note: load_history_api does NOT trigger a rerun itself. The main script continues execution.


    # Check if history data is available in session state to display it.
    if st.session_state['history_data']:
        # Convert the list of history item dictionaries into a pandas DataFrame for display.
        # This makes it easy to display a table using st.dataframe.
        history_df_rows = [] # List to build DataFrame rows
        for item in st.session_state['history_data']:
            # Safely get analysis result details from the nested dictionary.
            result = item.get('analysis_result', {}) # Default to empty dict if result is missing
            history_df_rows.append({
                "ID": item.get('id', 'N/A'), # Use .get() with default for safety
                "Type": item.get('item_type', 'Unknown'),
                "Data": item.get('item_data', 'N/A'),
                "Risk Level": result.get('risk_level', 'Unknown'),
                "Confidence (%)": result.get('confidence', 0),
                "Fraudulent": result.get('is_fraud', False), # Boolean value for fraud flag
                "Analyzed At": item.get('analyzed_at', 'N/A'),
                "Risk Factors": ", ".join(result.get('risk_factors', [])) # Join list of factors into a string
            })

        # Create the pandas DataFrame.
        history_df = pd.DataFrame(history_df_rows)

        # Display the DataFrame as an interactive table.
        # use_container_width=True makes the table fill the available width.
        st.dataframe(history_df, use_container_width=True)

        # TODO: Add deletion functionality for individual history items.
        # This is complex with st.dataframe directly. It typically involves
        # manually rendering rows or finding a Streamlit component that supports per-row buttons.
        # If implementing, the button for a row would need to call `delete_history_item(item_id)` via API.
        # st.write("*(Deletion functionality for individual items is a future enhancement)*")


    elif not st.session_state['history_filters']:
        # Display a message if history is empty *and* no filters are currently applied.
        st.info("No analysis history yet. Your analyses will appear here.")
    else:
        # Display a message if history is empty *but* filters are applied.
        st.info("No history found matching the current filters.")


    # --- History Action Buttons (Clear and Export) ---
    st.subheader("History Actions")
    # Use columns to place buttons side-by-side.
    clear_col, export_col = st.columns(2)

    with clear_col:
         # Button to clear all history for the user. Requires confirmation dialog.
         st.write("Clear all your analysis history.")
         # Use a standard button to trigger the confirmation flow.
         # Only show this button if we are NOT currently awaiting confirmation.
         if not st.session_state.get('awaiting_clear_confirm', False):
              # Add a unique key to the button
              if st.button("Clear All History", key="trigger_clear_confirm_button"):
                   # Set a flag in session state to indicate that confirmation is needed.
                   st.session_state['awaiting_clear_confirm'] = True
                   st.rerun() # Trigger a rerun to show the confirmation UI

         # Display confirmation message and buttons IF the confirmation flag is set.
         # THESE BUTTONS MUST BE OUTSIDE ANY st.form BLOCK.
         if st.session_state.get('awaiting_clear_confirm', False):
             st.warning("Are you sure you want to clear ALL your history? This cannot be undone.")
             # Use columns for the confirmation buttons to place them side-by-side.
             confirm_yes_col, confirm_cancel_col = st.columns(2)
             with confirm_yes_col:
                  # The button that performs the clear action if confirmed.
                  # This must be st.button. Add unique key.
                  if st.button("Yes, Confirm Clear History", key="confirm_clear_yes_button"):
                       clear_history_api() # Call the function to clear history via API
                       # clear_history_api handles resetting the awaiting_clear_confirm flag and rerunning.
             with confirm_cancel_col:
                  # The button to cancel the clear operation.
                  # This must be st.button. Add unique key.
                  if st.button("Cancel", key="confirm_clear_cancel_button"):
                       st.info("History clear cancelled.")
                       st.session_state['awaiting_clear_confirm'] = False # Clear the confirmation flag
                       st.rerun() # Use st.rerun() explicitly to dismiss the confirmation UI


    with export_col:
         # Button to export filtered history to CSV.
         st.write("Export your filtered history to CSV.")
         # Button to trigger the process of fetching export data from the backend.
         # When this button is clicked, it calls export_history_api to fetch data and store it in session state.
         if st.button("Generate Export CSV"):
             export_history_api(st.session_state['history_filters']) # This function fetches data & updates session state['export_csv_data']
             # export_history_api handles displaying status messages (fetching, no data, success, error).
             # A rerun is NOT explicitly needed here within the button, as updating session state usually triggers one.

         # Display the download button ONLY if the export data is available in session state.
         # st.download_button renders a button that, when clicked, serves the provided 'data'.
         # The 'data' must be available *when st.download_button is rendered*.
         # export_history_api fetches the data and stores it as bytes in 'export_csv_data'.
         if 'export_csv_data' in st.session_state and st.session_state['export_csv_data'] is not None:
             st.download_button(
                 label="Download CSV", # Label for the download button
                 data=st.session_state['export_csv_data'], # The actual data to download (bytes)
                 file_name="fraud_detection_history_export.csv", # Suggested filename for the downloaded file
                 mime="text/csv", # MIME type for CSV files
                 key="download_history_button" # Use a unique key for the widget
                 # Optional: on_click callback to clear st.session_state['export_csv_data'] after button is displayed (doesn't track actual download click)
             )
             # Optional: Clear the export data from session state after download button appears
             # This would hide the download button after a rerun, forcing the user to click "Generate" again.
             # del st.session_state['export_csv_data'] # Uncomment if you want to clear it on the next rerun


    st.subheader("Analysis Overview (Stats)")
    # Section for data visualization charts based on analysis history statistics.

    # Load statistics data when the logged-in section is displayed for the first time,
    # but only if the stats data is not already loaded in session state.
    # Also reload stats after any history change (analysis save, delete, clear).
    # Check if both stats dicts are None (initial state before first load attempt) or empty.
    # We trigger load if risk stats is None AND logged in. This function loads both.
    if st.session_state['logged_in'] and (st.session_state['risk_level_stats'] is None): # Check only risk level stats for initial load trigger
         load_stats_api() # Call this function to fetch stats data from the backend
         # load_stats_api fetches BOTH stats types.
         # load_stats_api does not trigger a rerun itself.

    # Use columns to place the two charts side-by-side on wider screens.
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        # Display Risk Level Distribution Chart if data is available in session state.
        # Check if the data is a dictionary and not empty.
        if isinstance(st.session_state['risk_level_stats'], dict) and st.session_state['risk_level_stats']:
             st.write("Risk Level Distribution:")
             # Convert the stats dictionary into a pandas DataFrame for charting with Altair.
             # Use .items() to get (key, value) pairs, then create DataFrame columns.
             risk_stats_df = pd.DataFrame(list(st.session_state['risk_level_stats'].items()), columns=['Risk Level', 'Count'])

             # Create an Altair chart (Bar chart).
             # Ensure Altair is installed (`uv pip install altair`).
             chart = alt.Chart(risk_stats_df).mark_bar().encode(
                 # Use x for Risk Level (nominal) and y for Count (quantitative)
                 # Use sort='-y' to sort bars by count descending
                 x=alt.X('Risk Level', title='Risk Level', sort='-y'),
                 y=alt.Y('Count', title='Number of Analyses'), # Y-axis: Count
                 color=alt.Color(field="Risk Level", type="nominal", scale=alt.Scale(
                     # Define colors corresponding to your risk levels. These should ideally match the theme/CSS.
                     # Example domain values and range colors:
                     # Keep 'Fraudulent' in the domain to assign it a color, even if the backend doesn't return it as a risk_level string.
                     domain=['Critical', 'High', 'Medium', 'Low', 'Safe', 'Fraudulent', 'Unknown', 'Error', 'Invalid Result'],
                     range=['#ef4444', '#f97316', '#f59e0b', '#4ade80', '#16a34a', '#dc2626', '#9ca3af', '#a1a1aa', '#64748b'] # Example colors (Tailwind CSS palette inspired)
                 )),
                 # Tooltip: Include Risk Level and Count.
                 tooltip=[
                     alt.Tooltip("Risk Level", title="Risk Level"), # Show Risk Level label
                     alt.Tooltip("Count", title="Count") # Show Count
                 ]
             ).properties(
                 title="Distribution of Analysis Results by Risk Level" # Chart title
             )
             st.altair_chart(chart, use_container_width=True) # Display the chart using Streamlit

        # Display message if no stats data is available for THIS chart but user is logged in.
        # Check if logged in AND stats data for this chart is None OR an empty dict.
        elif st.session_state['logged_in'] and (st.session_state['risk_level_stats'] is None or not st.session_state['risk_level_stats']):
             st.info("No analysis history yet to display Risk Level stats.")


    with chart_col2:
        # Display Analysis Type Distribution Chart if data is available.
        # Check if the data is a dictionary and not empty.
        if isinstance(st.session_state['type_stats'], dict) and st.session_state['type_stats']:
             st.write("Analysis Type Distribution:")
             # Convert the stats dictionary into a pandas DataFrame for charting.
             type_stats_df = pd.DataFrame(list(st.session_state['type_stats'].items()), columns=['Type', 'Count'])
             # Create a Bar chart for type counts using Altair.
             # Use Altair for better control over colors and formatting than st.bar_chart.
             type_chart = alt.Chart(type_stats_df).mark_bar().encode(
                 x=alt.X('Type', title='Analysis Type'), # X-axis for Type
                 y=alt.Y('Count', title='Number of Analyses'), # Y-axis for Count
                 color=alt.Color('Type', scale=alt.Scale(
                      domain=['url', 'qr'], # Backend uses 'url', 'qr' as keys for types
                      range=['#2563eb', '#d97706'] # Example colors (Primary color for URL, Warning color for QR)
                  )),
                 tooltip=['Type', 'Count'] # Tooltip shows Type and Count
             ).properties(
                  title="Analysis Count by Type (URL vs QR Code)" # Chart title
              )
             st.altair_chart(type_chart, use_container_width=True) # Display the chart using Streamlit

         # Display message if no stats data is available for THIS chart but user is logged in.
         # Check if logged in AND stats data for this chart is None OR an empty dict.
        elif st.session_state['logged_in'] and (st.session_state['type_stats'] is None or not st.session_state['type_stats']):
             st.info("No analysis history yet to display Analysis Type stats.")


else:
    # --- Content displayed when the user is NOT logged in (Login and Register forms) ---

    st.subheader("Login or Register")

    # Use Streamlit columns to arrange login and register forms side-by-side.
    col1, col2 = st.columns(2)

    # Login Form Column
    with col1:
        st.subheader("Login")
        # Use a form to group login inputs and the submit button.
        # This improves performance by preventing reruns on every character typed.
        with st.form("login_form"):
            # Use unique keys for all Streamlit widgets of the same type.
            email = st.text_input("Email", key="login_email_input")
            password = st.text_input("Password", type="password", key="login_password_input")
            login_button = st.form_submit_button("Login") # The submit button for this form

            # Logic executed when the login button is clicked (within the form context).
            if login_button:
                if email and password:
                    login_user(email, password) # Call the login function to interact with the backend API
                else:
                    st.warning("Please enter both email and password.")

    # Register Form Column
    with col2:
        st.subheader("Register")
        # Use a form to group registration inputs and the submit button.
        with st.form("register_form"):
            # Use unique keys for all widgets.
            reg_email = st.text_input("Email", key="reg_email_input")
            reg_username = st.text_input("Username", key="reg_username_input")
            reg_password = st.text_input("Password", type="password", key="reg_password_input")
            reg_confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password_input")
            register_button = st.form_submit_button("Register") # The submit button for this form

            # Logic executed when the register button is clicked.
            if register_button:
                 # Basic check if required fields are filled before calling register function.
                 if reg_email and reg_username and reg_password and reg_confirm_password:
                     register_user(reg_email, reg_username, reg_password, reg_confirm_password) # Call the registration function to interact with the backend API
                 else:
                     st.warning("Please fill in all registration fields.")