# helpers/db/handler.py

import mysql.connector
from mysql.connector import Error
import json
import time # Added for example usage
import sys # Import sys for printing to stderr
import os # Import os to access environment variables

# Import load_dotenv if you want to test handler.py standalone
# If app.py already calls load_dotenv, it's not strictly needed here for the app to run,
# but uncommenting it here allows you to run this file directly for testing database connection.
# from dotenv import load_dotenv
# Determine the path to the project root from the location of handler.py
# handler.py is in 'Python scripts/helpers/db'. Project root is three directories up.
# current_script_dir = os.path.dirname(os.path.abspath(__file__))
# project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_script_dir)))
# dotenv_path = os.path.join(project_root, '.env')
# if os.path.exists(dotenv_path):
#     load_dotenv(dotenv_path)
# else:
#     # This warning will show if .env isn't found when running handler.py directly
#     print(f"Warning: .env file not found at {dotenv_path}. Database credentials must be set in the environment.", file=sys.stderr)


# --- Database Connection Details (READ FROM ENVIRONMENT VARIABLES) ---
# Read from environment variables, providing defaults if not set
DB_HOST = os.getenv("DB_HOST", "127.0.0.1") # Default to 127.0.0.1 if not set in .env
DB_PORT = os.getenv("DB_PORT", "3306") # Default to 3306 if not set in .env
DB_USER = os.getenv("DB_USER") # <--- Read MySQL username from environment
DB_PASSWORD = os.getenv("DB_PASSWORD") # <--- Read MySQL password from environment
DB_NAME = os.getenv("DB_NAME") # <--- Read MySQL database name from environment


def create_db_connection():
    """Creates and returns a database connection."""
    # Add checks to ensure DB variables are set from environment (via .env or system)
    if not DB_USER or not DB_PASSWORD or not DB_NAME:
        print("Error: Database credentials (DB_USER, DB_PASSWORD, DB_NAME) are not set in environment variables.", file=sys.stderr)
        print("Please set them in your .env file or system environment.", file=sys.stderr)
        return None

    connection = None
    try:
        # Convert port to int as required by mysql.connector if it's not None
        db_port_int = int(DB_PORT) if DB_PORT is not None else 3306

        connection = mysql.connector.connect(
            host=DB_HOST,
            port=db_port_int,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        if connection.is_connected():
            # print("Database connection successful", file=sys.stderr) # Optional: uncomment for testing
            pass # Keep silent unless error
        return connection
    except ValueError:
        print(f"Error: Invalid DB_PORT value '{DB_PORT}'. Must be an integer.", file=sys.stderr)
        return None
    except Error as e:
        print(f"Error connecting to MySQL Database '{DB_NAME}' for user '{DB_USER}': {e}", file=sys.stderr)
        # Consider adding more specific error handling or logging here
        return None
    except Exception as e:
         print(f"An unexpected error occurred during database connection: {e}", file=sys.stderr)
         return None


# --- Database Operations ---

# create_user function - takes email, username, password_hash
def create_user(email, username, password_hash):
    """Inserts a new user into the users table."""
    connection = create_db_connection()
    if connection is None:
        return None

    cursor = None # Initialize cursor
    user_id = None # Initialize user_id
    # Query includes email, username, and password_hash columns
    query = "INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)"

    try:
        cursor = connection.cursor()
        # Execute with email, username, password_hash
        cursor.execute(query, (email, username, password_hash))
        connection.commit()
        user_id = cursor.lastrowid # Get the ID of the newly inserted row
        print(f"[DB] User created: {email} ({username}) (ID: {user_id})", file=sys.stderr)
        return user_id
    except mysql.connector.IntegrityError as e:
        # This error usually occurs for UNIQUE constraints (email or username)
        print(f"[DB] Error creating user: Email or username already exists. {e}", file=sys.stderr)
        connection.rollback()
        return None # Indicate user creation failed (e.g., duplicate)
    except Error as e:
        print(f"[DB] Error creating user: {e}", file=sys.stderr)
        connection.rollback()
        return None
    except Exception as e:
        print(f"[DB] An unexpected error occurred during user creation: {e}", file=sys.stderr)
        connection.rollback()
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# find_user_by_email function - Selects id, email, username, and password_hash
def find_user_by_email(email):
    """Finds a user by email and returns their ID, email, username, and password hash."""
    connection = create_db_connection()
    if connection is None:
        return None

    cursor = None
    user = None
    # SELECTS id, email, username, and password_hash
    query = "SELECT id, email, username, password_hash FROM users WHERE email = %s"

    try:
        cursor = connection.cursor(dictionary=True) # Return results as dictionary
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        # print(f"[DB] Finding user by email: {email} - Result: {user}", file=sys.stderr) # Optional: uncomment for debugging
        # user will be a dictionary like { 'id': ..., 'email': ..., 'username': ..., 'password_hash': ... } or None
        return user
    except Error as e:
        print(f"[DB] Error finding user by email: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[DB] An unexpected error occurred finding user by email: {e}", file=sys.stderr)
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# find_user_by_id function - Selects id, email, and username
def find_user_by_id(user_id):
    """Finds a user by ID and returns their details (id, email, username)."""
    connection = create_db_connection()
    if connection is None:
        return None

    cursor = None
    user = None
    try:
        user_id = int(user_id)

        cursor = connection.cursor(dictionary=True)
        # SELECTS id, email, and username
        query = "SELECT id, email, username FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        # print(f"[DB] Finding user by ID: {user_id} - Result: {user}", file=sys.stderr) # Optional: uncomment for debugging
        # user will be a dictionary like { 'id': ..., 'email': ..., 'username': ... } or None
        return user
    except ValueError:
        print(f"[DB] Error: Invalid user ID format - {user_id}", file=sys.stderr)
        return None
    except Error as e:
        print(f"[DB] Error finding user by ID: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[DB] An unexpected error occurred finding user by ID: {e}", file=sys.stderr)
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# save_analysis_result function
def save_analysis_result(user_id, item_type, item_data, analysis_result):
    """Saves an analysis result to the analysis_history table."""
    connection = create_db_connection()
    if connection is None:
        return False

    cursor = None # Initialize cursor
    try:
        user_id = int(user_id)
        analysis_result_json = json.dumps(analysis_result)

        cursor = connection.cursor()
        query = """
        INSERT INTO analysis_history (user_id, item_type, item_data, analysis_result)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, item_type, item_data, analysis_result_json))
        connection.commit()
        history_item_id = cursor.lastrowid
        print(f"[DB] Analysis result saved for user {user_id} (ID: {history_item_id})", file=sys.stderr)
        return history_item_id
    except ValueError:
        print(f"[DB] Error saving analysis result: Invalid user ID format - {user_id}", file=sys.stderr)
        connection.rollback()
        return False
    except Error as e:
        print(f"[DB] Error saving analysis result: {e}", file=sys.stderr)
        connection.rollback()
        return False
    except Exception as e:
        print(f"[DB] An unexpected error occurred saving analysis result: {e}", file=sys.stderr)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# get_user_history function
def get_user_history(user_id):
    """Fetches analysis history for a given user ID."""
    connection = create_db_connection()
    if connection is None:
        return []

    cursor = None
    history_items = []
    query = "SELECT id, item_type, item_data, analysis_result, analyzed_at FROM analysis_history WHERE user_id = %s ORDER BY analyzed_at DESC"

    try:
        user_id = int(user_id)

        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (user_id,))
        history_items = cursor.fetchall()
        # print(f"[DB] Fetched history for user {user_id}: {len(history_items)} items", file=sys.stderr)

        for item in history_items:
            if 'analysis_result' in item and isinstance(item['analysis_result'], str):
                try:
                    item['analysis_result'] = json.loads(item['analysis_result'])
                except json.JSONDecodeError:
                    print(f"[DB] Warning: Could not parse JSON for history item ID {item.get('id')}", file=sys.stderr)
                    item['analysis_result'] = None

        return history_items
    except ValueError:
        print(f"[DB] Error fetching user history: Invalid user ID format - {user_id}", file=sys.stderr)
        return []
    except Error as e:
        print(f"[DB] Error fetching user history: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[DB] An unexpected error occurred fetching user history: {e}", file=sys.stderr)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# delete_history_item function
def delete_history_item(item_id, user_id):
    """Deletes a specific history item, ensuring it belongs to the user."""
    connection = create_db_connection()
    if connection is None:
        return False

    cursor = None
    try:
        item_id = int(item_id)
        user_id = int(user_id)

        cursor = connection.cursor()
        query = "DELETE FROM analysis_history WHERE id = %s AND user_id = %s"
        cursor.execute(query, (item_id, user_id))
        connection.commit()

        if cursor.rowcount > 0:
            print(f"[DB] History item {item_id} deleted for user {user_id}", file=sys.stderr)
            return True
        else:
            print(f"[DB] History item {item_id} not found for user {user_id} or already deleted.", file=sys.stderr)
            return False
    except ValueError:
        print(f"[DB] Error deleting history item: Invalid ID format (item_id: {item_id}, user_id: {user_id})", file=sys.stderr)
        connection.rollback()
        return False
    except Error as e:
        print(f"[DB] Error deleting history item: {e}", file=sys.stderr)
        connection.rollback()
        return False
    except Exception as e:
        print(f"[DB] An unexpected error occurred deleting history item: {e}", file=sys.stderr)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# clear_user_history function
def clear_user_history(user_id):
    """Deletes all history items for a specific user."""
    connection = create_db_connection()
    if connection is None:
        return False

    cursor = None
    try:
        user_id = int(user_id)

        cursor = connection.cursor()
        query = "DELETE FROM analysis_history WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        connection.commit()
        print(f"[DB] All history cleared for user {user_id}. Deleted {cursor.rowcount} items.", file=sys.stderr)
        return True
    except ValueError:
        print(f"[DB] Error clearing user history: Invalid user ID format - {user_id}", file=sys.stderr)
        connection.rollback()
        return False
    except Error as e:
        print(f"[DB] Error clearing user history: {e}", file=sys.stderr)
        connection.rollback()
        return False
    except Exception as e:
        print(f"[DB] An unexpected error occurred clearing user history: {e}", file=sys.stderr)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --- Function to Get All Users ---
def get_all_users():
    """Fetches all users (id, email, username) from the database."""
    connection = create_db_connection()
    if connection is None:
        return []

    cursor = None
    users = []
    query = "SELECT id, email, username FROM users"

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query)
        users = cursor.fetchall()
        print(f"[DB] Fetched all users: {len(users)} items", file=sys.stderr)
        return users
    except Error as e:
        print(f"[DB] Error fetching all users: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[DB] An unexpected error occurred fetching all users: {e}", file=sys.stderr)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# --- Function to Delete a User by ID ---
def delete_user_by_id(user_id):
    """Deletes a user by their ID."""
    connection = create_db_connection()
    if connection is None:
        return False

    cursor = None
    try:
        user_id = int(user_id)

        cursor = connection.cursor()
        # Added CASCADE DELETE in schema.sql is recommended,
        # but if not, history for this user might remain.
        # Consider deleting history first if needed.
        # query_delete_history = "DELETE FROM analysis_history WHERE user_id = %s"
        # cursor.execute(query_delete_history, (user_id,))
        # connection.commit()
        # print(f"[DB] Deleted history for user {user_id} before deleting user.")


        query_delete_user = "DELETE FROM users WHERE id = %s"
        cursor.execute(query_delete_user, (user_id,))
        connection.commit()

        if cursor.rowcount > 0:
            print(f"[DB] User with ID {user_id} deleted.", file=sys.stderr)
            return True
        else:
            print(f"[DB] User with ID {user_id} not found or already deleted.", file=sys.stderr)
            return False
    except ValueError:
        print(f"[DB] Error deleting user: Invalid user ID format - {user_id}", file=sys.stderr)
        connection.rollback()
        return False
    except Error as e:
        print(f"[DB] Error deleting user {user_id}: {e}", file=sys.stderr)
        connection.rollback()
        return False
    except Exception as e:
        print(f"[DB] An unexpected error occurred deleting user: {e}", file=sys.stderr)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# Example Usage (for testing the handler.py file itself)
if __name__ == "__main__":
    print("Testing Database Handler (MySQL)...")

    # If running handler.py standalone for testing, uncomment the load_dotenv call above
    # and ensure your .env file is in the project root.

    # Add checks before running tests to ensure DB variables are set
    if not os.getenv("DB_USER") or not os.getenv("DB_PASSWORD") or not os.getenv("DB_NAME"):
        print("Error: Database credentials are not set as environment variables.", file=sys.stderr)
        print("Please set DB_USER, DB_PASSWORD, DB_NAME in your .env file.", file=sys.stderr)
        # DB_HOST and DB_PORT have defaults, so checking user, password, name is sufficient
        sys.exit(1) # Exit if DB credentials are missing


    # --- Ensure your MySQL server is running and credentials in .env are correct! ---

    # --- Test Connection ---
    print("\nAttempting simple database connection test...")
    conn = create_db_connection()
    if conn:
        print("Simple database connection test successful.")
        conn.close()
    else:
        print("Simple database connection test failed. Please check your MySQL server and credentials in your .env file.")
        sys.exit(1) # Exit if connection fails

    # --- Rest of your example usage tests ---
    # --- UNCOMMENT sections as needed for testing ---
    # Ensure Werkzeug is installed (uv add Werkzeug) if testing user creation/password hashing
    # try:
    #     from werkzeug.security import generate_password_hash, check_password_hash

    #     print("\nAttempting to create a test user...")
    #     test_email = "test_user_" + str(int(time.time())) + "@example.com" # Use timestamp to make email unique
    #     test_username = "testuser_" + str(int(time.time())) # Use timestamp for unique username
    #     test_password = "secure_password_123"
    #     dummy_password_hash = generate_password_hash(test_password)
    #     test_user_id = create_user(test_email, test_username, dummy_password_hash)

    #     if test_user_id:
    #         print(f"Created user with ID: {test_user_id}, Email: {test_email}, Username: {test_username}")

    #         print(f"\nAttempting to find user by email: {test_email}")
    #         found_user = find_user_by_email(test_email)
    #         print(f"Found user: {found_user}")

    #         if found_user and check_password_hash(found_user['password_hash'], test_password):
    #             print("Password check successful.")
    #         else:
    #             print("Password check failed or user not found.")

    #         if found_user: # Proceed only if user was found
    #              print(f"\nAttempting to find user by ID: {found_user['id']}")
    #              found_user_by_id = find_user_by_id(found_user['id'])
    #              print(f"Found user by ID: {found_user_by_id}")


    #              print("\nAttempting to save a test analysis result...")
    #              test_result = {"is_fraud": False, "confidence": "98.7", "risk_level": "Low", "risk_factors": ["Short URL"]}
    #              save_success = save_analysis_result(found_user['id'], "url", "https://www.anothersafeurl.com", test_result)
    #              print(f"Save successful: {save_success}")

    #              test_qr_result = {"is_fraud": True, "confidence": "75.1", "risk_level": "Medium"}
    #              save_success_qr = save_analysis_result(found_user['id'], "qr", "malicious_qr.png (http://bad.link)", test_qr_result)
    #              print(f"QR Save successful: {save_success_qr}")


    #              print(f"\nAttempting to fetch user history for user ID: {found_user['id']}")
    #              history = get_user_history(found_user['id'])
    #              print("Fetched History:")
    #              if history:
    #                  for item in history:
    #                      print(item)
    #                  # Example of deleting the first item fetched
    #                  if history: # Check if history is not empty
    #                      first_item_id = history[0]['id']
    #                      print(f"\nAttempting to delete history item ID: {first_item_id}")
    #                      delete_success = delete_history_item(first_item_id, found_user['id'])
    #                      print(f"Delete successful: {delete_success}")
    #              else:
    #                  print("No history found.")

    #              print(f"\nAttempting to clear all history for user ID: {found_user['id']}")
    #              # clear_success = clear_user_history(found_user['id']) # Uncomment to test clearing history
    #              # print(f"Clear history successful: {clear_success}")


    # except ImportError:
    #      print("\nWerkzeug not installed. Skipping user creation/password hashing tests.")
    # except Error as e:
    #      print(f"\nAn error occurred during tests: {e}")
    # except Exception as e:
    #     print(f"\nAn unexpected error occurred during tests: {e}", file=sys.stderr)


    print("\nTesting complete.")