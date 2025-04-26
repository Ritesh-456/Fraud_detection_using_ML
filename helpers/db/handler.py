# helpers/db/handler.py

import mysql.connector
from mysql.connector import Error
import json
import time
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Database Connection Details (Loaded from .env) ---
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")


def create_db_connection():
    """Creates and returns a database connection."""
    if not DB_USER or not DB_PASSWORD or not DB_NAME:
        print("[DB] Error: Database credentials (DB_USER, DB_PASSWORD, DB_NAME) not set in environment variables.", file=sys.stderr)
        return None

    connection = None
    try:
        # Add explicit logging before attempting connection
        # print(f"[DB] Attempting to connect to {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}", file=sys.stderr)
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
            # --- REMOVED: Unsupported isolation_level parameter ---
            #,isolation_level='READ COMMITTED'
            # --- END REMOVED ---
        )
        if connection.is_connected():
            # print("Database connection successful", file=sys.stderr)
            # --- REMOVED: Verify isolation level log ---
            # print(f"[DB] Connection Isolation Level: {connection.get_transaction_isolation()}", file=sys.stderr)
            # --- END REMOVED ---
            pass
        return connection
    except Error as e:
        print(f"[DB] Error connecting to MySQL Database '{DB_NAME}' for user '{DB_USER}': {e}", file=sys.stderr)
        return None

# --- Database Operations (Functions defined before __main__ block) ---

def create_user(email, username, password_hash):
    """Inserts a new user into the users table."""
    connection = create_db_connection()
    if connection is None:
        return None

    cursor = None
    user_id = None
    query = "INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)"

    try:
        cursor = connection.cursor()
        cursor.execute(query, (email, username, password_hash))
        connection.commit()
        user_id = cursor.lastrowid
        print(f"[DB] User created: {email} ({username}) (ID: {user_id})", file=sys.stderr)
        return user_id
    except mysql.connector.IntegrityError as e:
        print(f"[DB] Error creating user: Email or username already exists. {e}", file=sys.stderr)
        connection.rollback()
        return None
    except Error as e:
        print(f"[DB] Error creating user: {e}", file=sys.stderr)
        connection.rollback()
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def find_user_by_email(email):
    """Finds a user by email and returns their ID, email, username, and password hash."""
    connection = create_db_connection()
    if connection is None:
        return None

    cursor = None
    user = None
    query = "SELECT id, email, username, password_hash FROM users WHERE email = %s"

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        return user
    except Error as e:
        print(f"[DB] Error finding user by email: {e}", file=sys.stderr)
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


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
        query = "SELECT id, email, username FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        return user
    except ValueError:
        print(f"[DB] Error: Invalid user ID format - {user_id}", file=sys.stderr)
        return None
    except Error as e:
        print(f"[DB] Error finding user by ID: {e}", file=sys.stderr)
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def save_analysis_result(user_id, item_type, item_data, analysis_result):
    """Saves an analysis result to the analysis_history table."""
    connection = create_db_connection()
    if connection is None:
        print("[DB] Save failed: Database connection is None.", file=sys.stderr)
        return False

    cursor = None
    history_item_id = None
    try:
        user_id = int(user_id)

        # Ensure item_data is not too long for logging, but use the full data for insertion
        item_data_log = item_data[:100] + '...' if len(item_data) > 100 else item_data

        # Convert analysis_result dict to JSON string
        analysis_result_json = json.dumps(analysis_result)
        analysis_result_log = analysis_result_json[:100] + '...' if len(analysis_result_json) > 100 else analysis_result_json


        cursor = connection.cursor()
        query = """
        INSERT INTO analysis_history (user_id, item_type, item_data, analysis_result)
        VALUES (%s, %s, %s, %s)
        """
        print(f"[DB] Attempting to execute save query for user {user_id}...", file=sys.stderr)
        # print(f"[DB] Query: {query}", file=sys.stderr) # Too verbose for standard run
        # print(f"[DB] Params: ({user_id}, {item_type}, '{item_data_log}', '{analysis_result_log}')", file=sys.stderr) # Too verbose

        # Execute the insert query
        cursor.execute(query, (user_id, item_type, item_data, analysis_result_json))

        print(f"[DB] Execute successful, attempting to commit transaction...", file=sys.stderr)
        # Commit the transaction to save the changes to the database
        connection.commit()
        print(f"[DB] Commit successful.", file=sys.stderr)


        # Get the ID of the last inserted row
        history_item_id = cursor.lastrowid
        print(f"[DB] Analysis result saved for user {user_id} (History ID: {history_item_id})", file=sys.stderr)

        # Return the ID on successful save
        return history_item_id

    except ValueError as e:
        print(f"[DB] Save failed (ValueError): Invalid user ID format - {user_id}. Error: {e}", file=sys.stderr)
        if connection and connection.is_connected(): connection.rollback()
        return False
    except mysql.connector.IntegrityError as e:
         # Handle cases like duplicate key errors if needed, though unlikely for history
        print(f"[DB] Save failed (IntegrityError): Database integrity issue. Error: {e}", file=sys.stderr)
        if connection and connection.is_connected(): connection.rollback()
        return False
    except Error as e:
        # Log specific MySQL database errors during execute or commit
        print(f"[DB] Save failed (MySQL Error): Error executing query or committing. Error: {e}", file=sys.stderr)
        if connection and connection.is_connected(): connection.rollback() # Roll back the transaction on error
        return False # Indicate failure
    except Exception as e:
        # Catch any other unexpected exceptions
        import traceback
        print(f"[DB] Save failed (Unexpected Error): An unexpected error occurred. Error: {e}\n{traceback.format_exc()}", file=sys.stderr)
        if connection and connection.is_connected(): connection.rollback()
        return False
    finally:
        # Ensure cursor is closed, connection is closed if it was opened
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # Only close if connection was successfully established
             # print("[DB] Closing database connection.", file=sys.stderr)
             connection.close()
        else:
             print("[DB] Connection was not active or failed to establish, not closing.", file=sys.stderr)


# Corrected get_user_history function (filtering logic should be fixed now)
def get_user_history(user_id, filters=None):
    """
    Fetches analysis history for a given user ID, with optional filtering.

    Args:
        user_id (int): The ID of the user.
        filters (dict, optional): A dictionary of filters.
            Expected keys: 'item_type', 'risk_level', 'is_fraud', 'search_term'.
            Defaults to None (no filtering).

    Returns:
        list: A list of history items (dictionaries), or an empty list on error/no results.
    """
    connection = create_db_connection()
    if connection is None:
        print("[DB] Get history failed: Database connection is None.", file=sys.stderr)
        return []

    cursor = None
    history_items = []
    base_query = "SELECT id, item_type, item_data, analysis_result, analyzed_at FROM analysis_history WHERE user_id = %s"
    where_clauses = []
    query_params = [user_id]

    try:
        user_id = int(user_id)

        # Build WHERE clauses based on filters
        if filters:
            # Filter by item_type ('url' or 'qr')
            item_type = filters.get('item_type')
            # Check for empty string because frontend sends '' for 'All Types'
            if item_type and item_type.lower() != '' and item_type.lower() != 'all':
                where_clauses.append("item_type = %s")
                query_params.append(item_type)

            # Filter by risk_level ('Low', 'Medium', 'High', 'Critical', 'Safe')
            risk_level = filters.get('risk_level')
            # Check for empty string
            if risk_level and risk_level.lower() != '' and risk_level.lower() != 'all':
                 # Use JSON_EXTRACT and CAST for reliable string comparison
                 where_clauses.append("CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) = %s")
                 query_params.append(risk_level)
                 # Removed the redundant is_fraud='false' clause from here


            # Filter by is_fraud (boolean true or false)
            # Check if the key 'is_fraud' is present in the filters dictionary, regardless of its boolean value
            if 'is_fraud' in filters:
                 # Use JSON_EXTRACT and CAST for reliable string comparison
                 where_clauses.append("CAST(JSON_EXTRACT(analysis_result, '$.is_fraud') AS CHAR) = %s")
                 # Append the string 'true' or 'false' based on the boolean value in the filters dict
                 query_params.append(str(bool(filters['is_fraud'])).lower()) # Convert Python bool from filters dict to lowercase string 'true' or 'false'


            # Filter by search_term (in item_data)
            search_term = filters.get('search_term')
            if search_term:
                where_clauses.append("item_data LIKE %s")
                query_params.append(f"%{search_term}%")

            # Add more filters here as needed (e.g., date range)
            # start_date = filters.get('start_date')
            # if start_date:
            #     where_clauses.append("analyzed_at >= %s")
            #     query_params.append(start_date) # Ensure date format is compatible with MySQL

            # end_date = filters.get('end_date')
            # if end_date:
            #     where_clauses.append("analyzed_at <= %s")
            #     query_params.append(end_date) # Ensure date format is compatible with MySQL


        full_query = base_query
        if where_clauses:
            full_query += " AND " + " AND ".join(where_clauses)

        full_query += " ORDER BY analyzed_at DESC"

        print(f"[DB] Executing history query: {full_query} with params {query_params}", file=sys.stderr)

        cursor = connection.cursor(dictionary=True)
        cursor.execute(full_query, tuple(query_params))
        history_items = cursor.fetchall()

        # Process analysis_result JSON and ensure key types for frontend consistency
        for item in history_items:
            # Ensure analysis_result is present and is a string/bytes before parsing
            if 'analysis_result' in item and item['analysis_result'] is not None:
                if isinstance(item['analysis_result'], (bytes, bytearray, str)):
                     try:
                        json_string = item['analysis_result'].decode('utf-8') if isinstance(item['analysis_result'], (bytes, bytearray)) else item['analysis_result']
                        if json_string.strip(): # Check if JSON string is not empty or just whitespace
                           item['analysis_result'] = json.loads(json_string)
                        else:
                            print(f"[DB] Warning: Empty JSON string for history item ID {item.get('id')}", file=sys.stderr)
                            item['analysis_result'] = {}

                     except json.JSONDecodeError:
                        print(f"[DB] Warning: Could not parse JSON for history item ID {item.get('id')}. Raw data: {item['analysis_result']}", file=sys.stderr)
                        item['analysis_result'] = {} # Assign empty dict on decode error
                # Ensure is_fraud is boolean and risk_level is string after parsing
                if isinstance(item['analysis_result'], dict):
                    # Safely get is_fraud, convert to boolean. Default to False if key is missing or value is not true/false-like
                    item['analysis_result']['is_fraud'] = bool(item['analysis_result'].get('is_fraud', False))
                     # Safely get risk_level, convert to string. Default to 'Unknown' if key is missing or value is None
                    item['analysis_result']['risk_level'] = str(item['analysis_result'].get('risk_level', 'Unknown'))
                else:
                    # If analysis_result wasn't a parsable JSON dict, replace with empty dict
                     item['analysis_result'] = {}
                     print(f"[DB] Warning: analysis_result for history item ID {item.get('id')} was not a dictionary after parsing.", file=sys.stderr)

            else:
                 # If analysis_result was None initially, set to empty dict
                 item['analysis_result'] = {}


        return history_items
    except ValueError as e: # Explicitly catch ValueError for user_id conversion
        print(f"[DB] Error fetching user history: Invalid user ID format - {user_id}. Error: {e}", file=sys.stderr)
        return []
    except mysql.connector.Error as e: # Catch specific MySQL errors
        import traceback
        print(f"[DB] MySQL Error fetching user history: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return []
    except Exception as e: # Catch any other unexpected exceptions
        import traceback
        print(f"[DB] Unexpected Error fetching user history: {e}\n{traceback.format_exc()}", file=sys.stderr)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             connection.close()


# --- User Listing and Deletion Functions (Moved before __main__ block) ---

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
        # print(f"[DB] Fetched all users: {len(users)} items", file=sys.stderr) # Keep logging minimal unless debugging
        return users
    except Error as e:
        print(f"[DB] Error fetching all users: {e}", file=sys.stderr)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def delete_user_by_id(user_id):
    """Deletes a user by their ID."""
    connection = create_db_connection()
    if connection is None:
        return False

    cursor = None
    try:
        user_id = int(user_id)

        cursor = connection.cursor()
        # Added CASCADE DELETE on analysis_history in schema means we only need to delete the user
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
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --- Example Usage (for testing the handler.py file itself) ---
if __name__ == "__main__":
    print("Testing Database Handler (MySQL)...")

    conn = create_db_connection()
    if conn:
        print("Simple database connection test successful.")
        conn.close()
    else:
        print("Simple database connection test failed. Please check your MySQL server and credentials in the .env file.")
        sys.exit(1)

    print("\nAttempting to get all users...")
    # Corrected NameError by moving get_all_users definition above this block
    all_users = get_all_users()
    if all_users is not None:
        if all_users:
            print("Fetched Users:")
            for user in all_users:
                print(f"ID: {user['id']}, Email: {user['email']}, Username: {user['username']}")
        else:
            print("No users found in the database.")
    else:
        print("Failed to fetch users due to a database error.")

    # --- Example: Test History Filtering ---
    print("\nAttempting to fetch history with filters...")
    # Assuming user with ID 1 exists and has some history
    # You might need to change this ID to match your test user's ID
    test_user_id = 6 # Assuming user 6 (honeygirl) is your test user now

    # Example filters
    filters_url_only = {'item_type': 'url'}
    filters_fraud_only = {'is_fraud': True} # Note: Flask-Login sends 'true'/'false' strings, but internal handler logic might prefer bool/string based on implementation
    filters_not_fraud_only = {'is_fraud': False}
    filters_critical_risk = {'risk_level': 'Critical', 'is_fraud': False} # Specific risk level filters should also include is_fraud=False
    filters_high_risk = {'risk_level': 'High', 'is_fraud': False}
    filters_medium_risk = {'risk_level': 'Medium', 'is_fraud': False}
    filters_low_risk = {'risk_level': 'Low', 'is_fraud': False}
    filters_safe_risk = {'risk_level': 'Safe', 'is_fraud': False}
    filters_search_example = {'search_term': 'example'} # Search for 'example' in item_data
    filters_all = {} # Empty filter means get all history for the user


    print(f"\nFetching history for user {test_user_id} (All):")
    history_all = get_user_history(test_user_id, filters_all)
    print(f"Found {len(history_all)} items.")
    if history_all:
        print("First item example:", history_all[0]) # Print first item to see structure
    # for item in history_all: print(item) # Uncomment to see all items


    print(f"\nFetching history for user {test_user_id} (URL only):")
    history_url = get_user_history(test_user_id, filters_url_only)
    print(f"Found {len(history_url)} URL items.")
    # for item in history_url: print(item) # Uncomment to see items

    print(f"\nFetching history for user {test_user_id} (Fraudulent only):")
    history_fraud = get_user_history(test_user_id, filters_fraud_only)
    print(f"Found {len(history_fraud)} fraudulent items.")
    # for item in history_fraud: print(item) # Uncomment to see items

    print(f"\nFetching history for user {test_user_id} (Not Fraudulent only):")
    history_not_fraud = get_user_history(test_user_id, filters_not_fraud_only)
    print(f"Found {len(history_not_fraud)} not fraudulent items.")
    # for item in history_not_fraud: print(item) # Uncomment to see items


    print(f"\nFetching history for user {test_user_id} (Medium Risk only):")
    history_medium = get_user_history(test_user_id, filters_medium_risk)
    print(f"Found {len(history_medium)} medium risk items.")
    # for item in history_medium: print(item) # Uncomment to see items

    print(f"\nFetching history for user {test_user_id} (High Risk only):")
    history_high = get_user_history(test_user_id, filters_high_risk)
    print(f"Found {len(history_high)} high risk items.")
    # for item in history_high: print(item) # Uncomment to see items

    print(f"\nFetching history for user {test_user_id} (Safe Risk only):")
    history_safe = get_user_history(test_user_id, filters_safe_risk)
    print(f"Found {len(history_safe)} safe risk items.")
    # for item in history_safe: print(item) # Uncomment to see items


    print(f"\nFetching history for user {test_user_id} (Search 'example'):")
    history_search = get_user_history(test_user_id, filters_search_example)
    print(f"Found {len(history_search)} items matching search term.")
    # for item in history_search: print(item) # Uncomment to see items


    print("\nTesting complete.")