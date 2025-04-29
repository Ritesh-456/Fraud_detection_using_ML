# helpers/db/handler.py

# This module contains functions for interacting with the MySQL database
# and managing the training data file.

# --- Standard Library Imports ---
import json # For handling JSON data in analysis_result
import time # For time-related operations
import sys # For accessing system-specific parameters
import os # For interacting with the operating system (e.g., environment variables, file paths)
import traceback # For getting detailed traceback information in error logs
import csv # For writing data to a CSV file

# --- Third-Party Library Imports ---
# Ensure these are in your pyproject.toml and installed (uv sync or uv pip install .)
# mysql.connector-python for connecting to MySQL database
import mysql.connector
from mysql.connector import Error
# python-dotenv for loading environment variables
from dotenv import load_dotenv
# pandas is needed for load_real_data example implementation
import pandas as pd


# --- Standard Logging Configuration ---
# Get a logger instance specific to this module (__name__ is 'helpers.db.handler')
# The basic logging configuration (setting up handlers, format, initial level)
# should ideally be done once in the main application entry point (app.py).
import logging
logger = logging.getLogger(__name__)


# --- Database Connection Details (Loaded from .env) ---
# Load environment variables from the .env file (assuming it's in the project root or parent directory)
load_dotenv()

# Get database credentials from environment variables. Provide default values for host/port.
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306") # Note: os.getenv returns string, mysql.connector might handle it, or cast to int
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")


def create_db_connection():
    """
    Creates and returns a new database connection to the configured MySQL database.
    Handles basic connection errors and logs them.
    Returns:
        mysql.connector.connection.MySQLConnection: A database connection object, or None if connection fails.
    """
    # Check if required credentials are set in environment variables.
    if not DB_USER or not DB_PASSWORD or not DB_NAME:
        logger.error("Database credentials (DB_USER, DB_PASSWORD, DB_NAME) are not set in environment variables or .env file.")
        return None

    connection = None
    try:
        # Attempt to connect to the MySQL database.
        # logger.debug(f"Attempting to connect to {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}") # Debug level log for connection attempt
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=int(DB_PORT), # Ensure port is an integer
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
            # Note: isolation_level parameter was removed as it caused AttributeError in some setups.
            # Default isolation level is often READ COMMITTED or REPEATABLE READ depending on MySQL configuration.
        )
        # Check if the connection was successful.
        if connection.is_connected():
            # logger.debug(f"Database connection successful (Connection ID: {connection.connection_id}).") # Debug connection ID
            pass # Connection is successful, no need for verbose info log on every connection
        return connection
    except Error as e:
        # Log specific MySQL connector errors during connection establishment.
        logger.error(f"Error connecting to MySQL Database '{DB_NAME}' for user '{DB_USER}': {e}", exc_info=True) # exc_info=True adds traceback
        return None
    # Note: Connection is not closed in finally here; it's the caller's responsibility to close the connection.


# --- Database Operations ---
# Functions to interact with the database for user management and analysis history.

def create_user(email, username, password_hash):
    """
    Inserts a new user into the 'users' table.
    Args:
        email (str): User's email address.
        username (str): User's chosen username.
        password_hash (str): Hashed password string.
    Returns:
        int: The ID of the newly created user on success, or None on failure (e.g., email/username exists, DB error).
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        return None # Error is already logged in create_db_connection

    cursor = None
    user_id = None # Initialize user_id to None
    query = "INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)"

    try:
        cursor = connection.cursor() # Use default cursor (tuple)
        # Execute the INSERT query with parameters for safety (prevents SQL injection).
        cursor.execute(query, (email, username, password_hash))
        connection.commit() # Commit the transaction to make changes persistent

        user_id = cursor.lastrowid # Get the ID of the last inserted row
        logger.info(f"User created successfully: {email} ({username}) (ID: {user_id})")
        return user_id # Return the new user's ID

    except mysql.connector.IntegrityError as e:
        # Catch IntegrityError specifically, often indicates a unique constraint violation (email or username already exists).
        logger.warning(f"Error creating user: Email or username already exists for email='{email}', username='{username}'. Error: {e}")
        connection.rollback() # Roll back the transaction on this specific error
        return None # Return None to indicate failure (conflict)

    except Error as e:
        # Catch other MySQL connector errors during execute or commit.
        logger.error(f"MySQL Error creating user email='{email}', username='{username}': {e}", exc_info=True)
        connection.rollback() # Roll back the transaction on general DB errors
        return None # Return None to indicate failure

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error in create_user for email='{email}', username='{username}'.") # Log with traceback
        connection.rollback()
        return None

    finally:
        # Ensure cursor and connection are closed in all cases.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            # logger.debug("Closing DB connection in create_user.") # Optional debug log
            connection.close()


def find_user_by_email(email):
    """
    Finds a user by their email address in the 'users' table.
    Args:
        email (str): The email address to search for.
    Returns:
        dict: A dictionary containing user details ('id', 'email', 'username', 'password_hash')
              on success, or None if user is not found or a database error occurs.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        return None # Error logged in create_db_connection

    cursor = None
    user = None # Initialize user to None
    query = "SELECT id, email, username, password_hash FROM users WHERE email = %s"

    try:
        # Use cursor(dictionary=True) to fetch rows as dictionaries instead of tuples.
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (email,)) # Execute query with email parameter
        user = cursor.fetchone() # Fetch a single row

        # Log lookup result (optional, debug level is appropriate)
        # if user:
        #      logger.debug(f"User found by email '{email}': ID {user.get('id')}")
        # else:
        #      logger.debug(f"User not found by email: '{email}'")

        return user # Return the user dictionary or None

    except Error as e:
        # Log MySQL connector errors during lookup.
        logger.error(f"MySQL Error finding user by email '{email}': {e}", exc_info=True)
        return None # Return None on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error in find_user_by_email for email='{email}'.") # Log with traceback
        return None

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            # logger.debug("Closing DB connection in find_user_by_email.") # Optional debug log
            connection.close()


def find_user_by_id(user_id):
    """
    Finds a user by their ID in the 'users' table.
    Args:
        user_id (int or str): The user ID to search for.
    Returns:
        dict: A dictionary containing user details ('id', 'email', 'username')
              on success, or None if user is not found or a database error occurs.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        return None # Error logged in create_db_connection

    cursor = None
    user = None # Initialize user to None
    try:
        # Attempt to convert user_id to an integer, handle ValueError if format is invalid.
        user_id_int = int(user_id)

        # Use cursor(dictionary=True) to fetch rows as dictionaries.
        cursor = connection.cursor(dictionary=True)
        query = "SELECT id, email, username FROM users WHERE id = %s"
        cursor.execute(query, (user_id_int,)) # Execute query with integer ID
        user = cursor.fetchone() # Fetch a single row

        # Log lookup result (optional, debug level)
        # if user:
        #      logger.debug(f"User found by ID '{user_id}': {user.get('username')}")
        # else:
        #      logger.debug(f"User not found by ID: '{user_id}'")

        return user # Return user dictionary or None

    except ValueError:
        # Catch error if user_id cannot be converted to an integer.
        logger.warning(f"Error finding user by ID: Invalid user ID format received: '{user_id}'.")
        return None # Return None for invalid ID format

    except Error as e:
        # Log MySQL connector errors during lookup.
        logger.error(f"MySQL Error finding user by ID '{user_id}': {e}", exc_info=True)
        return None # Return None on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error in find_user_by_id for ID='{user_id}'.") # Log with traceback
        return None

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            # logger.debug("Closing DB connection in find_user_by_id.") # Optional debug log
            connection.close()


def save_analysis_result(user_id, item_type, item_data, analysis_result):
    """
    Saves an analysis result for a user into the 'analysis_history' table.
    Args:
        user_id (int): The ID of the user.
        item_type (str): Type of item analyzed ('url' or 'qr').
        item_data (str): The data that was analyzed (e.g., the URL string).
        analysis_result (dict): The dictionary containing the analysis results (is_fraud, confidence, risk_level, risk_factors).
                                This will be stored as a JSON string in the database.
    Returns:
        int: The ID of the newly created history item on success, or False on failure.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Save analysis result failed for user {user_id}: Database connection could not be established.")
        return False # Indicate failure

    cursor = None
    history_item_id = False # Initialize history_item_id to False (indicating failure by default)
    try:
        # Ensure user_id is an integer.
        user_id_int = int(user_id)

        # Convert the analysis_result dictionary into a JSON string for database storage.
        # json.dumps handles dicts, lists, basic types.
        analysis_result_json = json.dumps(analysis_result)

        query = """
        INSERT INTO analysis_history (user_id, item_type, item_data, analysis_result)
        VALUES (%s, %s, %s, %s)
        """
        # logger.debug(f"Attempting to save analysis result for user {user_id_int}, type='{item_type}', data='{item_data[:100]}...'") # Debug query execution intent

        cursor = connection.cursor() # Use default cursor
        # Execute the INSERT query with parameters.
        cursor.execute(query, (user_id_int, item_type, item_data, analysis_result_json))

        # Commit the transaction to save the data to the database.
        # logger.debug("Executing commit for analysis result save.")
        connection.commit()
        # logger.debug("Commit successful.")


        # Get the ID of the last inserted row.
        history_item_id = cursor.lastrowid
        logger.info(f"Analysis result saved for user {user_id_int}: item_type='{item_type}', item_data='{item_data[:50]}...' (History ID: {history_item_id})") # Log success with snippet

        # Return the ID on successful save.
        return history_item_id

    except ValueError as e:
        # Catch error if user_id is not a valid integer.
        logger.error(f"Save analysis result failed (ValueError): Invalid user ID format received: '{user_id}'. Error: {e}", exc_info=True)
        # Roll back the transaction in case any partial operation occurred (though unlikely for initial insert).
        if connection and connection.is_connected(): connection.rollback()
        return False # Indicate failure

    except mysql.connector.IntegrityError as e:
         # Catch IntegrityError specifically, often indicates a unique constraint violation (email or username already exists).
        logger.error(f"Save failed (IntegrityError): Database integrity issue saving analysis result for user {user_id}. Error: {e}", exc_info=True)
         # Roll back the transaction on this specific error
        if connection and connection.is_connected(): connection.rollback()
        return False # Indicate failure (conflict)

    except Error as e:
        # Catch other MySQL connector errors during execute or commit.
        logger.error(f"MySQL Error saving analysis result for user {user_id}: {e}", exc_info=True)
        if connection and connection.is_connected(): connection.rollback() # Roll back on error
        return False # Indicate failure

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error in save_analysis_result for user {user_id}.") # Log with traceback
        if connection and connection.is_connected(): connection.rollback()
        return False

    finally:
        # Ensure cursor and connection are closed in all cases.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # logger.debug("Closing database connection in save_analysis_result.") # Optional debug log
             connection.close()


def get_user_history(user_id, filters=None):
    """
    Fetches analysis history for a given user ID from the 'analysis_history' table, with optional filtering.
    Filters are applied based on the provided dictionary.
    Args:
        user_id (int): The ID of the user.
        filters (dict, optional): A dictionary of filters.
            Expected keys can include:
            'item_type' (str): 'url' or 'qr'.
            'risk_level' (str): 'Low', 'Medium', 'High', 'Critical', 'Safe', 'Unknown', 'Error', 'Invalid Result'. Filters by this level string in the JSON.
            'is_fraud' (bool): True to filter for fraudulent items, False for non-fraudulent items.
            'search_term' (str): A string to search for within 'item_data'.
            Defaults to None (no filtering).
    Returns:
        list: A list of history items (each as a dictionary) on success, or an empty list on error or if no results found.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Get user history failed for user {user_id}: Database connection could not be established.")
        return [] # Return empty list on DB connection failure

    cursor = None
    history_items = [] # Initialize history_items list
    # Base query to select history items for the specific user.
    base_query = "SELECT id, item_type, item_data, analysis_result, analyzed_at FROM analysis_history WHERE user_id = %s"
    where_clauses = [] # List to build dynamic WHERE clauses
    query_params = [] # List to hold query parameters in correct order

    try:
        # Ensure user_id is an integer and add it as the first parameter.
        user_id_int = int(user_id)
        query_params.append(user_id_int)

        # Build dynamic WHERE clauses based on the filters dictionary.
        if filters:
            # Filter by item_type ('url' or 'qr')
            item_type = filters.get('item_type')
            # Check if filter value is provided and is not the default empty string or 'all'.
            if item_type and item_type.lower() not in ['', 'all']:
                where_clauses.append("item_type = %s")
                query_params.append(item_type) # Add type value to parameters
                logger.debug(f"History filter: Type='{item_type}'")


            # Filter by risk_level string ('Low', 'Medium', etc.).
            # This filter now applies independently of the 'is_fraud' flag filter.
            risk_level = filters.get('risk_level')
            # Check if filter value is provided and not empty/all.
            if risk_level and risk_level.lower() not in ['', 'all']:
                 # Add clause to filter by the specific risk_level string stored in the JSON.
                 # Use JSON_EXTRACT and CAST AS CHAR for robust string comparison from JSON.
                 where_clauses.append("CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) = %s")
                 query_params.append(risk_level) # Add risk_level value to parameters
                 logger.debug(f"History filter: Risk_level='{risk_level}'")


            # Filter by is_fraud (boolean True or False).
            # This filter applies independently of the risk_level filter. It checks the boolean flag.
            # Check if the key 'is_fraud' is present in the filters dictionary (meaning frontend sent the parameter).
            if 'is_fraud' in filters:
                 # Add clause to filter by the boolean 'is_fraud' flag stored in the JSON.
                 # Use CAST AS CHAR and compare to string 'true' or 'false'.
                 where_clauses.append("CAST(JSON_EXTRACT(analysis_result, '$.is_fraud') AS CHAR) = %s")
                 # Append the string 'true' or 'false' parameter based on the boolean value in the filters dict.
                 query_params.append(str(bool(filters['is_fraud'])).lower())
                 logger.debug(f"History filter: Is_fraud={bool(filters['is_fraud'])}")


            # Filter by search_term (substring search within 'item_data').
            search_term = filters.get('search_term')
            if search_term:
                # Add clause for LIKE comparison. Use % wildcards.
                where_clauses.append("item_data LIKE %s")
                query_params.append(f"%{search_term}%") # Add search term with wildcards to parameters
                logger.debug(f"History filter: Search='{search_term[:50]}...'")

            # Add more filters here as needed (e.g., date range filters would involve 'analyzed_at' column).


        # Construct the full SQL query by joining the base query and WHERE clauses.
        full_query = base_query
        if where_clauses:
            full_query += " AND " + " AND ".join(where_clauses) # Join multiple clauses with AND

        full_query += " ORDER BY analyzed_at DESC" # Order results by timestamp (newest first)


        # Log the final query and parameters for debugging.
        logger.debug(f"Executing history query for user {user_id_int}: {full_query}")
        # logger.debug(f"Query parameters: {query_params}") # Log parameters only in debug mode due to potential sensitive data

        # Use cursor(dictionary=True) to fetch rows as dictionaries.
        cursor = connection.cursor(dictionary=True)
        # Execute the full query with the collected parameters (pass parameters as a tuple).
        cursor.execute(full_query, tuple(query_params))
        history_items = cursor.fetchall() # Fetch all matching rows

        # Process the fetched history items to parse the 'analysis_result' JSON string into a Python dictionary.
        # This is done here to ensure frontend always receives parsed dictionaries.
        for item in history_items:
            # Check if 'analysis_result' key exists and its value is not None.
            if 'analysis_result' in item and item['analysis_result'] is not None:
                json_data = item['analysis_result'] # Get the value from the dictionary
                # MySQL connector might return JSON as bytes or string. Handle both.
                if isinstance(json_data, (bytes, bytearray)):
                     try:
                         # Decode bytes to UTF-8 string
                         json_string = json_data.decode('utf-8')
                     except UnicodeDecodeError:
                          logger.warning(f"Could not decode analysis_result bytes for history item ID {item.get('id')}: {json_data[:50]}... Skipping JSON parse.")
                          item['analysis_result'] = {} # Assign empty dict on decode error
                          continue # Skip to next item in loop
                elif isinstance(json_data, str):
                     json_string = json_data # Use string directly
                else:
                     # If it's not bytes or string, log warning and assign empty dict.
                     logger.warning(f"analysis_result for history item ID {item.get('id')} is not string or bytes: {type(json_data)}. Assigning empty dict.")
                     item['analysis_result'] = {}
                     continue # Skip JSON parse

                # Attempt to parse the JSON string if it's not empty or just whitespace.
                if isinstance(json_string, str) and json_string.strip():
                     try:
                        item['analysis_result'] = json.loads(json_string) # Parse JSON string to Python object (expected dict)
                        # After parsing, ensure specific keys expected by frontend are present and have correct types/defaults.
                        if isinstance(item['analysis_result'], dict):
                             # Ensure 'is_fraud' is boolean. Default to False if key missing or value is not true/false-like.
                             item['analysis_result']['is_fraud'] = bool(item['analysis_result'].get('is_fraud', False))
                             # Ensure 'risk_level' is a string. Default to 'Unknown'.
                             item['analysis_result']['risk_level'] = str(item['analysis_result'].get('risk_level', 'Unknown'))
                             # Ensure 'risk_factors' is a list. Default to empty list.
                             item['analysis_result']['risk_factors'] = list(item['analysis_result'].get('risk_factors', []))
                             # Ensure 'confidence' is a number (float). Default to 0.
                             item['analysis_result']['confidence'] = float(item['analysis_result'].get('confidence', 0))
                        else:
                             # If JSON parsed but resulted in something other than a dictionary (e.g., list, string, number, null)
                             logger.warning(f"analysis_result for history item ID {item.get('id')} was not a dictionary after JSON parsing. Got {type(item['analysis_result'])}. Assigning empty dict.")
                             item['analysis_result'] = {} # Assign empty dict to prevent errors in frontend accessing keys
                             continue # Done processing this item's result

                     except json.JSONDecodeError:
                        # Log error if JSON parsing fails for a non-empty string.
                        logger.error(f"Could not parse JSON analysis_result for history item ID {item.get('id')}. Raw data (truncated): {json_string[:100]}", exc_info=True)
                        item['analysis_result'] = {} # Assign empty dict on decode error
                else:
                     # Handle empty or whitespace-only JSON strings explicitly.
                     # logger.debug(f"analysis_result was empty/None for history item ID {item.get('id')}. Assigning empty dict.") # Debug empty case
                     item['analysis_result'] = {} # Assign empty dict

            else:
                 # If analysis_result was initially None in the database.
                 # logger.debug(f"analysis_result was NULL for history item ID {item.get('id')}. Assigning empty dict.") # Debug null case
                 item['analysis_result'] = {}


        return history_items # Return the list of processed history items

    except ValueError as e:
        # Catch error if the initial user_id conversion fails.
        logger.error(f"Error fetching user history (ValueError): Invalid user ID format '{user_id}'. Error: {e}", exc_info=True)
        return [] # Return empty list on invalid ID

    except mysql.connector.Error as e:
        # Catch specific MySQL connector errors during query execution or fetch.
        logger.error(f"MySQL Error fetching user history for user {user_id}: {e}", exc_info=True)
        return [] # Return empty list on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected Error fetching user history for user {user_id}.") # Log with traceback
        return [] # Return empty list on unexpected error

    finally:
        # Ensure cursor and connection are closed in all cases.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # logger.debug("Closing database connection in get_user_history.") # Optional debug log
             connection.close()


def delete_history_item(item_id, user_id):
    """
    Deletes a specific history item from the 'analysis_history' table.
    Ensures the item belongs to the specified user before deletion.
    Args:
        item_id (int): The ID of the history item to delete.
        user_id (int): The ID of the user attempting deletion.
    Returns:
        bool: True if the item was found and deleted, False otherwise (item not found for user, or DB error).
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Delete history item {item_id} failed for user {user_id}: Database connection could not be established.")
        return False # Indicate failure

    cursor = None
    try:
        # Attempt to convert IDs to integers, handle ValueError.
        item_id_int = int(item_id)
        user_id_int = int(user_id)

        cursor = connection.cursor() # Use default cursor
        # Delete query targeting a specific item ID AND user ID to ensure ownership.
        query = "DELETE FROM analysis_history WHERE id = %s AND user_id = %s"
        # logger.debug(f"Attempting to delete history item ID {item_id_int} for user {user_id_int}...")

        # Execute delete query with parameters.
        cursor.execute(query, (item_id_int, user_id_int,))
        connection.commit() # Commit the transaction

        # Check the number of rows affected by the DELETE statement.
        # If rowcount is 1, the item was found and deleted. If 0, item wasn't found for this user.
        if cursor.rowcount > 0:
            logger.info(f"History item with ID {item_id_int} deleted successfully by user {user_id_int}.")
            return True # Indicate successful deletion

        else:
            # Log warning if no rows were deleted (item not found for user or already deleted).
            logger.warning(f"Attempted to delete history item ID {item_id_int} for user {user_id_int}, but item was not found or not owned.")
            return False # Indicate failure (item not found/not owned)

    except ValueError:
        # Catch error if item_id or user_id cannot be converted to integer.
        logger.warning(f"Invalid item_id or user_id format for delete_history_item. item_id: '{item_id}', user_id: '{user_id}'.")
        if connection and connection.is_connected(): connection.rollback() # Rollback just in case
        return False # Indicate failure

    except Error as e:
        # Catch MySQL connector errors.
        logger.error(f"MySQL Error deleting history item {item_id} for user {user_id}: {e}", exc_info=True)
        if connection and connection.is_connected(): connection.rollback() # Rollback on error
        return False # Indicate failure

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error in delete_history_item for item {item_id}, user {user_id}.") # Log with traceback
        if connection and connection.is_connected(): connection.rollback()
        return False

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close();
        if connection and connection.is_connected():
            # logger.debug("Closing database connection in delete_history_item.") # Optional debug log
            connection.close()

def clear_user_history(user_id):
    """
    Deletes all history items for a specific user from the 'analysis_history' table.
    Args:
        user_id (int): The ID of the user whose history should be cleared.
    Returns:
        bool: True if the operation completed successfully (even if no history existed), False on database error.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Clear history failed for user {user_id}: Database connection could not be established.")
        return False # Indicate failure

    cursor = None
    try:
        # Attempt to convert user_id to integer, handle ValueError.
        user_id_int = int(user_id)

        cursor = connection.cursor() # Use default cursor
        # Delete query targeting all history items for the specific user ID.
        query = "DELETE FROM analysis_history WHERE user_id = %s"
        # logger.debug(f"Attempting to clear history for user {user_id_int}...")

        # Execute delete query.
        cursor.execute(query, (user_id_int,))
        connection.commit() # Commit the transaction

        # Check number of rows affected. Can be 0 if user had no history.
        rows_deleted = cursor.rowcount
        if rows_deleted > 0:
            logger.info(f"Cleared {rows_deleted} history items for user {user_id_int}.")
        else:
            logger.info(f"No history found to clear for user {user_id_int}.") # Log if user had no history

        return True # Indicate operation completed successfully (regardless of rows deleted)

    except ValueError:
        # Catch error if user_id is not a valid integer.
        logger.warning(f"Invalid user_id format for clear_user_history: '{user_id}'.")
        if connection and connection.is_connected(): connection.rollback() # Rollback just in case
        return False # Indicate failure

    except Error as e:
        # Catch MySQL connector errors.
        logger.error(f"MySQL Error clearing history for user {user_id}: {e}", exc_info=True)
        if connection and connection.is_connected(): connection.rollback()
        return False # Indicate failure

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected error in clear_user_history for user {user_id}.") # Log with traceback
        if connection and connection.is_connected(): connection.rollback()
        return False

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            # logger.debug("Closing database connection in clear_user_history.") # Optional debug log
            connection.close()


# --- Data Visualization Helper Functions ---
# These functions query the database to get counts for charts/statistics.

def get_risk_level_counts(user_id):
    """
    Fetches the count of analysis results grouped by risk level (and 'Fraudulent' status) for a user.
    Args:
        user_id (int): The ID of the user.
    Returns:
        dict: A dictionary where keys are risk level names (e.g., 'Critical', 'Safe', 'Fraudulent')
              and values are the counts. Returns an empty dictionary on error or if no results found.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Get risk level counts failed for user {user_id}: Database connection could not be established.")
        return {} # Return empty dict on failure

    cursor = None
    risk_counts = {} # Initialize result dictionary

    try:
        # Ensure user_id is an integer.
        user_id_int = int(user_id)

        # We need to count items based on both 'risk_level' and 'is_fraud' in the JSON.
        # 'Fraudulent' items are those where 'is_fraud' is true.
        # Other risk levels ('Critical', 'High', 'Medium', 'Low', 'Safe', 'Unknown', 'Error', 'Invalid Result') apply regardless of 'is_fraud'.
        # Let's count ALL items by their 'risk_level' string value first.
        query_all_risk_levels = """
        SELECT
            CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) as risk_level,
            COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
          AND JSON_EXTRACT(analysis_result, '$.risk_level') IS NOT NULL -- Only count items where risk_level key/value exists
        GROUP BY risk_level;
        """
        # We might ALSO want a separate count for the boolean is_fraud flag if the UI wants to highlight that specifically.
        # But the current stats endpoint in app.py is designed to show risk level distribution, including 'Fraudulent' as a category.
        # Let's rely on the 'risk_level' string from the JSON, but include 'Fraudulent' if the backend assigns it.
        # The backend's analyze_url *does* set risk_level based on confidence and prediction, including assigning 'Critical'/'High'/'Medium' when prediction is 1.
        # It does *not* currently assign the STRING 'Fraudulent' as a risk_level.
        # The frontend maps is_fraud=true to badge 'Fraudulent'.
        # The stats endpoint should count how many items have is_fraud=true.

        # Let's adjust the stats fetching logic to align with the UI display logic:
        # 1. Count by the specific 'risk_level' string for items where is_fraud is FALSE.
        # 2. Count items where is_fraud is TRUE, and label this count as 'Fraudulent'.

        # Query 1: Count by specific risk levels ONLY for items where 'is_fraud' is false.
        query_risk_levels_non_fraud = """
        SELECT
            CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) as risk_level,
            COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
          AND CAST(JSON_EXTRACT(analysis_result, '$.is_fraud') AS CHAR) = 'false'
          AND CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) IN ('Critical', 'High', 'Medium', 'Low', 'Safe', 'Unknown', 'Error', 'Invalid Result') -- Count known non-fraud levels
          AND JSON_EXTRACT(analysis_result, '$.risk_level') IS NOT NULL -- Ensure risk_level exists
        GROUP BY risk_level;
        """
        # Query 2: Count items where 'is_fraud' is true.
        query_is_fraud = """
        SELECT COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
          AND CAST(JSON_EXTRACT(analysis_result, '$.is_fraud') AS CHAR) = 'true'; -- Explicitly filter fraud items
        """
        # Optional Query 3: Count items with invalid JSON or missing is_fraud/risk_level if needed,
        # assign them to an 'Other' or 'Invalid Data' category if not covered by Q1/Q2.

        cursor = connection.cursor(dictionary=True) # Fetch results as dictionaries

        # Execute Query 1: Get counts for non-fraud risk levels
        logger.debug(f"Executing risk level counts query (non-fraud) for user {user_id_int}")
        cursor.execute(query_risk_levels_non_fraud, (user_id_int,))
        risk_level_results = cursor.fetchall()
        for row in risk_level_results:
            # Add results to the dictionary. Ensure risk_level key exists and is non-empty string.
            if row.get('risk_level'):
                 risk_counts[row['risk_level']] = row.get('count', 0) # Use .get('count', 0) for safety

        # Execute Query 2: Get count for fraudulent items
        logger.debug(f"Executing is_fraud counts query (fraud) for user {user_id_int}")
        cursor.execute(query_is_fraud, (user_id_int,))
        is_fraud_result = cursor.fetchone() # Fetch a single row (the count)
        if is_fraud_result and is_fraud_result.get('count', 0) > 0:
            # If there are fraudulent items, add their count under the key 'Fraudulent'.
            # This adds a 'Fraudulent' slice to the pie chart.
            risk_counts['Fraudulent'] = is_fraud_result.get('count', 0)

        # Optional: Execute Query 3 for other cases and add to counts if applicable.

        logger.info(f"Risk level counts fetched for user {user_id_int}: {risk_counts}")
        return risk_counts # Return the dictionary of counts

    except ValueError as e:
        # Catch error if user_id is not a valid integer.
        logger.error(f"Error fetching risk level counts (ValueError): Invalid user ID format '{user_id}'. Error: {e}", exc_info=True)
        return {} # Return empty dict on invalid ID

    except mysql.connector.Error as e:
        # Catch specific MySQL connector errors during query execution or fetch.
        logger.error(f"MySQL Error fetching risk level counts for user {user_id}: {e}", exc_info=True)
        return {} # Return empty dict on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected Error fetching risk level counts for user {user_id}.") # Log with traceback
        return {} # Return empty dict on unexpected error

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # logger.debug("Closing database connection in get_risk_level_counts.") # Optional debug log
             connection.close()


def get_type_counts(user_id):
    """
    Fetches the count of analysis results grouped by item type ('url', 'qr') for a user.
    Args:
        user_id (int): The ID of the user.
    Returns:
        dict: A dictionary where keys are item types ('url', 'qr') and values are counts.
              Returns {'url': 0, 'qr': 0} on success if no history found, or an empty dictionary on DB error.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Get type counts failed for user {user_id}: Database connection could not be established.")
        return {} # Return empty dict on failure

    cursor = None
    # Initialize type_counts with 0 for expected types, ensures keys always exist even if counts are zero.
    type_counts = {'url': 0, 'qr': 0}

    try:
        # Ensure user_id is an integer.
        user_id_int = int(user_id)

        # Query to count items grouped by item_type for the specific user.
        query = """
        SELECT item_type, COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
        GROUP BY item_type;
        """
        # logger.debug(f"Executing type counts query for user {user_id_int}")

        cursor = connection.cursor(dictionary=True) # Fetch results as dictionaries
        cursor.execute(query, (user_id_int,)) # Execute query with user ID
        results = cursor.fetchall() # Fetch all rows

        # Populate the type_counts dictionary from the query results.
        for row in results:
             # Only add counts for expected item types ('url', 'qr').
             # Use .get() with default 'Unknown' just in case, though item_type is NOT NULL.
             # If you want to include 'Unknown' types, add 'Unknown' to the initial dict and remove this check.
             if row.get('item_type') in ['url', 'qr']:
                  type_counts[row['item_type']] = row.get('count', 0) # Use .get('count', 0) for safety


        logger.info(f"Type counts fetched for user {user_id_int}: {type_counts}")
        return type_counts # Return the dictionary of counts (including 0s for missing types)

    except ValueError as e:
        # Catch error if user_id is not a valid integer.
        logger.error(f"Error fetching type counts (ValueError): Invalid user ID format '{user_id}'. Error: {e}", exc_info=True)
        return {} # Return empty dict on invalid ID

    except mysql.connector.Error as e:
        # Catch specific MySQL connector errors during query execution or fetch.
        logger.error(f"MySQL Error fetching type counts for user {user_id}: {e}", exc_info=True)
        return {} # Return empty dict on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected Error fetching type counts for user {user_id}.") # Log with traceback
        return {} # Return empty dict on unexpected error

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # logger.debug("Closing database connection in get_type_counts.") # Optional debug log
             connection.close()


# --- Admin/User Management Functions (Optional, potentially for admin interface) ---

def get_all_users():
    """
    Fetches all users (id, email, username) from the 'users' table.
    Note: This function is intended for administrative use and should be secured.
    Returns:
        list: A list of user dictionaries, or an empty list on error.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error("Get all users failed: Database connection could not be established.")
        return [] # Return empty list on failure

    cursor = None
    users = [] # Initialize users list
    query = "SELECT id, email, username FROM users"

    try:
        cursor = connection.cursor(dictionary=True) # Fetch as dictionaries
        logger.debug("Executing get_all_users query.")
        cursor.execute(query)
        users = cursor.fetchall() # Fetch all rows
        logger.debug(f"Fetched {len(users)} users.")
        return users # Return list of user dictionaries

    except Error as e:
        # Log MySQL connector errors.
        logger.error(f"MySQL Error fetching all users: {e}", exc_info=True)
        return [] # Return empty list on DB error

    except Exception as e: # Catch any other unexpected exceptions
         logger.exception(f"Unexpected error in get_all_users.") # Log with traceback
         return []

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            # logger.debug("Closing database connection in get_all_users.") # Optional debug log
            connection.close()

def delete_user_by_id(user_id):
    """
    Deletes a user by their ID from the 'users' table.
    Due to ON DELETE CASCADE in the schema, associated history items will also be deleted.
    Note: This function is intended for administrative use and should be secured.
    Args:
        user_id (int): The ID of the user to delete.
    Returns:
        bool: True if the user was found and deleted, False otherwise (user not found or DB error).
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Delete user {user_id} failed: Database connection could not be established.")
        return False # Indicate failure

    cursor = None
    try:
        # Attempt to convert user_id to integer, handle ValueError.
        user_id_int = int(user_id)

        cursor = connection.cursor() # Use default cursor
        # Delete query for the user. ON DELETE CASCADE handles history deletion.
        query_delete_user = "DELETE FROM users WHERE id = %s"
        logger.debug(f"Attempting to delete user ID: {user_id_int}")

        # Execute delete query.
        cursor.execute(query_delete_user, (user_id_int,))
        connection.commit() # Commit the transaction

        # Check number of rows affected. If 1, user was found and deleted. If 0, user wasn't found.
        if cursor.rowcount > 0:
            logger.info(f"User with ID {user_id_int} deleted successfully (and history cascaded).")
            return True # Indicate successful deletion

        else:
            # Log warning if no rows were deleted (user not found or already deleted).
            logger.warning(f"Delete user by ID: User with ID {user_id_int} not found or already deleted.")
            return False # Indicate failure (user not found)

    except ValueError:
        # Catch error if user_id is not a valid integer.
        logger.warning(f"Invalid user_id format for delete_user_by_id: '{user_id}'.")
        if connection and connection.is_connected(): connection.rollback() # Rollback just in case
        return False # Indicate failure

    except Error as e:
        # Catch MySQL connector errors.
        logger.error(f"MySQL Error deleting user {user_id}: {e}", exc_info=True)
        if connection and connection.is_connected(): connection.rollback()
        return False # Indicate failure

    except Exception as e: # Catch any other unexpected exceptions
         logger.exception(f"Unexpected error in delete_user_by_id for user {user_id}.") # Log with traceback
         if connection and connection.is_connected(): connection.rollback()
         return False

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close();
        if connection and connection.is_connected():
            # logger.debug("Closing database connection in delete_user_by_id.") # Optional debug log
            connection.close()


# --- Data Visualization Helper Functions ---
# These functions query the database to get counts for charts/statistics.

def get_risk_level_counts(user_id):
    """
    Fetches the count of analysis results grouped by risk level (and 'Fraudulent' status) for a user.
    Args:
        user_id (int): The ID of the user.
    Returns:
        dict: A dictionary where keys are risk level names (e.g., 'Critical', 'Safe', 'Fraudulent')
              and values are the counts. Returns an empty dictionary on error or if no results found.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Get risk level counts failed for user {user_id}: Database connection could not be established.")
        return {} # Return empty dict on failure

    cursor = None
    risk_counts = {} # Initialize result dictionary

    try:
        # Ensure user_id is an integer.
        user_id_int = int(user_id)

        # We need to count items based on their 'risk_level' string value from the JSON result.
        # The frontend UI displays different categories ('Fraudulent', 'Critical', 'High', etc.).
        # The backend's analyze_url sets the 'risk_level' string based on prediction and confidence.
        # It also sets the 'is_fraud' boolean flag.
        # The stats endpoint /analysis-stats in app.py calls THIS function (get_risk_level_counts).
        # The goal is for THIS function to return counts that match the categories displayed in the UI chart.
        # The UI chart labels are ['Critical', 'High', 'Medium', 'Low', 'Safe', 'Fraudulent', 'Unknown', 'Error', 'Invalid Result'].
        # The backend analysis sets 'risk_level' to Critical/High/Medium/Low/Safe/Unknown/Error. It ALSO sets 'is_fraud'.
        # The UI badge logic prioritizes 'is_fraud=true' to show 'Fraudulent'.
        # The stats chart should probably show counts for the 'risk_level' string as determined by the backend, PLUS a separate count for 'Fraudulent' items.

        # Let's define the query to aggregate counts based on the 'risk_level' string.
        # Include a case for 'Fraudulent' based on the 'is_fraud' boolean flag if needed,
        # but the current UI chart seems to just want counts by the 'risk_level' string values directly from the JSON.
        # Reverting to a single query that counts by the 'risk_level' string.
        query = """
        SELECT
            CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) as risk_level,
            COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
          AND JSON_EXTRACT(analysis_result, '$.risk_level') IS NOT NULL -- Only count items where risk_level key/value exists
          AND CAST(JSON_EXTRACT(analysis_result, '$.risk_level') AS CHAR) IN ('Critical', 'High', 'Medium', 'Low', 'Safe', 'Unknown', 'Error') -- Add 'Error' here
        GROUP BY risk_level;
        """
        # Query 2: Count items where is_fraud is true - this is needed if UI wants 'Fraudulent' as a separate category
        query_is_fraud = """
        SELECT COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
          AND CAST(JSON_EXTRACT(analysis_result, '$.is_fraud') AS CHAR) = 'true'; -- Explicitly filter fraud items
        """


        cursor = connection.cursor(dictionary=True) # Fetch results as dictionaries

        # Execute Query 1: Get counts by risk level string (excluding explicit 'Fraudulent' if backend doesn't set that string)
        logger.debug(f"Executing risk level counts query (by string) for user {user_id_int}")
        cursor.execute(query, (user_id_int,))
        risk_level_results = cursor.fetchall()
        for row in risk_level_results:
            # Add results to the dictionary. Ensure risk_level key exists and is non-empty string.
            if row.get('risk_level'):
                 risk_counts[row['risk_level']] = row.get('count', 0) # Use .get('count', 0) for safety


        # Execute Query 2: Get count for fraudulent items (based on is_fraud boolean)
        logger.debug(f"Executing is_fraud counts query (fraud) for user {user_id_int}")
        cursor.execute(query_is_fraud, (user_id_int,))
        is_fraud_result = cursor.fetchone() # Fetch a single row (the count)
        if is_fraud_result and is_fraud_result.get('count', 0) > 0:
            # If there are fraudulent items, add their count under the key 'Fraudulent'.
            # This ensures the 'Fraudulent' category appears in the stats.
            risk_counts['Fraudulent'] = risk_counts.get('Fraudulent', 0) + is_fraud_result.get('count', 0) # Add to any items already counted under a risk_level string if needed, or just use the explicit fraud count. Let's use the explicit fraud count.
            risk_counts['Fraudulent'] = is_fraud_result.get('count', 0)


        logger.info(f"Risk level counts fetched for user {user_id_int}: {risk_counts}")
        return risk_counts # Return the dictionary of counts

    except ValueError as e:
        # Catch error if user_id is not a valid integer.
        logger.error(f"Error fetching risk level counts (ValueError): Invalid user ID format '{user_id}'. Error: {e}", exc_info=True)
        return {} # Return empty dict on invalid ID

    except mysql.connector.Error as e:
        # Catch specific MySQL connector errors during query execution or fetch.
        logger.error(f"MySQL Error fetching risk level counts for user {user_id}: {e}", exc_info=True)
        return {} # Return empty dict on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected Error fetching risk level counts for user {user_id}.") # Log with traceback
        return {} # Return empty dict on unexpected error

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # logger.debug("Closing database connection in get_risk_level_counts.") # Optional debug log
             connection.close()


def get_type_counts(user_id):
    """
    Fetches the count of analysis results grouped by item type ('url', 'qr') for a user.
    Args:
        user_id (int): The ID of the user.
    Returns:
        dict: A dictionary where keys are item types ('url', 'qr') and values are counts.
              Returns {'url': 0, 'qr': 0} on success if no history found, or an empty dictionary on DB error.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Get type counts failed for user {user_id}: Database connection could not be established.")
        return {} # Return empty dict on failure

    cursor = None
    # Initialize type_counts with 0 for expected types, ensures keys always exist even if counts are zero.
    type_counts = {'url': 0, 'qr': 0}

    try:
        # Ensure user_id is an integer.
        user_id_int = int(user_id)

        # Query to count items grouped by item_type for the specific user.
        query = """
        SELECT item_type, COUNT(*) as count
        FROM analysis_history
        WHERE user_id = %s
        GROUP BY item_type;
        """
        # logger.debug(f"Executing type counts query for user {user_id_int}")

        cursor = connection.cursor(dictionary=True) # Fetch results as dictionaries
        cursor.execute(query, (user_id_int,)) # Execute query with user ID
        results = cursor.fetchall() # Fetch all rows

        # Populate the type_counts dictionary from the query results.
        for row in results:
             # Only add counts for expected item types ('url', 'qr').
             # Use .get() with default 'Unknown' just in case, though item_type is NOT NULL.
             # If you want to include 'Unknown' types, add 'Unknown' to the initial dict and remove this check.
             if row.get('item_type') in ['url', 'qr']:
                  type_counts[row['item_type']] = row.get('count', 0) # Use .get('count', 0) for safety


        logger.info(f"Type counts fetched for user {user_id_int}: {type_counts}")
        return type_counts # Return the dictionary of counts (including 0s for missing types)

    except ValueError as e:
        # Catch error if user_id is not a valid integer.
        logger.error(f"Error fetching type counts (ValueError): Invalid user ID format '{user_id}'. Error: {e}", exc_info=True)
        return {} # Return empty dict on invalid ID

    except mysql.connector.Error as e:
        # Catch specific MySQL connector errors during query execution or fetch.
        logger.error(f"MySQL Error fetching type counts for user {user_id}: {e}", exc_info=True)
        return {} # Return empty dict on DB error

    except Exception as e: # Catch any other unexpected exceptions
        logger.exception(f"Unexpected Error fetching type counts for user {user_id}.") # Log with traceback
        return {} # Return empty dict on unexpected error

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
             # logger.debug("Closing database connection in get_type_counts.") # Optional debug log
             connection.close()


# --- Admin/User Management Functions (Optional, potentially for admin interface) ---

def get_all_users():
    """
    Fetches all users (id, email, username) from the 'users' table.
    Note: This function is intended for administrative use and should be secured.
    Returns:
        list: A list of user dictionaries, or an empty list on error.
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error("Get all users failed: Database connection could not be established.")
        return [] # Return empty list on failure

    cursor = None
    users = [] # Initialize users list
    query = "SELECT id, email, username FROM users"

    try:
        cursor = connection.cursor(dictionary=True) # Fetch as dictionaries
        logger.debug("Executing get_all_users query.")
        cursor.execute(query)
        users = cursor.fetchall() # Fetch all rows
        logger.debug(f"Fetched {len(users)} users.")
        return users # Return list of user dictionaries

    except Error as e:
        # Log MySQL connector errors.
        logger.error(f"MySQL Error fetching all users: {e}", exc_info=True)
        return [] # Return empty list on DB error

    except Exception as e: # Catch any other unexpected exceptions
         logger.exception(f"Unexpected error in get_all_users.") # Log with traceback
         return []

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            # logger.debug("Closing database connection in get_all_users.") # Optional debug log
            connection.close()

def delete_user_by_id(user_id):
    """
    Deletes a user by their ID from the 'users' table.
    Due to ON DELETE CASCADE in the schema, associated history items will also be deleted.
    Note: This function is intended for administrative use and should be secured.
    Args:
        user_id (int): The ID of the user to delete.
    Returns:
        bool: True if the user was found and deleted, False otherwise (user not found or DB error).
    """
    connection = create_db_connection() # Create a new connection
    if connection is None:
        logger.error(f"Delete user {user_id} failed: Database connection could not be established.")
        return False # Indicate failure

    cursor = None
    try:
        # Attempt to convert user_id to integer, handle ValueError.
        user_id_int = int(user_id)

        cursor = connection.cursor() # Use default cursor
        # Delete query for the user. ON DELETE CASCADE handles history deletion.
        query_delete_user = "DELETE FROM users WHERE id = %s"
        logger.debug(f"Attempting to delete user ID: {user_id_int}")

        # Execute delete query.
        cursor.execute(query_delete_user, (user_id_int,))
        connection.commit() # Commit the transaction

        # Check number of rows affected. If 1, user was found and deleted. If 0, user wasn't found.
        if cursor.rowcount > 0:
            logger.info(f"User with ID {user_id_int} deleted successfully (and history cascaded).")
            return True # Indicate successful deletion

        else:
            # Log warning if no rows were deleted (user not found or already deleted).
            logger.warning(f"Delete user by ID: User with ID {user_id_int} not found or already deleted.")
            return False # Indicate failure (user not found)

    except ValueError:
        # Catch error if user_id is not a valid integer.
        logger.warning(f"Invalid user_id format for delete_user_by_id: '{user_id}'.")
        if connection and connection.is_connected(): connection.rollback() # Rollback just in case
        return False # Indicate failure

    except Error as e:
        # Catch MySQL connector errors.
        logger.error(f"MySQL Error deleting user {user_id}: {e}", exc_info=True)
        if connection and connection.is_connected(): connection.rollback()
        return False # Indicate failure

    except Exception as e: # Catch any other unexpected exceptions
         logger.exception(f"Unexpected error in delete_user_by_id for user {user_id}.") # Log with traceback
         if connection and connection.is_connected(): connection.rollback()
         return False

    finally:
        # Close cursor and connection.
        if cursor:
            cursor.close();
        if connection and connection.is_connected():
            # logger.debug("Closing database connection in delete_user_by_id.") # Optional debug log
            connection.close()

# --- ADDED: Function to Append Data to Training File ---
def append_training_data(file_path, item_data, label):
    """
    Appends a new data sample (item_data, label) to the specified training data file (CSV).
    This is used for user feedback to grow the real-world training dataset.
    Args:
        file_path (str): The path to the training data file (e.g., 'Notebook/your_real_data.csv').
        item_data (str): The URL or QR content string that was analyzed.
        label (int): The correct label for the item_data (0 for legitimate, 1 for fraudulent).
    Returns:
        bool: True if data was successfully appended, False otherwise.
    """
    try:
        # Check if the file exists. If not, create it and write the header.
        # This ensures the file is ready for appending even if it didn't exist before feedback.
        file_exists = os.path.exists(file_path)

        # Open the file in append mode ('a'). Use newline='' to prevent extra blank rows on Windows.
        # Use encoding='utf-8' for consistency.
        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write header row ONLY if the file did not exist before opening (it was just created).
            if not file_exists:
                writer.writerow(['url', 'label']) # Write the expected header row

            # Write the new data row (item_data and label).
            writer.writerow([item_data, label]) # csv.writer handles quoting if needed

        logger.info(f"Appended data sample to training file '{os.path.basename(file_path)}'. Item: '{item_data[:50]}...', Label: {label}")
        return True # Indicate success

    except Exception as e:
        # Catch any errors during file operations (opening, writing).
        logger.exception(f"Error appending data sample to training file '{file_path}'.")
        return False # Indicate failure
# --- END ADDED ---

# --- Example Usage (for testing this handler.py file itself) ---
# This block runs only when the script is executed directly.
if __name__ == "__main__":
    print("\n--- Running helpers/db/handler.py for testing ---")

    # Configure Python logging specifically for this standalone script run.
    # This is separate from the logging configured in app.py's __main__ block.
    # Setting level to DEBUG here provides more detailed output for testing the handler functions.
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Re-get the logger instance after basicConfig, ensures it uses the new configuration.
    logger = logging.getLogger(__name__)
    logger.info("Logging configured for standalone handler testing.")


    # Test database connection
    logger.info("Testing database connection...")
    conn = create_db_connection()
    if conn:
        logger.info("Simple database connection test successful.")
        conn.close()
    else:
        logger.critical("Simple database connection test failed. Please check your MySQL server and credentials in the .env file.")
        sys.exit(1) # Exit if cannot connect

    # Test fetching all users
    logger.info("\nAttempting to get all users...")
    all_users = get_all_users() # Call the function
    if all_users is not None: # get_all_users returns [] on success or error if logging works
        if all_users:
            logger.info(f"Fetched {len(all_users)} users:")
            for user in all_users:
                print(f"ID: {user.get('id')}, Email: {user.get('email')}, Username: {user.get('username')}") # Use print for script output
        else:
            logger.info("No users found in the database.")
    else:
        logger.error("Failed to fetch users due to a database error (see logs).") # Point user to logs


    # --- Example: Test History Filtering ---
    logger.info("\nAttempting to fetch history with filters...")
    # IMPORTANT: Replace with an actual user ID that exists in your database and has history.
    test_user_id = 1 # Default test user ID

    # Example filters dictionary for testing the get_user_history function logic.
    # These filters match the parameters expected by the /history API endpoint in app.py.
    filters_url_only = {'item_type': 'url'}
    filters_qr_only = {'item_type': 'qr'} # Added QR filter example
    filters_fraud_only = {'is_fraud': True} # Frontend sends 'true' string, handler expects bool from frontend logic or string for query param
    filters_not_fraud_only = {'is_fraud': False} # Frontend sends 'false' string, handler expects bool or string for query param
    # Test specific risk level filters (should NOT implicitly exclude fraudulent items anymore)
    filters_critical_risk = {'risk_level': 'Critical'} # Frontend selects 'Critical'
    filters_high_risk = {'risk_level': 'High'}
    filters_medium_risk = {'risk_level': 'Medium'}
    filters_low_risk = {'risk_level': 'Low'}
    filters_safe_risk = {'risk_level': 'Safe'}
    filters_unknown_risk = {'risk_level': 'Unknown'}
    filters_search_example = {'search_term': 'example'} # Search for 'example' in item_data
    filters_all = {} # Empty filter dictionary means no filters applied
    # Example of a compound filter: URL type AND High risk AND Not Fraudulent
    filters_compound = {'item_type': 'url', 'risk_level': 'High', 'is_fraud': False} # This combination should now work IF you have a URL analysis that is 'High' risk AND Not Fraudulent.

    # Example: Compound filter - URL type AND Fraudulent (should include Critical/High/Medium URLs that are fraud)
    filters_url_and_fraud = {'item_type': 'url', 'is_fraud': True}


    # Run get_user_history with various filters and print results (using logger for function output, print for summary)
    logger.info(f"\nFetching history for user {test_user_id} (All items):")
    history_all = get_user_history(test_user_id, filters_all)
    print(f"Found {len(history_all)} items matching 'All' filters.")
    # if history_all: print("First item example:", history_all[0]) # Print first item example


    logger.info(f"\nFetching history for user {test_user_id} (URL only):")
    history_url = get_user_history(test_user_id, filters_url_only)
    print(f"Found {len(history_url)} URL items.")


    logger.info(f"\nFetching history for user {test_user_id} (Fraudulent only):")
    history_fraud = get_user_history(test_user_id, filters_fraud_only)
    print(f"Found {len(history_fraud)} fraudulent items.")

    logger.info(f"\nFetching history for user {test_user_id} (Not Fraudulent only):")
    history_not_fraud = get_user_history(test_user_id, filters_not_fraud_only)
    print(f"Found {len(history_not_fraud)} not fraudulent items.")


    # Test specific risk level filters (should now include fraudulent items IF they have that risk_level string)
    logger.info(f"\nFetching history for user {test_user_id} (Critical Risk only):")
    history_critical = get_user_history(test_user_id, filters_critical_risk)
    print(f"Found {len(history_critical)} critical risk items.")

    logger.info(f"\nFetching history for user {test_user_id} (High Risk only):")
    history_high = get_user_history(test_user_id, filters_high_risk)
    print(f"Found {len(history_high)} high risk items.")

    logger.info(f"\nFetching history for user {test_user_id} (Medium Risk only):")
    history_medium = get_user_history(test_user_id, filters_medium_risk)
    print(f"Found {len(history_medium)} medium risk items.")

    logger.info(f"\nFetching history for user {test_user_id} (Low Risk only):")
    history_low = get_user_history(test_user_id, filters_low_risk)
    print(f"Found {len(history_low)} low risk items.")

    logger.info(f"\nFetching history for user {test_user_id} (Safe Risk only):")
    history_safe = get_user_history(test_user_id, filters_safe_risk)
    print(f"Found {len(history_safe)} safe risk items.")

    logger.info(f"\nFetching history for user {test_user_id} (Unknown Risk only):")
    history_unknown = get_user_history(test_user_id, filters_unknown_risk)
    print(f"Found {len(history_unknown)} unknown risk items.")

    logger.info(f"\nFetching history for user {test_user_id} (Search term 'example'):")
    history_search = get_user_history(test_user_id, filters_search_example)
    print(f"Found {len(history_search)} items matching search term.")

    logger.info(f"\nFetching history for user {test_user_id} (Compound Filter - URL & High & Not Fraud):")
    filters_compound = {'item_type': 'url', 'risk_level': 'High', 'is_fraud': False}
    history_compound = get_user_history(test_user_id, filters_compound)
    print(f"Found {len(history_compound)} items matching compound filter.")
    # if history_compound: print("First compound item example:", history_compound[0])

    logger.info(f"\nFetching history for user {test_user_id} (Compound Filter - URL & Fraudulent):")
    filters_url_and_fraud = {'item_type': 'url', 'is_fraud': True}
    history_url_and_fraud = get_user_history(test_user_id, filters_url_and_fraud)
    print(f"Found {len(history_url_and_fraud)} items matching compound filter.")


    # --- Test getting analysis stats counts ---
    logger.info(f"\nAttempting to get risk level counts for user {test_user_id}:")
    risk_counts = get_risk_level_counts(test_user_id)
    print(f"Risk Counts: {risk_counts}")

    logger.info(f"\nAttempting to get type counts for user {test_user_id}:")
    type_counts = get_type_counts(test_user_id)
    print(f"Type Counts: {type_counts}")

    # --- Test Appending Data to Training File ---
    logger.info("\nAttempting to append data to training file...")
    # Define the path to the test training data file (must match app.py and fraud_detection_model_.py)
    # Assuming the file is in the Notebook directory relative to the project root
    test_training_data_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Notebook', 'your_real_data.csv') # Go up two levels from helpers/db to project root, then into Notebook

    test_item_data = "http://example.com/feedback/test"
    test_label = 0 # Assuming it's legitimate feedback

    logger.info(f"Appending '{test_item_data}' with label {test_label} to '{os.path.basename(test_training_data_file_path)}'")
    append_success = append_training_data(test_training_data_file_path, test_item_data, test_label)

    if append_success:
        logger.info("Data appended successfully.")
        # Verify by trying to load the file content (optional)
        try:
            with open(test_training_data_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.debug(f"Current content of training file:\n---\n{content}\n---")
        except Exception as e:
             logger.error(f"Error reading training file after append: {e}")
    else:
        logger.error("Failed to append data to training file.")
    # --- End Test Appending ---


    print("\n--- Testing Complete ---")