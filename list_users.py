# D:\Projects\Fraud Detection using ML\Fraud_detection_using_ML\list_users.py

import sqlite3
import os
import sys # Import sys for printing to stderr

# Get the directory where this script is located
current_script_dir = os.path.dirname(os.path.abspath(__file__))
# Assuming database.db is in a 'database' folder in the project root
# And this script (list_users.py) is in the project root
project_root = current_script_dir # If you put list_users.py in the project root
db_path = os.path.join(project_root, 'database', 'database.db')

# --- Double-check the db_path ---
# If you saved list_users.py inside 'Python scripts', you might need this instead:
# current_script_dir = os.path.dirname(os.path.abspath(__file__))
# project_root = os.path.dirname(current_script_dir) # Go up one level from 'Python scripts'
# db_path = os.path.join(project_root, 'database', 'database.db')
print(f"Attempting to connect to: {db_path}", file=sys.stderr) # Optional: uncomment to verify the path


conn = None
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Select id, email, and username from the users table
    cursor.execute("SELECT id, email, username FROM users")

    users = cursor.fetchall()

    if users:
        print("Users in the database:")
        print("---------------------")
        for user in users:
            print(f"ID: {user[0]}, Email: {user[1]}, Username: {user[2]}")
    else:
        print("No users found in the database.")

except sqlite3.Error as e:
    print(f"Database error: {e}", file=sys.stderr)
except FileNotFoundError:
     print(f"Error: Database file not found at {db_path}", file=sys.stderr)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
finally:
    if conn:
        conn.close()