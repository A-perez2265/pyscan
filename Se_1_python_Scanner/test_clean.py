import sys
import os
import hashlib
import json
import subprocess # Used for safe command execution

# --- File: test_clean_production.py ---
# This script uses only safe functions, modern modules, and validated practices.

# 1. Safe Hashing (Uses SHA-256, avoids MD5/SHA1)
def generate_safe_hash(data: str) -> str:
    """Generates a cryptographic hash using SHA-256."""
    # NO hashlib.md5 or hashlib.sha1
    hasher = hashlib.sha256()
    hasher.update(data.encode('utf-8'))
    return hasher.hexdigest()

# 2. Safe Command Execution (Uses subprocess, avoids shell=True and os.popen/os.system)
def list_files_safely(directory: str):
    """Executes a command using a list, preventing shell injection."""
    
    # NO os.system, os.popen, or shell=True
    try:
        # Command arguments passed as a list (secure)
        result = subprocess.run(['ls', '-l', directory], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return "Command failed."

# 3. Safe Data Conversion (No eval() or pickle.load)
def safe_data_conversion(data_string: str) -> dict:
    """Safely converts a string to a dictionary."""
    # NO eval(), exec(), or pickle.load(s)
    try:
        data = json.loads(data_string)
        return data
    except json.JSONDecodeError:
        return {}

# 4. Input Handling and File Access (Validation Bypass)
def process_validated_path(path_variable: str):
    
    # Validation checks would occur here in a real app, 
    # but the function itself does not call the dangerous input sources.
    safe_path = os.path.basename(path_variable)
    
    # Safe file access (assuming safe_path is clean, and not derived directly from input()/sys.argv in this scope)
    try:
        with open(safe_path, 'r') as f:
            content = f.read(10)
        return content
    except FileNotFoundError:
        return "File not found."

# 5. Safe Database Query (Parameterized Query structure)
def query_database_safely(cursor, user_id):
    """Uses parameterized queries, preventing SQL injection."""
    # NO f-strings in execute() calls to prevent SQL injection
    sql_query = "SELECT username FROM users WHERE id = %s" 
    
    # The vulnerability scanner should NOT flag this line.
    cursor.execute(sql_query, (user_id,))
    # Note: This is simplified pseudocode for testing the regex
    return cursor.fetchone() 

# Main execution block
if __name__ == "__main__":
    # Test execution using constants (no user input)
    print("Clean script running...")
    
    # Simulate a cursor and execute to test the SQL regex bypass
    class MockCursor:
        def execute(self, query, params):
            pass
        def fetchone(self):
            return ("TestUser",)
            
    mock_cursor = MockCursor()
    query_database_safely(mock_cursor, 101)
    
    print("Clean script finished.")