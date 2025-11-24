import os
import sys

# This file is for testing the Static Vulnerability Scanner's ability to count
# and report multiple instances of each vulnerability category.

# --- 1. RISKY FUNCTION (Code Injection Risk: eval, exec) ---

# First Risky Issue (Line 10): Simple use of eval()
def run_risky_eval(code_str):
    # This call should be flagged as HIGH severity
    result_a = eval(code_str)
    return result_a

# Second Risky Issue : Simple use of exec()
def run_risky_exec(command_str):
    #This call should also be flagged as HIGH severity
    exec(command_str)


# MISSING INPUT VALIDATION

# First Validation Issue : Direct use of input()
def get_user_data_a():
    #This call should be flagged as MEDIUM severity
    data_a = input("Enter your username: ")
    if data_a == "admin":
        print("Welcome!")

# Second Validation Issue : Direct use of sys.argv[]
def get_user_data_b():
    # This call should also be flagged as MEDIUM severity
    if len(sys.argv) > 1:
        file_path = sys.argv[1] #  Direct use of unvalidated command-line input
        try:
            with open(file_path, 'r') as f:
                print(f"Opening file: {f.name}")
        except Exception:
            pass


# DEPRECATED FUNCTIONS 

# First Deprecated Issue: Use of os.popen()
def run_deprecated_a():
    # This call should be flagged as LOW severity
    stream = os.popen('echo "hello world"')
    return stream.read()

# Second Deprecated Issue: Another use of os.popen()
def run_deprecated_b():
    # This second instance should also be flagged.
    output = os.popen('ls -l').read()
    return output


if __name__ == "__main__":
    print("Test script loaded.")
    # Execution is commented out to prevent side effects, but the code remains to be scanned.
    # run_risky_eval("1+1")
    # run_risky_exec("print('Executed')")
    # get_user_data_a() 
    # get_user_data_b()
    # run_deprecated_a()
    # run_deprecated_b()