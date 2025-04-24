def log_error(error: Exception, context: str = ""):
    # In a production application, you might want to log to a file or a logging service.
    # For this project, printing to the console is sufficient.
    # Ensure the error is converted to a string in case it's an exception object
    error_message = str(error)
    if context:
        print(f"[ERROR] {context}: {error_message}")
    else:
        print(f"[ERROR] {error_message}")