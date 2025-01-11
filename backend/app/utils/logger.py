"""
Module: logger
Description:
    Configures and provides a default logger for application-wide logging.
    The logger outputs logs to stdout with a standard format including timestamp, log level, and module.
"""

import logging
import sys

def setup_logger(name=__name__, level=logging.DEBUG):
    """
    Create and configure a logger with the specified name and logging level.
    
    This function sets up a logger with a StreamHandler that writes to stdout and applies a custom formatter.
    If the logger already has handlers attached, new handlers are not added.
    
    Args:
        name (str): The name of the logger. Default is the module name.
        level (int): The logging level (e.g., logging.DEBUG, logging.INFO). Default is logging.DEBUG.
    
    Returns:
        logging.Logger: The configured logger instance.
    """
    # Create a new logger with the provided name
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create a stream handler to output logs to stdout
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    
    # Create a formatter including the timestamp, log level, and module information
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    ch.setFormatter(formatter)
    
    # Only add a new handler if there are no existing handlers attached to this logger
    if not logger.handlers:
        logger.addHandler(ch)
    
    return logger

# Initialize a default logger for the application
logger = setup_logger(__name__)
