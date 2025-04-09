# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
from typing import Any, Dict
import json

logger = logging.getLogger()

def setup_logging(level: str = 'INFO') -> None:
    """
    Configure logging for the application.
    
    Args:
        level: Logging level (default: 'INFO')
    """
    logging.getLogger().setLevel(level)
    
    # Reduce logging noise from AWS SDK
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    
    # Set format for logging
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure handler if none exists
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)

def log_event(event: Dict[str, Any]) -> None:
    """
    Log the Lambda event in a formatted way.
    
    Args:
        event: Lambda event to log
    """
    logger.info(f"Event received: {json.dumps(event, default=str)}")