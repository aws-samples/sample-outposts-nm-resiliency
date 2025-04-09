# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import logging
import os
from typing import Dict, Any, List
from botocore.exceptions import ClientError

from .logging_utils import setup_logging

logger = logging.getLogger()
setup_logging()

def get_baseline_template() -> Dict[str, Any]:
    """
    Get the baseline template from the packaged template file.
    
    Returns:
        Dictionary containing the baseline CloudFormation template
    """
    try:
        # Since the template is in the same directory as the Lambda function
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            os.environ['MONITORING_STACK_TEMPLATE_PATH']
        )
        logger.debug(f"Reading baseline template from: {template_path}")
        
        with open(template_path, 'r') as f:
            template = json.load(f)
            
        logger.debug(f"Successfully loaded baseline template: {json.dumps(template, default=str)}")
        return template
        
    except Exception as e:
        logger.error(f"Error reading baseline template: {str(e)}", exc_info=True)
        raise

def update_monitoring_stack(
    cfn_client: Any,
    stack_arn: str,
    alarm_definitions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Update the nested monitoring stack with new alarm definitions or revert to baseline.
    
    Args:
        cfn_client: AWS CloudFormation client
        stack_arn: ARN of the nested monitoring stack
        alarm_definitions: List of alarm definitions (empty if no alarms needed)
        
    Returns:
        Dictionary containing update status and details
    """
    try:
        # Get baseline template
        template = get_baseline_template()
        
        # Add alarm resources if we have any
        if alarm_definitions:
            logger.info(f"Updating monitoring stack with {len(alarm_definitions)} alarm definitions")
            
            # Clear existing resources except Placeholder
            template["Resources"] = {}
            
            # Add alarm resources
            for alarm_def in alarm_definitions:
                if 'name' in alarm_def and 'definition' in alarm_def:
                    template["Resources"][alarm_def['name']] = alarm_def['definition']
                else:
                    logger.warning(
                        f"Skipping invalid alarm definition: {json.dumps(alarm_def, default=str)}"
                    )
        else:
            logger.info(
                "No alarms to deploy, using baseline template."
            )
        
        try:
            logger.info(
                f"Initiating update for monitoring stack {stack_arn} "
                f"with {len(template.get('Resources', {}))} resources"
            )
            response = cfn_client.update_stack(
                StackName=stack_arn,
                TemplateBody=json.dumps(template),
                Capabilities=['CAPABILITY_IAM']
            )
            logger.info(
                f"Successfully initiated monitoring stack update. "
                f"Stack ID: {response['StackId']}"
            )
            return {
                'status': 'SUCCESS',
                'operation': 'UPDATE',
                'stack_id': response['StackId']
            }
        except ClientError as e:
            if 'No updates are to be performed' in str(e):
                logger.info("No updates needed for monitoring stack")
                return {
                    'status': 'SUCCESS',
                    'operation': 'NO_UPDATES_NEEDED'
                }
            logger.error(
                f"Error updating stack: {str(e)}",
                exc_info=True
            )
            raise

    except Exception as e:
        logger.error(
            f"Error updating monitoring stack: {str(e)}",
            exc_info=True
        )
        return {
            'status': 'ERROR',
            'error_type': type(e).__name__,
            'error_message': str(e)
        }
