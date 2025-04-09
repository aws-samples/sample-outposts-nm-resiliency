# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import logging
import os
from typing import Dict, Any

from shared.aws_clients import AWSClients
from shared.models import MonitorConfig
from shared.monitor import OutpostMonitor
from shared.utils.logging_utils import setup_logging, log_event

logger = logging.getLogger()
setup_logging()

class AlarmProcessor:
    def __init__(self, aws_clients: AWSClients, sns_topic_arn: str):
        self.clients = aws_clients
        self.sns_topic_arn = sns_topic_arn

    def get_alarm_details(self, alarm_name: str) -> Dict[str, Any]:
        """Get current alarm configuration and history."""
        try:
            alarm = self.clients.cloudwatch.describe_alarms(
                AlarmNames=[alarm_name]
            )['MetricAlarms'][0]

            history = self.clients.cloudwatch.describe_alarm_history(
                AlarmName=alarm_name,
                HistoryItemType='StateUpdate',
                MaxRecords=1
            )['AlarmHistoryItems']

            return {
                'alarm': alarm,
                'history': history[0] if history else None
            }
        except Exception as e:
            logger.error(f"Error getting alarm details: {str(e)}")
            raise

    def verify_threshold(self, monitor: OutpostMonitor, instance_type: str, current_threshold: float) -> bool:
        """Verify if the current alarm threshold is still accurate."""
        try:
            assets = monitor.get_assets()
            results = monitor.analyze_instance_type(instance_type, assets)
            
            if not isinstance(results, dict):
                logger.error(f"Invalid analysis results for {instance_type}")
                return False

            # If the analysis shows insufficient hosts, any threshold is valid
            # as the instance type can't meet N+M requirements
            if (results.get('details', {}).get('reason') == 'insufficient_hosts' or
                'insufficient hosts' in results.get('details', {}).get('reason', '')):
                logger.info(
                    f"Instance type {instance_type} cannot meet N+M requirements due to insufficient hosts. "
                    "Current threshold is valid."
                )
                return True

            # For all other cases, verify the calculated threshold
            if 'details' in results and 'threshold' in results['details']:
                calculated_threshold = results['details']['threshold']
                return calculated_threshold == current_threshold

            return False

        except Exception as e:
            logger.error(f"Error verifying threshold: {str(e)}")
            return False

    def generate_report(
        self,
        alarm_info: Dict[str, Any],
        monitor: OutpostMonitor,
        instance_type: str,
        needs_update: bool
    ) -> str:
        """Generate focused report for the alarm state change."""
        try:
            instance_family = instance_type.split('.')[0]
            assets = monitor.get_assets()
            
            # Only analyze instance types from the same family
            family_instance_types = {
                itype for itype in monitor.get_instance_types() 
                if itype.startswith(f"{instance_family}.")
            }
            
            results = {}
            for itype in family_instance_types:
                results[itype] = monitor.analyze_instance_type(itype, assets)

            vcpu_metrics = monitor._calculate_vcpu_metrics(instance_family, assets)
            
            # Get m_value from the monitor's instance_family_resiliency_map or default
            m_value = monitor.config.instance_family_resiliency_map.get(
                instance_family, 
                monitor.config.m_value
            )

            # Determine status indicator and message based on state
            status_indicator = "⚠️ PROBLEM DETECTED" if alarm_info['state'] == 'ALARM' else "✅ PROBLEM RESOLVED"
            status_message = (
                "Instance count exceeds resiliency threshold" if alarm_info['state'] == 'ALARM' 
                else "Instance count now within resiliency threshold"
            )
            
            report_data = {
                'instance_families': {
                    instance_family: {
                        'status': 'RED' if any(r['status'] == 'RED' for r in results.values()) else 'GREEN',
                        'm_value': m_value,
                        'red_instance_types': {
                            itype: result['details']
                            for itype, result in results.items()
                            if result['status'] == 'RED'
                        },
                        'vcpu_metrics': vcpu_metrics
                    }
                }
            }

            # Generate report header with more details and better formatting
            header = f"""
{'=' * 80}
                         {status_indicator}
{'=' * 80}

ALARM STATUS DETAILS
-------------------
Status Message:  {status_message}
Instance Type:  {instance_type}
Outpost ID:     {monitor.config.outpost_id}

State Transition
---------------
Previous State: {alarm_info['previous_state']}
Current State:  {alarm_info['state']}
Change Time:    {alarm_info['timestamp']}

Metric Information
-----------------
Current Value:  {alarm_info['current_value']} instances
Threshold:      {alarm_info['threshold']} instances

Transition Reason
----------------
{alarm_info['reason']}

{'=' * 80}
"""
            if needs_update:
                header += f"""
⚠️  ACTION REQUIRED
-------------------
The alarm threshold appears to be outdated. Please run the Monitoring Stack Manager
to update the alarm definitions with current thresholds.

{'=' * 80}
"""

            # Add transitional message
            transition_message = f"""
COMPLETE FAMILY ANALYSIS
-----------------------
For a comprehensive understanding of the current situation, below is the complete
resiliency analysis for the {instance_family.upper()} instance family, which includes
the {instance_type} instance type that triggered this alert.

This analysis provides context about:
• The overall family resiliency status
• Status of all instance types in the family
• Current vCPU capacity and utilization
• Potential impact of host failures
• Available mitigation options

{'=' * 80}
"""
            # Generate family report section using existing monitor reporter
            family_report = monitor.reporter._generate_family_report_section(
                instance_family,
                report_data['instance_families'][instance_family],
                monitor.config.outpost_id
            )

            return header + transition_message + family_report

        except Exception as e:
            logger.error(f"Error generating alarm report: {str(e)}")
            return f"Error generating report: {str(e)}"

def should_process_alarm(alarm_data: Dict[str, Any]) -> bool:
    """
    Determine if the alarm state change should be processed.
    Only process transitions between OK and ALARM states.
    
    Args:
        alarm_data: Alarm data from CloudWatch event
        
    Returns:
        bool: True if the transition should be processed, False otherwise
    """
    previous_state = alarm_data['previousState']['value']
    current_state = alarm_data['state']['value']
    
    # Only process OK->ALARM or ALARM->OK transitions
    valid_transition = (
        (previous_state == 'OK' and current_state == 'ALARM') or
        (previous_state == 'ALARM' and current_state == 'OK')
    )
    
    if not valid_transition:
        logger.info(
            "Skipping alarm state change:\n"
            f"Alarm Name: {alarm_data['alarmName']}\n"
            f"Transition: {previous_state} -> {current_state}\n"
            f"Timestamp: {alarm_data['state']['timestamp']}"
        )
    
    return valid_transition

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Process CloudWatch alarm state changes."""
    try:
        # Set up structured logging format
        log_context = {
            'aws_request_id': context.aws_request_id,
            'function_name': context.function_name,
            'function_version': context.function_version,
        }
        
        logger.info(
            "Processing alarm event",
            extra={
                **log_context,
                'event_source': event.get('source'),
                'event_time': event.get('time')
            }
        )
        
        # Extract alarm information from the CloudWatch event structure
        alarm_data = event['alarmData']
        
        # Check if we should process this state change
        if not should_process_alarm(alarm_data):
            response = {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Skipped processing - not a transition between OK and ALARM',
                    'alarm_name': alarm_data['alarmName'],
                    'from_state': alarm_data['previousState']['value'],
                    'to_state': alarm_data['state']['value'],
                    'evaluation_time': alarm_data['state']['timestamp']
                })
            }
            logger.info(
                "Skipped alarm processing",
                extra={
                    **log_context,
                    'alarm_name': alarm_data['alarmName'],
                    'reason': 'not_valid_transition'
                }
            )
            return response

        alarm_state = alarm_data['state']
        alarm_config = alarm_data['configuration']
        
        # Log processing start with alarm details
        logger.info(
            "Starting alarm processing",
            extra={
                **log_context,
                'alarm_name': alarm_data['alarmName'],
                'state_change': f"{alarm_data['previousState']['value']} -> {alarm_state['value']}",
                'evaluation_time': alarm_state['timestamp']
            }
        )

        # Initialize AWS clients and processor
        aws_clients = AWSClients.initialize()
        processor = AlarmProcessor(aws_clients, os.environ['SNS_TOPIC_ARN'])
        
        # Get dimensions directly from the metric configuration
        dimensions = alarm_config['metrics'][0]['metricStat']['metric']['dimensions']
        outpost_id = dimensions['OutpostId']
        instance_type = dimensions['InstanceType']
        
        # Parse the reasonData JSON string for additional details
        reason_data = json.loads(alarm_state['reasonData'])
        
        alarm_info = {
            'alarm_name': alarm_data['alarmName'],
            'description': alarm_config['description'],
            'state': alarm_state['value'],
            'reason': alarm_state['reason'],
            'timestamp': alarm_state['timestamp'],
            'previous_state': alarm_data['previousState']['value'],
            'previous_reason': alarm_data['previousState']['reason'],
            'current_value': reason_data['recentDatapoints'][0],
            'threshold': reason_data['threshold'],
            'metric_details': alarm_config['metrics'][0]['metricStat']['metric']
        }

        # Create monitor configuration
        config = MonitorConfig(
            outpost_id=outpost_id,
            m_value=1,  # Default value
            instance_family_resiliency_map={},
            process_alarm_lambda_arn=context.invoked_function_arn,
            sns_topic_arn=os.environ['SNS_TOPIC_ARN']
        )

        # Initialize monitor
        monitor = OutpostMonitor(aws_clients, config)

        # Verify threshold accuracy
        needs_update = not processor.verify_threshold(
            monitor,
            instance_type,
            reason_data['threshold']
        )

        # Generate and send report
        report = processor.generate_report(
            alarm_info,
            monitor,
            instance_type,
            needs_update
        )

        logger.info(
            "Generated alarm report",
            extra={
                **log_context,
                'alarm_name': alarm_data['alarmName'],
                'instance_type': instance_type,
                'outpost_id': outpost_id,
                'needs_update': needs_update
            }
        )

        # Determine the status for the subject
        status_indicator = "⚠️ PROBLEM" if alarm_state['value'] == 'ALARM' else "✅ RESOLVED"

        # Send report via SNS
        aws_clients.sns.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Subject=(
                f"{status_indicator} - Resiliency Alert - {instance_type} on {outpost_id} "
                f"[{alarm_state['value']}]"
            ),
            Message=report
        )

        response = {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Alarm processed successfully',
                'alarm_name': alarm_data['alarmName'],
                'state': alarm_state['value'],
                'needs_update': needs_update,
                'processing_time': alarm_state['timestamp']
            })
        }
        
        logger.info(
            "Completed alarm processing",
            extra={
                **log_context,
                'alarm_name': alarm_data['alarmName'],
                'status': 'success'
            }
        )
        
        return response

    except Exception as e:
        logger.error(
            "Error processing alarm",
            extra={
                **log_context,
                'error_type': type(e).__name__,
                'error_message': str(e)
            },
            exc_info=True
        )
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'error_type': type(e).__name__,
                'request_id': context.aws_request_id
            })
        }
