# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import logging
import os
from typing import Dict, Any, List, Optional
from dataclasses import replace

from shared.aws_clients import AWSClients
from shared.models import MonitorConfig, OutpostResult
from shared.monitor import OutpostMonitor
from shared.outpost_validator import OutpostValidator
from shared.utils.logging_utils import setup_logging, log_event
from shared.utils.cloudformation import update_monitoring_stack

logger = logging.getLogger()
setup_logging()

def parse_config(event: Dict[str, Any], outpost_id: str) -> MonitorConfig:
    """
    Parse event and create monitor configuration for a specific Outpost.
    
    Args:
        event: Lambda event containing configuration
        outpost_id: Specific Outpost ID to configure
        
    Returns:
        MonitorConfig for the specified Outpost
    """
    # Handle instance family map
    instance_family_map_str = event.get(
        'InstanceFamilyResiliencyMap',
        os.environ.get('INSTANCE_FAMILY_RESILIENCY_MAP', '{}')
    )
    if isinstance(instance_family_map_str, str):
        instance_family_map = json.loads(instance_family_map_str)
    else:
        instance_family_map = instance_family_map_str

    return MonitorConfig(
        outpost_id=outpost_id,
        m_value=event.get('M', int(os.environ.get('DEFAULT_M', 1))),
        instance_family_resiliency_map=instance_family_map,
        process_alarm_lambda_arn=event['ProcessAlarmLambdaArn'],
        sns_topic_arn=event['SNSTopicArn']
    )

def process_outpost(monitor: OutpostMonitor, outpost_id: str) -> OutpostResult:
    """Process a single outpost."""
    try:

        capacity_result = monitor.check_capacity_tasks()
        if not capacity_result['clear']:
            return OutpostResult(
                outpost_id=outpost_id,
                status='SKIPPED',
                details={
                    'reason': capacity_result['reason'],
                    'capacity_tasks': capacity_result.get('details', [])
                }
            )

        assets = monitor.get_assets()
        instance_types = monitor.get_instance_types()
        results = monitor.analyze_instance_types(instance_types, assets)
        
        monitor.process_and_report_results(results)
        
        return OutpostResult(
            outpost_id=outpost_id,
            status='SUCCESS',
            analyzed_instances=len(instance_types),
            results=results
        )

    except Exception as e:
        logger.error(f"Error processing outpost {outpost_id}: {str(e)}")
        return OutpostResult(
            outpost_id=outpost_id,
            status='ERROR',
            error_type=type(e).__name__,
            error_message=str(e)
        )

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda handler function."""
    try:
        log_event(event)
        
        # Initialize AWS clients
        aws_clients = AWSClients.initialize()
        
        results: List[OutpostResult] = []
        alarm_definitions: List[Dict[str, Any]] = []

        # Get list of Outpost IDs
        outpost_ids = event['OutpostIds']
        if isinstance(outpost_ids, str):
            outpost_ids = [outpost_ids]
        elif not isinstance(outpost_ids, list):
            outpost_ids = list(outpost_ids)

        # Process each Outpost
        for outpost_id in outpost_ids:
            try:
                # Create config for this specific Outpost
                config = parse_config(event, outpost_id)

                # Validate outpost first
                validation_result = OutpostValidator.validate(aws_clients, outpost_id)
                if not validation_result['valid']:
                    results.append(OutpostResult(
                        outpost_id=outpost_id,
                        status='SKIPPED',
                        details={'reason': validation_result['reason']}
                    ))
                    continue
                
                monitor = OutpostMonitor(
                    aws_clients=aws_clients,
                    config=config
                )
                
                result = process_outpost(monitor, outpost_id)
                results.append(result)
                
                if result.status == 'SUCCESS' and result.results:
                    alarm_definitions.extend(
                        monitor.get_alarm_definitions(result.results)
                    )

            except Exception as e:
                logger.error(f"Error processing outpost {outpost_id}: {str(e)}")
                results.append(OutpostResult(
                    outpost_id=outpost_id,
                    status='ERROR',
                    error_type=type(e).__name__,
                    error_message=str(e)
                ))

        # Update the nested Monitoring Stack
        monitoring_stack_arn = os.environ['MONITORING_STACK_ARN']
        logger.info(
            f"Updating monitoring stack: {monitoring_stack_arn} "
            f"with {len(alarm_definitions)} alarm definitions"
        )
        
        deployment_result = update_monitoring_stack(
            aws_clients.cfn,
            monitoring_stack_arn,
            alarm_definitions  # Will revert to baseline if empty
        )
        
        results.append(OutpostResult(
            outpost_id='MonitoringStack',
            status=deployment_result['status'],
            details=deployment_result
        ))

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Monitoring analysis completed',
                'results': [result.__dict__ for result in results]
            }, default=str)
        }

    except Exception as e:
        logger.error(f"Error in lambda execution: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'error_type': type(e).__name__
            }, default=str)
        }