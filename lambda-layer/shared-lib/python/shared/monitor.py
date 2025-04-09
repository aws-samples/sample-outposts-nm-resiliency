# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import json
from typing import Dict, List, Any, Set, Optional
from datetime import datetime
from zoneinfo import ZoneInfo
from botocore.exceptions import ClientError
from collections import defaultdict

from .models import HostImpact, AnalysisResult, MonitorConfig
from .constants import (
    HostState, 
    Status, 
    CW_METRIC_NAMESPACE, 
    CW_PERIOD, 
    CW_EVALUATION_PERIOD
)
from .utils.reporting import ResiliencyReporter
from .utils.logging_utils import setup_logging
from .aws_clients import AWSClients
from .outpost_validator import OutpostValidator

logger = logging.getLogger()
setup_logging()

class OutpostMonitor:
    def __init__(self, aws_clients: AWSClients, config: MonitorConfig):
        """
        Initialize OutpostMonitor with AWS clients and configuration.
        
        Args:
            aws_clients: Initialized AWS clients
            config: Monitor configuration
        """
        self.clients = aws_clients
        self.config = config
        self.timezone = ZoneInfo('UTC')
        self.instance_type_vcpus = self._initialize_instance_type_vcpus()
        self.reporter = ResiliencyReporter(aws_clients.sns, config.sns_topic_arn)

    def _initialize_instance_type_vcpus(self) -> Dict[str, int]:
        """Initialize mapping of instance types to their vCPU count."""
        vcpu_map = {}
        try:
            paginator = self.clients.outposts.get_paginator('get_outpost_instance_types')
            for page in paginator.paginate(OutpostId=self.config.outpost_id):
                for instance_info in page.get('InstanceTypes', []):
                    vcpu_map[instance_info['InstanceType']] = instance_info['VCPUs']
            
            logger.debug(f"Initialized vCPU mapping for Outpost {self.config.outpost_id}: {json.dumps(vcpu_map, default=str)}")
            return vcpu_map
            
        except ClientError as e:
            logger.error(f"Error getting instance type vCPUs: {str(e)}", exc_info=True)
            raise

    def check_capacity_tasks(self) -> Dict[str, Any]:
        """Check for any running capacity tasks on the Outpost."""
        try:
            paginator = self.clients.outposts.get_paginator('list_capacity_tasks')
            
            for page in paginator.paginate(OutpostIdentifierFilter=self.config.outpost_id):
                tasks = page.get('Tasks', [])
                if tasks:
                    task_info = [
                        f"Task ID: {task.get('TaskId', 'Unknown')}, Status: {task.get('Status', 'Unknown')}"
                        for task in tasks
                    ]
                    logger.warning(
                        f"Found running capacity tasks on Outpost {self.config.outpost_id}: "
                        f"{json.dumps(task_info, default=str)}"
                    )
                    return {
                        'clear': False,
                        'reason': f"Found running capacity tasks on Outpost {self.config.outpost_id}",
                        'details': task_info
                    }
            
            logger.info(f"No running capacity tasks found for Outpost {self.config.outpost_id}")
            return {'clear': True}
            
        except ClientError as e:
            logger.error(f"Error checking capacity tasks: {str(e)}", exc_info=True)
            raise

    def get_assets(self) -> List[Dict[str, Any]]:
        """Get all assets for the Outpost."""
        try:
            assets = []
            paginator = self.clients.outposts.get_paginator('list_assets')
            for page in paginator.paginate(OutpostIdentifier=self.config.outpost_id):
                assets.extend(page.get('Assets', []))
            
            logger.info(f"Retrieved {len(assets)} assets for Outpost {self.config.outpost_id}")
            return assets
            
        except ClientError as e:
            logger.error(f"Error getting assets: {str(e)}", exc_info=True)
            raise

    def get_instance_types(self) -> Set[str]:
        """Get all available instance types on the Outpost."""
        try:
            instance_types = set()
            paginator = self.clients.outposts.get_paginator('get_outpost_instance_types')
            
            for page in paginator.paginate(OutpostId=self.config.outpost_id):
                for instance_type in page.get('InstanceTypes', []):
                    instance_types.add(instance_type['InstanceType'])
            
            logger.info(f"Found instance types for Outpost {self.config.outpost_id}: {instance_types}")
            return instance_types
            
        except ClientError as e:
            logger.error(f"Error getting instance types: {str(e)}", exc_info=True)
            raise

    def _get_m_value_for_family(self, instance_family: str) -> int:
        """Get the M value for a specific instance family."""
        return self.config.instance_family_resiliency_map.get(
            instance_family, 
            self.config.m_value
        )

    def _get_hosts_for_family(self, instance_family: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get all hosts that support this instance family."""
        hosts = []
        for asset in assets:
            if asset.get('AssetType') != 'COMPUTE':
                continue
                
            compute_attrs = asset.get('ComputeAttributes', {})

            # Case-insensitive comparison for instance families
            asset_families = [f.lower() for f in compute_attrs.get('InstanceFamilies', [])]
            if instance_family.lower() in asset_families:
                hosts.append(asset)
                logger.debug(
                    f"Found host {asset.get('AssetId')} supporting family {instance_family} "
                    f"(supported families: {compute_attrs.get('InstanceFamilies', [])})"
                )

        logger.info(
            f"Found {len(hosts)} active hosts supporting instance family {instance_family}"
        )
        return hosts
    
    def _get_slots_for_instance_type(self, asset: Dict[str, Any], instance_type: str) -> int:
        """
        Get available slots for an instance type on a host.
        
        Args:
            asset: Host asset information
            instance_type: Instance type to check
            
        Returns:
            Number of available slots for the instance type
        """
        try:
            compute_attrs = asset.get('ComputeAttributes', {})
            instance_type_capacities = compute_attrs.get('InstanceTypeCapacities', [])
            
            for capacity in instance_type_capacities:
                if capacity['InstanceType'] == instance_type:
                    return capacity['Count']
            
            logger.debug(f"No slots found for {instance_type} on host {asset.get('AssetId', 'Unknown')}")
            return 0
            
        except Exception as e:
            logger.error(f"Error getting slots for host {asset.get('AssetId', 'Unknown')}: {str(e)}")
            return 0

    def _get_current_instance_usage(self, instance_type: str) -> int:
        """
        Get current number of running instances of a specific type.
        
        Args:
            instance_type: Instance type to check
            
        Returns:
            Number of running instances of the specified type
        """
        try:
            instance_count = 0
            paginator = self.clients.outposts.get_paginator('list_asset_instances')
            
            for page in paginator.paginate(
                OutpostIdentifier=self.config.outpost_id,
                InstanceTypeFilter=[instance_type]
            ):
                instance_count += len(page.get('AssetInstances', []))
            
            logger.info(f"Found {instance_count} running instances of type {instance_type}")
            return instance_count
            
        except ClientError as e:
            logger.error(f"Error getting instance usage for type {instance_type}: {str(e)}", exc_info=True)
            raise

    def _calculate_vcpu_metrics(self, instance_family: str, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate vCPU metrics for an instance family."""
        try:
            # Get all the hosts for this family
            hosts_family = []
            for asset in assets:
                compute_attrs = asset.get('ComputeAttributes', {})
                asset_families = compute_attrs.get('InstanceFamilies', [])
                
                if (asset.get('AssetType') == 'COMPUTE' and
                    instance_family.lower() in [f.lower() for f in asset_families]):
                    hosts_family.append(asset)
                    logger.debug(f"Found active host {asset.get('AssetId')} for family {instance_family}")

            n_hosts_family_total_vcpus = sum(
                asset.get('ComputeAttributes', {}).get('MaxVcpus', 0)
                for asset in hosts_family
            )

            family_instance_types = [
                itype for itype in self.instance_type_vcpus.keys()
                if itype.startswith(f"{instance_family}.")
            ]

            hosts_used_vcpus = 0
            for instance_type in family_instance_types:
                instance_count = self._get_current_instance_usage(instance_type)
                vcpus_per_instance = self.instance_type_vcpus.get(instance_type, 0)
                hosts_used_vcpus += instance_count * vcpus_per_instance
                logger.debug(
                    f"Instance type {instance_type}: {instance_count} instances "
                    f"using {vcpus_per_instance} vCPUs each"
                )

            sorted_hosts = sorted(
                hosts_family,
                key=lambda x: x.get('ComputeAttributes', {}).get('MaxVcpus', 0),
                reverse=True
            )
            
            m_value = self._get_m_value_for_family(instance_family)
            m_hosts_max_impact_vcpus = sum(
                host.get('ComputeAttributes', {}).get('MaxVcpus', 0)
                for host in sorted_hosts[:m_value]
            )

            metrics = {
                'n_hosts_family_total_vcpus': n_hosts_family_total_vcpus,
                'hosts_used_vcpus': hosts_used_vcpus,
                'm_hosts_max_impact_vcpus': m_hosts_max_impact_vcpus,
                'can_mitigate': hosts_used_vcpus <= (n_hosts_family_total_vcpus - m_hosts_max_impact_vcpus),
                'hosts_family_count': len(hosts_family)
            }

            logger.info(
                f"vCPU metrics for family {instance_family}: {json.dumps(metrics, default=str)}"
            )
            return metrics

        except Exception as e:
            logger.error(f"Error calculating vCPU metrics: {str(e)}", exc_info=True)
            raise

    def _calculate_host_impacts(self, assets: List[Dict[str, Any]], instance_type: str) -> List[HostImpact]:
        """Calculate the impact of each host for a specific instance type."""
        host_impacts: List[HostImpact] = []
        
        for asset in assets:
            try:
                asset_id = asset.get('AssetId')
                if not asset_id:
                    logger.warning("Skipping asset with no AssetId")
                    continue

                compute_attrs = asset.get('ComputeAttributes', {})
                if not compute_attrs:
                    logger.debug(f"Asset {asset_id} has no ComputeAttributes, skipping")
                    continue

                state_str = compute_attrs.get('State')
                if not state_str:
                    logger.warning(f"Asset {asset_id} has no State field in ComputeAttributes, skipping")
                    continue

                try:
                    state = HostState[state_str.upper()]
                except KeyError:
                    logger.warning(f"Asset {asset_id} has invalid state: {state_str}, skipping")
                    continue

                vcpus = compute_attrs.get('MaxVcpus', 0)
                
                if state == HostState.ACTIVE:
                    slots = self._get_slots_for_instance_type(asset, instance_type)
                    if slots > 0:
                        host_impacts.append(HostImpact(
                            asset_id=asset_id,
                            impact_value=slots,
                            vcpus=vcpus
                        ))
                        logger.debug(f"Added ACTIVE host impact for {asset_id}: {slots} slots")
                        
                elif state in (HostState.ISOLATED, HostState.RETIRING):
                    running_instances = self._get_running_instances_count(asset_id, instance_type)
                    if running_instances > 0:
                        host_impacts.append(HostImpact(
                            asset_id=asset_id,
                            impact_value=running_instances,
                            vcpus=vcpus
                        ))
                        logger.debug(f"Added {state.value} host impact for {asset_id}: {running_instances} instances")

            except Exception as e:
                logger.error(f"Error processing asset {asset.get('AssetId', 'Unknown')}: {str(e)}", exc_info=True)
                continue
                    
        logger.info(f"Calculated impacts for {len(host_impacts)} hosts for instance type {instance_type}")
        return host_impacts

    def _create_alarm_definition(self, instance_type: str, threshold: int) -> Dict[str, Any]:
        """Create CloudWatch alarm definition."""
        alarm_name = f"OutpostResiliency-{self.config.outpost_id}-{instance_type}"
        
        alarm_def = {
            "name": f"Alarm{instance_type.replace('.', '')}",
            "definition": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "AlarmDescription": (
                        f"Monitors N+M resiliency for {instance_type} instances on "
                        f"Outpost {self.config.outpost_id}"
                    ),
                    "MetricName": "UsedInstanceType_Count",
                    "Namespace": CW_METRIC_NAMESPACE,
                    "Statistic": "Maximum",
                    "Period": CW_PERIOD,
                    "EvaluationPeriods": CW_EVALUATION_PERIOD,
                    "Threshold": threshold,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "Dimensions": [
                        {"Name": "OutpostId", "Value": self.config.outpost_id},
                        {"Name": "InstanceType", "Value": instance_type}
                    ],
                    "AlarmActions": [self.config.process_alarm_lambda_arn],
                    "OKActions": [self.config.process_alarm_lambda_arn],
                    "TreatMissingData": "ignore"
                }
            }
        }
        
        logger.debug(f"Created alarm definition for {instance_type}: {json.dumps(alarm_def, default=str)}")
        return alarm_def

    def _check_family_capacity(self, instance_family: str, assets: List[Dict[str, Any]]) -> Optional[AnalysisResult]:
        """Check if family has enough hosts for resiliency requirements."""
        m_value = self._get_m_value_for_family(instance_family)
        if m_value == 0:
            logger.debug(f"Skipping family capacity check for {instance_family} (m_value=0)")
            return None

        family_hosts = self._get_hosts_for_family(instance_family, assets)
        
        if len(family_hosts) <= m_value:
            logger.warning(
                f"Family {instance_family} has insufficient hosts: "
                f"found {len(family_hosts)}, need at least {m_value + 1}"
            )
            return AnalysisResult(
                status=Status.RED.value,
                details={
                    'reason': 'insufficient_family_hosts',
                    'hosts_found': len(family_hosts),
                    'required_hosts': m_value + 1,
                    'resiliency_level': m_value,
                    'instance_family': instance_family,
                    'is_family_level_issue': True
                }
            )
        return None

    def analyze_instance_type(self, instance_type: str, assets: List[Dict[str, Any]]) -> AnalysisResult:
        """Analyze resiliency for a specific instance type."""
        try:
            logger.info(f"Starting analysis for instance type {instance_type}")
            instance_family = instance_type.split('.')[0]
            m_value = self._get_m_value_for_family(instance_family)
            
            if m_value == 0:
                logger.info(f"Instance type {instance_type} has m_value=0, marking as GREEN")
                return AnalysisResult(
                    status=Status.GREEN.value,
                    details={
                        'reason': 'zero_m_value',
                        'instance_family': instance_family
                    }
                )

            # First check family-level capacity
            family_check = self._check_family_capacity(instance_family, assets)
            if family_check is not None:
                return family_check

            # Calculate host impacts
            host_impacts = self._calculate_host_impacts(assets, instance_type)

            # Check if we have enough hosts
            if len(host_impacts) <= m_value:
                alarm_definition = self._create_alarm_definition(instance_type, 0)
                return AnalysisResult(
                    status=Status.RED.value,
                    details={
                        'reason': 'insufficient_hosts',
                        'hosts_found': len(host_impacts),
                        'required_hosts': m_value + 1,
                        'resiliency_level': m_value,
                        'alarm_definition': alarm_definition
                    }
                )

            # Calculate capacity and threshold
            sorted_impacts = sorted(host_impacts, key=lambda x: x.impact_value, reverse=True)
            m_hosts_impact_max = sum(h.impact_value for h in sorted_impacts[:m_value])
            n_hosts_total_capacity = sum(h.impact_value for h in host_impacts)
            threshold = n_hosts_total_capacity - m_hosts_impact_max

            current_usage = self._get_current_instance_usage(instance_type)
            alarm_definition = self._create_alarm_definition(instance_type, threshold)

            logger.info(
                f"Analysis metrics for {instance_type}: "
                f"current_usage={current_usage}, threshold={threshold}"
            )

            if current_usage > threshold:
                logger.warning(
                    f"Instance type {instance_type} exceeds threshold: "
                    f"usage={current_usage}, threshold={threshold}"
                )
                return AnalysisResult(
                    status=Status.RED.value,
                    details={
                        'reason': 'exceeds_threshold',
                        'threshold': threshold,
                        'current_usage': current_usage,
                        'impact_hosts': [
                            {'asset_id': h.asset_id, 'impact': h.impact_value}
                            for h in sorted_impacts[:m_value]
                        ],
                        'hosts_found': len(host_impacts),
                        'alarm_definition': alarm_definition
                    }
                )
            
            logger.info(f"Instance type {instance_type} meets resiliency requirements")
            return AnalysisResult(
                status=Status.GREEN.value,
                details={
                    'reason': 'compliant',
                    'threshold': threshold,
                    'current_usage': current_usage,
                    'hosts_found': len(host_impacts),
                    'alarm_definition': alarm_definition
                }
            )

        except Exception as e:
            logger.error(f"Error analyzing instance type {instance_type}: {str(e)}", exc_info=True)
            raise

    def analyze_instance_types(self, instance_types: Set[str], assets: List[Dict[str, Any]]) -> Dict[str, AnalysisResult]:
        """
        Analyze all instance types and return results.
        
        Args:
            instance_types: Set of instance types to analyze
            assets: List of Outpost assets
            
        Returns:
            Dictionary mapping instance types to their analysis results
        """
        logger.info(f"Starting analysis for {len(instance_types)} instance types")
        results = {}
        
        for instance_type in instance_types:
            try:
                logger.debug(f"Analyzing instance type: {instance_type}")
                result = self.analyze_instance_type(instance_type, assets)
                
                # Ensure the status is a string
                if isinstance(result['status'], Status):
                    result['status'] = result['status'].value
                
                results[instance_type] = result
                logger.info(f"Analysis result for {instance_type}: Status={result['status']}")
                
            except Exception as e:
                logger.error(f"Error analyzing {instance_type}: {str(e)}", exc_info=True)
                results[instance_type] = AnalysisResult(
                    status=Status.RED.value,
                    details={
                        'error': str(e),
                        'error_type': type(e).__name__
                    }
                )
        
        logger.info(f"Completed analysis of {len(instance_types)} instance types")
        return results

    def process_and_report_results(self, analysis_results: Dict[str, AnalysisResult]) -> None:
        """Process analysis results and send report."""
        try:
            logger.info("Starting to process analysis results")
            # Group results by instance family
            family_results = defaultdict(dict)
            
            # First pass: organize results by family
            for instance_type, result in analysis_results.items():
                family = instance_type.split('.')[0]
                
                # Initialize family if not already done
                if family not in family_results:
                    family_results[family] = {
                        'status': 'GREEN',
                        'm_value': self._get_m_value_for_family(family),
                        'red_instance_types': {}
                    }
                    logger.debug(f"Initialized family {family} with m_value={family_results[family]['m_value']}")

                # If any instance type is RED, mark the family as RED
                if result['status'] == Status.RED.value:
                    family_results[family]['status'] = 'RED'
                    family_results[family]['red_instance_types'][instance_type] = result['details']
                    logger.info(f"Marked family {family} as RED due to instance type {instance_type}")

            # Second pass: add vCPU metrics for RED families
            logger.debug("Calculating vCPU metrics for RED families")
            for family, data in family_results.items():
                if data['m_value'] == 0:
                    data['status'] = 'GREEN'
                    logger.info(f"Family {family} marked GREEN due to m_value=0")
                    continue
                    
                if data['status'] == 'RED':
                    vcpu_metrics = self._calculate_vcpu_metrics(family, self.get_assets())
                    data['vcpu_metrics'] = vcpu_metrics
                    logger.info(
                        f"Added vCPU metrics for RED family {family}: "
                        f"{json.dumps(vcpu_metrics, default=str)}"
                    )

            report_data = {
                'instance_families': family_results
            }

            logger.info(f"Sending report for Outpost {self.config.outpost_id}")
            self.reporter.send_report(self.config.outpost_id, report_data)
            
        except Exception as e:
            logger.error(f"Error processing and reporting results: {str(e)}", exc_info=True)
            raise

    def get_alarm_definitions(self, analysis_results: Dict[str, AnalysisResult]) -> List[Dict[str, Any]]:
        """Extract alarm definitions from analysis results."""
        alarm_definitions = []
        for instance_type, result in analysis_results.items():
            if 'alarm_definition' in result.get('details', {}):
                alarm_definitions.append(result['details']['alarm_definition'])
                logger.debug(f"Added alarm definition for {instance_type}")
        
        logger.info(f"Extracted {len(alarm_definitions)} alarm definitions")
        return alarm_definitions