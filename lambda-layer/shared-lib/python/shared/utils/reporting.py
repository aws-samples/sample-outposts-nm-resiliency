# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from typing import Dict, List, Any
from datetime import datetime
import logging
from botocore.exceptions import ClientError

from ..models import OutpostResult
from ..constants import Status

logger = logging.getLogger()

class ResiliencyReporter:
    def __init__(self, sns_client, sns_topic_arn: str):
        """
        Initialize ResiliencyReporter.
        
        Args:
            sns_client: AWS SNS client
            sns_topic_arn: ARN of SNS topic for sending reports
        """
        self.sns_client = sns_client
        self.sns_topic_arn = sns_topic_arn
        self.separator_main = "=" * 80
        self.separator_section = "-" * 80

    def _generate_family_level_issue(self, data: Dict[str, Any]) -> str:
        """
        Generate explanation for family-level issues.
        
        Args:
            data: Dictionary containing issue details from monitor:
                - resiliency_level: M value for the family
                - hosts_found: Number of hosts found
                - required_hosts: Number of hosts required (M + 1)
                - instance_family: Family being analyzed
                - is_family_level_issue: Boolean indicating family-level issue
        
        Returns:
            Formatted explanation string
        """
        try:
            m_value = data['resiliency_level']
            hosts_found = data['hosts_found']
            required_hosts = data['required_hosts']
            instance_family = data['instance_family']
            
            host_text = "host" if hosts_found == 1 else "hosts"
            
            return (
                f"Unable to meet resiliency requirement: The {instance_family} instance family has only {hosts_found} "
                f"available {host_text} in total, which is less than or equal to the desired "
                f"resiliency level (M={m_value}). This makes it impossible to achieve N+{m_value} resiliency for any "
                f"instance type in this family.\n\n"
                f"Note: CloudWatch alarms will not be created for instance types in this family as they would "
                f"all have a threshold of 0. To address this:\n"
                f"* Add more hosts that support the {instance_family} instance family, or\n"
                f"* Adjust the M value to better match your infrastructure capacity\n\n"
                f"This ensures meaningful monitoring of your Outpost's resiliency status."
            )
        except KeyError as e:
            logger.error(f"Missing required field in family-level issue data: {str(e)}")
            return "Error processing family-level issue data"
        except Exception as e:
            logger.error(f"Error generating family-level issue explanation: {str(e)}")
            return "Error generating family-level analysis"

    def _generate_instance_type_section(self, instance_type: str, issue: Dict[str, Any], m_value: int) -> str:
        """
        Generate report section for an instance type.
        
        Args:
            instance_type: The instance type being reported
            issue: Dictionary containing issue details
            m_value: The M value for N+M resiliency
            
        Returns:
            Formatted string containing instance type analysis
        """
        try:
            reason = issue.get('reason', '')
            
            # Handle family-level issues
            if reason == 'insufficient_family_hosts':
                # This case is handled by _generate_family_level_issue
                return ""

            # Handle instance-specific issues
            if reason == 'insufficient_hosts':
                hosts_found = issue.get('hosts_found', 0)
                host_text = "host" if m_value == 1 else "hosts"
                host_text_found = "host" if hosts_found == 1 else "hosts"
                return f"""

• {instance_type}:
  - Issue: Unable to meet resiliency requirement: To withstand {m_value} {host_text} failure, {instance_type} instances need to be able to run on at least {m_value + 1} hosts. Currently slots for this instance type are configured on {hosts_found} {host_text_found}."""

            elif reason == 'exceeds_threshold':
                current = issue['current_usage']
                threshold = issue['threshold']
                instances_at_risk = current - threshold
                host_text = "host" if m_value == 1 else "hosts"

                section = f"""

• {instance_type}:
  - Issue: Current usage ({current}) exceeds threshold ({threshold}). If {m_value} {host_text} with the highest impact for this instance type {instance_type} were to fail, there wouldn't be enough capacity to accommodate all running instances of type {instance_type}.
  - Current Running Instances: {current}
  - Maximum Allowed for N+{m_value}: {threshold}
  - Impact Assessment for Top {m_value} {host_text} Failure:"""

                if 'impact_hosts' in issue:
                    section += f"""
    This analysis considers the failure of the {m_value} {host_text} with highest impact on the capacity for {instance_type} instances:"""
                    for host in issue['impact_hosts']:
                        section += f"""
    * Asset ID: {host['asset_id']} (Impact: {host['impact']} slots)"""
                    
                    section += f"""
    In case of failure, {instances_at_risk} {instance_type} instance{'s' if instances_at_risk != 1 else ''} would remain without capacity"""
                return section

            elif reason == 'zero_m_value':
                return f"""

• {instance_type}:
  - Status: Compliant (M=0)"""

            elif reason == 'compliant':
                return f"""

• {instance_type}:
  - Status: Meets N+{m_value} resiliency requirements"""

            # Fallback for any unexpected cases
            return f"""

• {instance_type}:
  - Issue: {issue.get('reason', 'Unknown issue')}"""

        except Exception as e:
            logger.error(f"Error generating instance type section for {instance_type}: {str(e)}")
            return f"\n\n• {instance_type}: Error generating analysis"

    def _get_vcpu_explanation(self, vcpu_metrics: Dict[str, Any], outpost_id: str, m_value: int) -> str:
        """Generate explanatory text for vCPU analysis."""
        try:
            total_vcpus = vcpu_metrics['n_hosts_family_total_vcpus']
            free_vcpus = total_vcpus - vcpu_metrics['hosts_used_vcpus']
            impact_vcpus = vcpu_metrics['m_hosts_max_impact_vcpus']
            can_mitigate = vcpu_metrics.get('can_mitigate', False)
            host_text = "host" if m_value == 1 else "hosts"

            if can_mitigate:
                return (
                    f"The Outpost {outpost_id} has sufficient vCPU capacity to maintain N+{m_value} resiliency:\n"
                    f"• The Free vCPUs ({free_vcpus}) exceed the Potential vCPU loss from {m_value} {host_text} failure ({impact_vcpus}), "
                    f"indicating that workload redistribution may be possible through different slot configurations."
                )
            
            return (
                f"The Outpost {outpost_id} lacks sufficient vCPU capacity to maintain N+{m_value} resiliency:\n"
                f"• Available capacity is insufficient to handle {m_value} {host_text} failure:\n"
                f"  - Free vCPUs ({free_vcpus})\n"
                f"  - Potential vCPU loss from {m_value} {host_text} failure ({impact_vcpus})"
            )
        except KeyError as e:
            logger.error(f"Missing required metric in vCPU data: {str(e)}")
            return "Error processing vCPU metrics data"
        except Exception as e:
            logger.error(f"Error generating vCPU explanation: {str(e)}")
            return "Error generating vCPU analysis"

    def _get_mitigation_steps(self, vcpu_metrics: Dict[str, Any], m_value: int) -> str:
        """Generate mitigation steps for vCPU capacity constraints."""
        try:
            total_vcpus = vcpu_metrics['n_hosts_family_total_vcpus']
            free_vcpus = total_vcpus - vcpu_metrics['hosts_used_vcpus']
            impact_vcpus = vcpu_metrics['m_hosts_max_impact_vcpus']
            vcpus_to_free = impact_vcpus - free_vcpus if impact_vcpus > free_vcpus else 0

            return (
                f"To address the vCPU capacity constraint (one of the requirements for N+{m_value} resiliency), "
                f"consider one of these options:\n"
                f"• Add additional capacity to the Outpost, or\n"
                f"• Reduce the current workload by {vcpus_to_free} vCPUs."
            )
        except Exception as e:
            logger.error(f"Error generating mitigation steps: {str(e)}")
            return "Error generating mitigation steps"

    def _generate_instance_level_issues(self, family: str, data: Dict[str, Any], outpost_id: str) -> str:
        """
        Generate report section for instance-level issues.
        
        Args:
            family: Instance family being analyzed
            data: Dictionary containing family analysis data including:
                - m_value: Family's M value
                - vcpu_metrics: Dictionary containing:
                    - n_hosts_family_total_vcpus: Total vCPU capacity
                    - hosts_used_vcpus: Currently used vCPUs
                    - m_hosts_max_impact_vcpus: vCPUs that would be lost from M hosts
                    - can_mitigate: Whether redistribution is possible
                    - hosts_family_count: Number of active hosts
                - red_instance_types: Dictionary of instance types with issues
            outpost_id: The Outpost ID
        """
        try:
            m_value = data['m_value']
            vcpu = data.get('vcpu_metrics', {})
            
            if not vcpu:
                logger.error(f"No vCPU metrics found for family {family}")
                return "\nError: Missing vCPU metrics data"

            can_mitigate = vcpu.get('can_mitigate', False)
            total_vcpus = vcpu['n_hosts_family_total_vcpus']
            used_vcpus = vcpu['hosts_used_vcpus']
            free_vcpus = total_vcpus - used_vcpus
            hosts_family = vcpu.get('hosts_family_count', 0)
            host_text = "host" if m_value == 1 else "hosts"
            
            section = f"""

--------------------------------------------------------------------------------
                            Instance Type Issues
--------------------------------------------------------------------------------"""
            
            # Sort instance types for consistent output
            for itype in sorted(data.get('red_instance_types', {})):
                section += self._generate_instance_type_section(
                    itype, 
                    data['red_instance_types'][itype], 
                    m_value
                )

            # Add note about vCPU analysis if there are instance type issues
            if data.get('red_instance_types'):
                section += f"""

Note: Review the vCPU Capacity Analysis below to understand if there is sufficient physical capacity 
      to address these instance type issues through alternative slot configurations."""

            section += f"""

--------------------------------------------------------------------------------
                            vCPU Capacity Analysis
--------------------------------------------------------------------------------
Note: The vCPU Capacity Analysis below is including the hosts in any state (ACTIVE|ISOLATED|RETIRING)

• Total Hosts: {hosts_family}
• Total vCPU Capacity: {total_vcpus}
• Currently Used vCPUs: {used_vcpus}
• Free vCPUs: {free_vcpus}
• vCPU Capacity of Top {m_value} Hosts: {vcpu['m_hosts_max_impact_vcpus']}

Resiliency Assessment:
• Re-slotting Solution: {'[✓] Possible' if can_mitigate else '[✗] Not Possible'}"""

            if not can_mitigate:
                section += f"""
• Note: Based on the vCPUs analysis, the instance type risks cannot be mitigated through alternative slot configurations as there is insufficient physical capacity (vCPUs) to redistribute the running workload in case of {m_value} {host_text} failure."""

            section += f"""

Analysis Explanation:
{self._get_vcpu_explanation(vcpu, outpost_id, m_value)}

Possible Mitigations:
{self._get_mitigation_steps(vcpu, m_value) if not can_mitigate else '• No vCPU capacity constraints identified.\n• Consider exploring alternative slot configurations across the available hosts to address the instance type risks\n  while maintaining the current running workload.'}"""
            
            return section

        except KeyError as e:
            logger.error(f"Missing required data for family {family}: {str(e)}")
            return "\nError processing instance level data"
        except Exception as e:
            logger.error(f"Error generating instance level issues for family {family}: {str(e)}")
            return "\nError generating instance level analysis"

    def _generate_family_report_section(self, family: str, data: Dict[str, Any], outpost_id: str) -> str:
        """Generate report section for an instance family."""
        try:
            m_value = data['m_value']
            status_emoji = "✅" if data['status'] == 'GREEN' else "❌"
            
            report_section = f"""
{self.separator_main}
{status_emoji} Instance Family: {family.upper()} (M={m_value})
{self.separator_main}"""

            if data['status'] == 'RED':
                # Check if any instance type has a family-level issue
                has_family_level_issue = any(
                    details.get('is_family_level_issue', False)
                    for details in data['red_instance_types'].values()
                )
                
                if has_family_level_issue:
                    # Get the details from the first instance type with family-level issue
                    for instance_details in data['red_instance_types'].values():
                        if instance_details.get('is_family_level_issue'):
                            report_section += f"\n{self._generate_family_level_issue(instance_details)}\n"
                            break
                else:
                    report_section += self._generate_instance_level_issues(family, data, outpost_id)
            else:
                # Add appropriate message based on M value
                if m_value == 0:
                    report_section += "\nThis instance family is configured with M=0, indicating that monitoring of host failure resilience is not required\n"
                else:
                    report_section += f"\nThis instance family meets all the N+M resiliency requirements for M={m_value}\n"

            # Add extra newline at the end for spacing between families
            report_section += "\n"
            return report_section

        except KeyError as e:
            logger.error(f"Missing required data for family {family}: {str(e)}")
            return f"\n{self.separator_main}\n❌ Instance Family: {family.upper()}\nError processing family data\n"
        except Exception as e:
            logger.error(f"Error generating family report section for {family}: {str(e)}")
            return f"\n{self.separator_main}\n❌ Instance Family: {family.upper()}\nError generating family analysis\n"

    def _generate_report_header(self, outpost_id: str) -> str:
        """Generate the report header section."""
        return f"""{self.separator_main}
                            Outpost N+M Resiliency Report
{self.separator_main}
Outpost ID: {outpost_id}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
{self.separator_main}
"""

    def generate_report(self, outpost_id: str, results: Dict[str, Any]) -> str:
        """
        Generate the complete monitoring report.
        
        Args:
            outpost_id: The Outpost ID
            results: Dictionary containing all analysis results
            
        Returns:
            Complete formatted report as string
        """
        try:
            # Generate header section
            report_sections = [self._generate_report_header(outpost_id)]
            
            # Generate family summaries
            family_lines = []
            sorted_families = sorted(results.get('instance_families', {}).keys())
            
            for family in sorted_families:
                try:
                    data = results['instance_families'][family]
                    family_lines.append(self._format_status_summary(family, data))
                except Exception as e:
                    logger.error(f"Error processing family {family} for summary: {str(e)}")
                    family_lines.append(f"❌ | {family.upper():6} [Error processing family data]")

            report_sections.append('\n'.join(family_lines))
            
            # Generate detailed analysis section
            report_sections.append("\nDetailed Analysis by Family\n")
            
            # Add detailed analysis for each family
            for family in sorted_families:
                try:
                    data = results['instance_families'][family]
                    report_sections.append(
                        self._generate_family_report_section(family, data, outpost_id)
                    )
                except Exception as e:
                    logger.error(f"Error generating detailed analysis for family {family}: {str(e)}")
                    report_sections.append(
                        f"\n{self.separator_section}\n"
                        f"Instance Family: {family.upper()}\n"
                        f"Error generating detailed analysis\n"
                    )

            # Add final separator
            report_sections.append(f"\n{self.separator_main}\n")
            
            return '\n'.join(report_sections)

        except Exception as e:
            logger.error(f"Error generating report for Outpost {outpost_id}: {str(e)}")
            return self._generate_error_report(outpost_id, e)

    def _generate_error_report(self, outpost_id: str, error: Exception) -> str:
        """Generate an error report when the main report generation fails."""
        return f"""
{self.separator_main}
                            Outpost N+M Resiliency Report
{self.separator_main}
ERROR: Unable to generate report. Please check logs for details.
Outpost ID: {outpost_id}
Error message: {str(error)}
{self.separator_main}
"""

    def send_report(self, outpost_id: str, results: Dict[str, Any]) -> None:
        """
        Generate and send the monitoring report via SNS.
        
        Args:
            outpost_id: The Outpost ID
            results: Dictionary containing all analysis results
            
        Raises:
            ClientError: If there's an error sending the message via SNS
        """
        try:
            report_text = self.generate_report(outpost_id, results)
            
            self.sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=f"Outpost {outpost_id} N+M Resiliency Report",
                Message=report_text
            )
            
            logger.info(f"Successfully sent monitoring report for Outpost {outpost_id}")
            
        except ClientError as e:
            logger.error(f"Error sending SNS report for Outpost {outpost_id}: {str(e)}")
            raise

    def _format_status_summary(self, family: str, data: Dict[str, Any]) -> str:
        """
        Format the status summary line for a family in the overview section.
        
        Args:
            family: Instance family name
            data: Family analysis data
            
        Returns:
            Formatted status summary line
        """
        try:
            # If M=0, everything is automatically green
            if data['m_value'] == 0:
                return f"✅ | {family.upper():6} [M=0] - vCPUs: [✓] - Instance Types: [✓]"

            # Check if there are any instance type issues
            has_instance_issues = bool(data.get('red_instance_types'))
            
            # Only check vCPU status if there are instance type issues
            if has_instance_issues:
                vcpu_status = '[✓]' if data.get('vcpu_metrics', {}).get('can_mitigate', False) else '[✗]'
                vcpu_detail = f"vCPUs: {vcpu_status}"
                family_status = '[✗]'
                overall_status = '❌'
                
                # Add instance types with issues
                red_instances = sorted(data['red_instance_types'].keys())
                instance_types = [f"{it.split('.')[-1]}:✗" for it in red_instances]
                instance_types_detail = f" Issues with: ({', '.join(instance_types)})"
            else:
                vcpu_detail = "vCPUs: [✓]"
                family_status = '[✓]'
                overall_status = '✅'
                instance_types_detail = ""

            return f"{overall_status} | {family.upper():6} [M={data['m_value']}] - {vcpu_detail} - Instance Types: {family_status}{instance_types_detail}"

        except Exception as e:
            logger.error(f"Error formatting status summary for family {family}: {str(e)}")
            return f"❌ | {family.upper():6} [Error formatting status]"