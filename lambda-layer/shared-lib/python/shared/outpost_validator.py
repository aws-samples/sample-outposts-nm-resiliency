# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from typing import Dict, Any
import logging
from botocore.exceptions import ClientError
from .aws_clients import AWSClients

logger = logging.getLogger(__name__)

class OutpostValidator:
    @staticmethod
    def validate(aws_clients: AWSClients, outpost_id: str) -> Dict[str, Any]:
        """
        Validate Outpost existence and status.
        
        Args:
            aws_clients: AWS clients instance
            outpost_id: ID of the outpost to validate
            
        Returns:
            Dict containing validation result and reason if invalid
        """
        try:
            response = aws_clients.outposts.get_outpost(OutpostId=outpost_id)
            outpost = response['Outpost']
            
            if outpost['LifeCycleStatus'] != 'ACTIVE':
                logger.warning(
                    f"Outpost {outpost_id} is not in ACTIVE state: {outpost['LifeCycleStatus']}"
                )
                return {
                    'valid': False,
                    'reason': f"Outpost {outpost_id} is not ACTIVE (status: {outpost['LifeCycleStatus']})"
                }
            
            if outpost['SupportedHardwareType'] != 'RACK':
                logger.warning(f"Outpost {outpost_id} is not a RACK type")
                return {
                    'valid': False,
                    'reason': f"Outpost {outpost_id} is not a RACK type"
                }
            
            logger.info(f"Successfully validated Outpost {outpost_id}")
            return {'valid': True}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'NotFoundException':
                logger.warning(f"Outpost {outpost_id} not found: {error_message}")
                return {
                    'valid': False,
                    'reason': f"Outpost {outpost_id} not found"
                }
            
            # For other ClientErrors, we still want to raise them
            logger.error(f"Error validating Outpost {outpost_id}: {str(e)}", exc_info=True)
            raise