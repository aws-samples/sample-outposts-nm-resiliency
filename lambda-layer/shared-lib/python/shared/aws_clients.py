# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
from dataclasses import dataclass
from typing import Optional

@dataclass
class AWSClients:
    outposts: boto3.client
    cloudwatch: boto3.client
    sns: boto3.client
    cfn: boto3.client
    sts: boto3.client
    region: str
    account_id: str

    @classmethod
    def initialize(cls) -> 'AWSClients':
        """Initialize all AWS clients and get account/region info."""
        session = boto3.session.Session()
        region = session.region_name
        
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        return cls(
            outposts=boto3.client('outposts'),
            cloudwatch=boto3.client('cloudwatch'),
            sns=boto3.client('sns'),
            cfn=boto3.client('cloudformation'),
            sts=sts,
            region=region,
            account_id=account_id
        )
