# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from enum import Enum

class HostState(Enum):
    ACTIVE = "ACTIVE"
    ISOLATED = "ISOLATED"
    RETIRING = "RETIRING"

class Status(Enum):
    GREEN = "GREEN"
    RED = "RED"

# CloudWatch Constants
CW_METRIC_NAMESPACE = "AWS/Outposts"
CW_METRIC_NAME = "UsedInstanceType_Count"
CW_EVALUATION_PERIOD = 1
CW_PERIOD = 300  # 5 minutes