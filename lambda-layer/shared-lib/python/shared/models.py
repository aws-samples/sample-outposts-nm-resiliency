# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from dataclasses import dataclass
from typing import Dict, List, Optional, Any, TypedDict
from enum import Enum

class Status(Enum):
    GREEN = "GREEN"
    RED = "RED"

    def __str__(self) -> str:
        return self.value

@dataclass
class HostImpact:
    asset_id: str
    impact_value: int
    vcpus: int

class AnalysisResult(TypedDict):
    status: str
    details: Optional[Dict[str, Any]]

@dataclass
class MonitorConfig:
    outpost_id: str
    m_value: int
    instance_family_resiliency_map: Dict[str, int]
    process_alarm_lambda_arn: str
    sns_topic_arn: str

@dataclass
class OutpostResult:
    outpost_id: str
    status: str
    details: Optional[Dict[str, Any]] = None
    analyzed_instances: Optional[int] = None
    results: Optional[Dict[str, Any]] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None