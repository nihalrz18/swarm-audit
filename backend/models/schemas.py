from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    severity: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    owasp_category: str = ""
    raw_message: str = ""
    code_snippet: Optional[str] = None
    proof_of_concept: Optional[str] = None
    patch_diff: Optional[str] = None
    references: List[str] = []
    layer: str = "code"  # code | dependency | secret | api


class AttackChain(BaseModel):
    id: str
    name: str
    chain_steps: List[Dict[str, Any]]
    exploit_path: str
    risk_level: str
    cvss_overall: float
    business_impact_usd: float
    fix_sequence: List[str] = []


class BusinessRisk(BaseModel):
    total_risk_usd: float
    regulatory_fine_usd: float
    breach_cost_per_record_usd: float = 165.0
    affected_records_est: int
    fix_investment_hours: float
    roi_ratio: float
    risk_breakdown: Dict[str, float]


class AgentMessage(BaseModel):
    agent_name: str
    agent_type: str
    status: str   # thinking | working | done | error
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: float


class AuditRequest(BaseModel):
    github_url: str


class AuditSession(BaseModel):
    session_id: str
    github_url: str
    status: str
    vulnerabilities: List[Vulnerability] = []
    attack_chains: List[AttackChain] = []
    business_risk: Optional[BusinessRisk] = None
    report_ready: bool = False
