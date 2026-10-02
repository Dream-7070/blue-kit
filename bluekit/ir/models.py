import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

@dataclass
class AttackStage:
    stage_id: str
    timestamp: str
    host: str
    phase: str
    technique_id: str
    technique_name: str
    confidence: str = "HIGH"
    status: str = "CONFIRMED"  # CONFIRMED, PARTIALLY_CONFIRMED, SUSPECTED
    evidence: str = ""
    explain_uz: str = ""
    iocs: Dict[str, Any] = field(default_factory=dict)
    source_dataset: str = ""
    raw_event_id: str = ""
    timestamp_display: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AttackChain:
    chain_id: str
    stages: List[AttackStage] = field(default_factory=list)
    hosts_involved: List[str] = field(default_factory=list)
    attacker_ips: List[str] = field(default_factory=list)
    exfiltration_ips: List[str] = field(default_factory=list)
    compromised_users: List[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    lateral_edges: List[Dict[str, Any]] = field(default_factory=list)
    attack_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "hosts_involved": self.hosts_involved,
            "attacker_ips": self.attacker_ips,
            "exfiltration_ips": self.exfiltration_ips,
            "compromised_users": self.compromised_users,
            "lateral_edges": self.lateral_edges,
            "attack_path": self.attack_path,
            "stages": [s.to_dict() for s in self.stages],
        }

@dataclass
class IncidentReportModel:
    case_id: str
    title: str
    severity: str
    confidence_pct: int
    status: str
    hosts: List[str]
    accounts: List[str]
    period_start: str
    period_end: str
    source_name: str
    total_events_processed: int
    chain: AttackChain
    mitre_summary: List[Dict[str, Any]]
    all_iocs: List[Dict[str, Any]]
    missing_evidence: List[str]
    recommendations: Dict[str, List[str]]
    period_start_display: str = ""
    period_end_display: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "severity": self.severity,
            "confidence_pct": self.confidence_pct,
            "status": self.status,
            "hosts": self.hosts,
            "accounts": self.accounts,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "period_start_display": self.period_start_display,
            "period_end_display": self.period_end_display,
            "source_name": self.source_name,
            "total_events_processed": self.total_events_processed,
            "chain": self.chain.to_dict(),
            "mitre_summary": self.mitre_summary,
            "all_iocs": self.all_iocs,
            "missing_evidence": self.missing_evidence,
            "recommendations": self.recommendations,
        }
