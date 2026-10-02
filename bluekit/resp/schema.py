from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class Snapshot:
    meta: Dict[str, Any]
    users: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    tasks: List[Dict[str, Any]] = field(default_factory=list)
    cron: List[Dict[str, Any]] = field(default_factory=list)
    autoruns: List[Dict[str, Any]] = field(default_factory=list)
    wmi_subscriptions: List[Dict[str, Any]] = field(default_factory=list)
    ssh_authorized_keys: List[Dict[str, Any]] = field(default_factory=list)
    listening_ports: List[Dict[str, Any]] = field(default_factory=list)
    connections: List[Dict[str, Any]] = field(default_factory=list)
    hosts_file: List[str] = field(default_factory=list)
    suid_files: List[str] = field(default_factory=list)
    startup_items: List[Dict[str, Any]] = field(default_factory=list)
    remote_access_tools: List[Dict[str, Any]] = field(default_factory=list)
    defender: Dict[str, Any] = field(default_factory=dict)
    recent_modified: List[Dict[str, Any]] = field(default_factory=list)
    packages_modified: List[Any] = field(default_factory=list)
    proxy: Dict[str, Any] = field(default_factory=dict)
    dns_servers: List[Dict[str, Any]] = field(default_factory=list)
    root_cas: List[Dict[str, Any]] = field(default_factory=list)
    portproxy: List[Dict[str, Any]] = field(default_factory=list)
    firewall_profiles: List[Dict[str, Any]] = field(default_factory=list)
    packages: List[Dict[str, Any]] = field(default_factory=list)
    installed_apps: List[Dict[str, Any]] = field(default_factory=list)
    containers: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
