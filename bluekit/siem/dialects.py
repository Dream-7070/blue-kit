"""SIEM dialektlari: har biri = syntax klass + maydonlar xaritasi + manba xaritasi.

Yangi SIEM qo'shish uchun shu faylga uchta yozuv qo'shiladi (DIALECTS, FIELD_MAPS,
SOURCE_MAPS) — katalogdagi hunt larga tegilmaydi.
"""

DIALECTS = {
    'qradar': {
        'name': 'IBM QRadar', 'syntax': 'aql', 'language': 'AQL', 'bk_preset': 'qradar',
        'where': 'Log Activity -> Advanced Search (AQL rejimi)',
    },
    'splunk': {
        'name': 'Splunk Enterprise / Cloud', 'syntax': 'spl', 'language': 'SPL', 'bk_preset': 'splunk',
        'where': 'Search & Reporting -> qidiruv qatori',
    },
    'sentinel': {
        'name': 'Microsoft Sentinel', 'syntax': 'kql', 'language': 'KQL', 'bk_preset': 'sentinel',
        'where': 'Microsoft Sentinel -> Logs',
    },
    'defender': {
        'name': 'Microsoft Defender XDR', 'syntax': 'kql', 'language': 'KQL', 'bk_preset': 'sentinel',
        'where': 'Security.microsoft.com -> Hunting -> Advanced hunting',
    },
    'elastic': {
        'name': 'Elasticsearch ES|QL', 'syntax': 'esql', 'language': 'ES|QL', 'bk_preset': 'ecs',
        'where': 'Kibana -> Discover -> ES|QL rejimi',
    },
    'kibana': {
        'name': 'Kibana Discover (KQL)', 'syntax': 'dql', 'language': 'KQL/Lucene', 'bk_preset': 'ecs',
        'where': 'Kibana -> Discover -> qidiruv qatori',
    },
    'wazuh': {
        'name': 'Wazuh Dashboard', 'syntax': 'dql', 'language': 'DQL', 'bk_preset': 'wazuh',
        'where': 'Wazuh -> Threat Hunting -> qidiruv qatori',
    },
    'graylog': {
        'name': 'Graylog', 'syntax': 'dql', 'language': 'Lucene', 'bk_preset': 'graylog',
        'where': 'Graylog -> Search',
    },
    'chronicle': {
        'name': 'Google SecOps (Chronicle)', 'syntax': 'udm', 'language': 'UDM Search', 'bk_preset': None,
        'where': 'SecOps -> Search -> UDM Search',
    },
    'sumologic': {
        'name': 'Sumo Logic', 'syntax': 'sumo', 'language': 'Sumo Query', 'bk_preset': None,
        'where': 'Sumo Logic -> Log Search',
    },
    'arcsight': {
        'name': 'ArcSight Logger', 'syntax': 'cef_search', 'language': 'CEF Search', 'bk_preset': 'cef',
        'where': 'ArcSight Logger -> Analyze -> Search',
    },
    'logscale': {
        'name': 'CrowdStrike Falcon LogScale', 'syntax': 'cql', 'language': 'CQL', 'bk_preset': None,
        'where': 'LogScale -> Search',
    },
}

# Kanonik nom -> o'sha SIEM dagi haqiqiy maydon nomi.
# Bu yerda yo'q maydon uchun builder xom log matni bo'yicha qidiradi va ogohlantiradi.
FIELD_MAPS = {
    'qradar': {
        'ts': 'deviceTime', 'host': 'LOGSOURCENAME(logsourceid)', 'user': 'username',
        'src_ip': 'sourceip', 'dest_ip': 'destinationip',
        'src_port': 'sourceport', 'dest_port': 'destinationport',
        'event_id': '"EventID"', 'process': '"Process Name"',
        'parent_process': '"Parent Process Name"', 'command_line': '"Command Line"',
        'message': 'payload', 'protocol': 'protocolid',
        'bytes_sent': 'sourcebytes', 'bytes_recv': 'destinationbytes',
        'logon_type': '"Logon Type"', 'service_name': '"Service Name"',
        'url': '"URL"', 'user_agent': '"User Agent"', 'dns_query': '"DNS Query"',
        'http_status': '"HTTP Status"', 'file_path': '"File Path"',
        'registry_path': '"Registry Path"', 'target': '"Target Username"',
        'rule_name': '"Rule Name"', 'action': '"Action"',
    },
    'splunk': {
        'ts': '_time', 'host': 'host', 'user': 'user',
        'src_ip': 'src_ip', 'dest_ip': 'dest_ip',
        'src_port': 'src_port', 'dest_port': 'dest_port',
        'event_id': 'EventCode', 'process': 'New_Process_Name',
        'parent_process': 'Parent_Process_Name', 'command_line': 'Process_Command_Line',
        'message': '_raw', 'channel': 'source', 'protocol': 'protocol',
        'bytes_sent': 'bytes_out', 'bytes_recv': 'bytes_in', 'action': 'action',
        'logon_type': 'Logon_Type', 'service_name': 'Service_Name',
        'url': 'url', 'user_agent': 'http_user_agent', 'dns_query': 'query',
        'http_status': 'status', 'http_method': 'http_method',
        'file_path': 'file_path', 'registry_path': 'registry_path',
        'target': 'Target_Account_Name', 'ticket_encryption': 'Ticket_Encryption_Type',
    },
    'sentinel': {
        'ts': 'TimeGenerated', 'host': 'Computer', 'user': 'Account',
        'src_ip': 'IpAddress', 'dest_ip': 'DestinationIP',
        'src_port': 'SourcePort', 'dest_port': 'DestinationPort',
        'event_id': 'EventID', 'process': 'NewProcessName',
        'parent_process': 'ParentProcessName', 'command_line': 'CommandLine',
        'message': 'Activity', 'channel': 'Channel', 'protocol': 'Protocol',
        'logon_type': 'LogonType', 'service_name': 'ServiceName',
        'target': 'TargetAccount', 'action': 'DeviceAction',
        'bytes_sent': 'SentBytes', 'bytes_recv': 'ReceivedBytes',
        'url': 'RequestURL', 'http_status': 'scStatus',
        'ticket_encryption': 'TicketEncryptionType',
    },
    # Defender XDR da Windows EventID yo'q -- builder uni ActionType ga tarjima qiladi
    # (EVENT_ID_TRANSLATION), tarjima topilmasa ogohlantiradi.
    'defender': {
        'ts': 'Timestamp', 'host': 'DeviceName', 'user': 'AccountName',
        'src_ip': 'LocalIP', 'dest_ip': 'RemoteIP',
        'src_port': 'LocalPort', 'dest_port': 'RemotePort',
        'event_id': 'ActionType', 'process': 'FileName',
        'parent_process': 'InitiatingProcessFileName', 'command_line': 'ProcessCommandLine',
        'message': 'AdditionalFields', 'protocol': 'Protocol',
        'url': 'RemoteUrl', 'dns_query': 'RemoteUrl',
        'file_path': 'FolderPath', 'registry_path': 'RegistryKey',
        'logon_type': 'LogonType', 'target': 'AccountName',
        'sender': 'SenderFromAddress', 'recipient': 'RecipientEmailAddress',
        'subject': 'Subject',
    },
    'elastic': {
        'ts': '@timestamp', 'host': 'host.name', 'user': 'user.name',
        'src_ip': 'source.ip', 'dest_ip': 'destination.ip',
        'src_port': 'source.port', 'dest_port': 'destination.port',
        'event_id': 'event.code', 'process': 'process.name',
        'parent_process': 'process.parent.name', 'command_line': 'process.command_line',
        'pid': 'process.pid', 'ppid': 'process.parent.pid',
        'message': 'message', 'channel': 'winlog.channel', 'action': 'event.action',
        'protocol': 'network.protocol', 'bytes_sent': 'source.bytes',
        'bytes_recv': 'destination.bytes', 'url': 'url.original',
        'http_method': 'http.request.method', 'http_status': 'http.response.status_code',
        'user_agent': 'user_agent.original', 'dns_query': 'dns.question.name',
        'file_path': 'file.path', 'registry_path': 'registry.path',
        'logon_type': 'winlog.event_data.LogonType',
        'service_name': 'winlog.event_data.ServiceName',
        'target': 'winlog.event_data.TargetImage',
        'ticket_encryption': 'winlog.event_data.TicketEncryptionType',
        'sender': 'source.user.email', 'recipient': 'destination.user.email',
        'rule_name': 'rule.name',
    },
    'wazuh': {
        'ts': 'timestamp', 'host': 'agent.name',
        'event_id': 'data.win.system.eventID',
        'user': 'data.win.eventdata.targetUserName',
        'command_line': 'data.win.eventdata.commandLine',
        'process': 'data.win.eventdata.image',
        'parent_process': 'data.win.eventdata.parentImage',
        'src_ip': 'data.srcip', 'dest_ip': 'data.dstip',
        'src_port': 'data.srcport', 'dest_port': 'data.dstport',
        'rule_name': 'rule.description', 'message': 'full_log',
        'channel': 'data.win.system.channel', 'action': 'data.action',
        'url': 'data.url', 'user_agent': 'data.user_agent',
        'logon_type': 'data.win.eventdata.logonType',
        'service_name': 'data.win.eventdata.serviceName',
        'file_path': 'data.win.eventdata.targetFilename',
        'registry_path': 'data.win.eventdata.targetObject',
        'target': 'data.win.eventdata.targetImage',
    },
    # Graylog da maydon nomlari extractor ga bog'liq -- faqat kafolatlangan uchtasi
    # beriladi, qolgani xom `message` bo'yicha qidiriladi (builder ogohlantiradi).
    'graylog': {
        'ts': 'timestamp', 'host': 'source', 'message': 'message',
    },
    'chronicle': {
        'ts': 'metadata.event_timestamp', 'host': 'principal.hostname',
        'user': 'principal.user.userid', 'event_id': 'metadata.product_event_type',
        'process': 'target.process.file.full_path',
        'parent_process': 'principal.process.file.full_path',
        'command_line': 'target.process.command_line',
        'src_ip': 'principal.ip', 'dest_ip': 'target.ip',
        'src_port': 'principal.port', 'dest_port': 'target.port',
        'url': 'target.url', 'user_agent': 'network.http.user_agent',
        'http_status': 'network.http.response_code',
        'dns_query': 'network.dns.questions.name',
        'bytes_sent': 'network.sent_bytes', 'bytes_recv': 'network.received_bytes',
        'file_path': 'target.file.full_path',
        'registry_path': 'target.registry.registry_key',
        'message': 'metadata.description', 'action': 'security_result.action',
    },
    'sumologic': {
        'ts': '_messagetime', 'host': '_sourcehost', 'message': '_raw',
        'user': 'user', 'src_ip': 'src_ip', 'dest_ip': 'dest_ip',
        'src_port': 'src_port', 'dest_port': 'dest_port', 'event_id': 'event_id',
        'process': 'process', 'command_line': 'command_line', 'action': 'action',
        'bytes_sent': 'bytes_out', 'bytes_recv': 'bytes_in',
        'url': 'url', 'user_agent': 'user_agent', 'dns_query': 'query',
        'http_status': 'status',
    },
    'arcsight': {
        'ts': 'rt', 'host': 'dhost', 'user': 'duser',
        'src_ip': 'src', 'dest_ip': 'dst', 'src_port': 'spt', 'dest_port': 'dpt',
        'event_id': 'deviceEventClassId', 'process': 'sproc',
        'message': 'msg', 'action': 'act', 'protocol': 'proto',
        'bytes_sent': 'out', 'bytes_recv': 'in', 'url': 'request',
        'file_path': 'filePath', 'target': 'duser', 'rule_name': 'name',
    },
    'logscale': {
        'ts': '@timestamp', 'host': 'host', 'message': '@rawstring',
        'event_id': 'EventID', 'user': 'TargetUserName',
        'process': 'Image', 'parent_process': 'ParentImage',
        'command_line': 'CommandLine',
        'src_ip': 'SourceIp', 'dest_ip': 'DestinationIp',
        'src_port': 'SourcePort', 'dest_port': 'DestinationPort',
        'logon_type': 'LogonType', 'service_name': 'ServiceName',
        'file_path': 'TargetFilename', 'registry_path': 'TargetObject',
        'target': 'TargetImage',
    },
}

# Kibana Discover ham ECS maydonlaridan foydalanadi.
FIELD_MAPS['kibana'] = dict(FIELD_MAPS['elastic'])

FIELD_OVERRIDES = {
    'sentinel': {
        'firewall': {
            'src_ip': 'SourceIP', 'dest_ip': 'DestinationIP', 'src_port': 'SourcePort', 'dest_port': 'DestinationPort',
            'action': 'DeviceAction', 'bytes_sent': 'SentBytes', 'bytes_recv': 'ReceivedBytes', 'protocol': 'Protocol',
            'url': 'RequestURL', 'user': 'SourceUserName', 'host': 'DeviceName', 'message': 'Activity'
        },
        'proxy': {
            'src_ip': 'SourceIP', 'dest_ip': 'DestinationIP', 'src_port': 'SourcePort', 'dest_port': 'DestinationPort',
            'action': 'DeviceAction', 'bytes_sent': 'SentBytes', 'bytes_recv': 'ReceivedBytes', 'protocol': 'Protocol',
            'url': 'RequestURL', 'user': 'SourceUserName', 'host': 'DeviceName', 'message': 'Activity'
        },
        'dns': {
            'host': 'Computer', 'src_ip': 'ClientIP', 'dns_query': 'Name',
            'protocol': 'QueryType', 'dest_ip': 'IPAddresses'
        },
        'web': {
            'host': 'Computer', 'src_ip': 'cIP', 'url': 'csUriStem', 
            'http_status': 'scStatus', 'http_method': 'csMethod', 'user_agent': 'csUserAgent'
        },
        'vpn': {
            'user': 'UserPrincipalName', 'src_ip': 'IPAddress'
        },
        'mail': {
            'user': 'UserId', 'src_ip': 'ClientIP', 'action': 'Operation'
        }
    },
    'defender': {
        'windows-logon': {
            'src_ip': 'RemoteIP'
        },
        'linux-auth': {
            'src_ip': 'RemoteIP'
        },
        'vpn': {
            'src_ip': 'RemoteIP'
        }
    }
}

# Hunt ning `logsource` i -> o'sha dialektdagi jadval / indeks / manba sharti.
# Ro'yxatda yo'q logsource uchun 'any' ishlatiladi.
SOURCE_MAPS = {
    'qradar': {
        'windows-security': 'events', 'windows-logon': 'events', 'windows-process': 'events', 'windows-account': 'events', 'windows-service': 'events', 'windows-system': 'events', 'windows-registry': 'events', 'windows-sysmon': 'events', 'linux-auth': 'events', 'firewall': 'events', 'proxy': 'events', 'dns': 'events', 'web': 'events', 'edr': 'events', 'mail': 'events', 'vpn': 'events', 'ics': 'events', 'any': 'events'
    },
    'splunk': {
        'windows-security': 'index=wineventlog source="WinEventLog:Security"',
        'windows-logon': 'index=wineventlog source="WinEventLog:Security"',
        'windows-process': 'index=wineventlog source="WinEventLog:Security"',
        'windows-account': 'index=wineventlog source="WinEventLog:Security"',
        'windows-service': 'index=wineventlog source="WinEventLog:System"',
        'windows-system': 'index=wineventlog source="WinEventLog:System"',
        'windows-registry': 'index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
        'windows-sysmon': 'index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
        'linux-auth': 'index=linux source=/var/log/secure',
        'firewall': 'index=firewall', 'proxy': 'index=proxy', 'dns': 'index=dns',
        'web': 'index=web', 'edr': 'index=edr', 'mail': 'index=mail', 'vpn': 'index=vpn',
        'ics': 'index=ics', 'any': 'index=*',
    },
    'sentinel': {
        'windows-security': 'SecurityEvent', 'windows-logon': 'SecurityEvent',
        'windows-process': 'SecurityEvent', 'windows-account': 'SecurityEvent',
        'windows-service': 'Event', 'windows-system': 'Event',
        'windows-registry': 'Event', 'windows-sysmon': 'Event',
        'linux-auth': 'Syslog', 'firewall': 'CommonSecurityLog',
        'proxy': 'CommonSecurityLog', 'dns': 'DnsEvents', 'web': 'W3CIISLog',
        'edr': 'SecurityAlert', 'mail': 'OfficeActivity', 'vpn': 'SigninLogs',
        'ics': 'CommonSecurityLog', 'any': 'search *',
    },
    'defender': {
        'windows-security': 'DeviceEvents', 'windows-logon': 'DeviceLogonEvents',
        'windows-process': 'DeviceProcessEvents', 'windows-account': 'DeviceEvents',
        'windows-service': 'DeviceEvents', 'windows-system': 'DeviceEvents',
        'windows-registry': 'DeviceRegistryEvents', 'windows-sysmon': 'DeviceEvents',
        'linux-auth': 'DeviceLogonEvents', 'firewall': 'DeviceNetworkEvents',
        'proxy': 'DeviceNetworkEvents', 'dns': 'DeviceNetworkEvents',
        'web': 'DeviceNetworkEvents', 'edr': 'DeviceEvents',
        'mail': 'EmailEvents', 'vpn': 'DeviceLogonEvents', 'ics': 'DeviceEvents', 'any': 'DeviceEvents',
    },
    'elastic': {
        'windows-security': 'FROM logs-windows.*', 'windows-logon': 'FROM logs-windows.*',
        'windows-process': 'FROM logs-windows.*', 'windows-account': 'FROM logs-windows.*',
        'windows-service': 'FROM logs-windows.*', 'windows-system': 'FROM logs-windows.*',
        'windows-registry': 'FROM logs-windows.*', 'windows-sysmon': 'FROM logs-windows.*',
        'linux-auth': 'FROM logs-system.*', 'firewall': 'FROM logs-network.*',
        'proxy': 'FROM logs-network.*', 'dns': 'FROM logs-network.*',
        'web': 'FROM logs-nginx.*,logs-apache.*', 'edr': 'FROM logs-endpoint.*',
        'mail': 'FROM logs-mail.*', 'vpn': 'FROM logs-network.*', 'ics': 'FROM logs-ics.*', 'any': 'FROM logs-*',
    },
    'kibana': {
        'windows-security': '', 'windows-logon': '', 'windows-process': '', 'windows-account': '', 'windows-service': '', 'windows-system': '', 'windows-registry': '', 'windows-sysmon': '', 'linux-auth': '', 'firewall': '', 'proxy': '', 'dns': '', 'web': '', 'edr': '', 'mail': '', 'vpn': '', 'ics': '', 'any': ''
    },
    'wazuh': {
        'windows-security': 'rule.groups:windows', 'windows-logon': 'rule.groups:windows',
        'windows-process': 'rule.groups:windows', 'windows-account': 'rule.groups:windows',
        'windows-service': 'rule.groups:windows', 'windows-system': 'rule.groups:windows',
        'windows-registry': 'rule.groups:sysmon', 'windows-sysmon': 'rule.groups:sysmon',
        'linux-auth': 'rule.groups:syslog', 'firewall': 'rule.groups:firewall',
        'proxy': 'rule.groups:proxy', 'dns': 'rule.groups:dns', 'web': 'rule.groups:web',
        'edr': 'rule.groups:ossec', 'mail': 'rule.groups:mail', 'vpn': 'rule.groups:vpn',
        'ics': '', 'any': '',
    },
    'graylog': {
        'windows-security': 'source:windows', 'windows-logon': 'source:windows',
        'windows-process': 'source:windows', 'windows-account': 'source:windows',
        'windows-service': 'source:windows', 'windows-system': 'source:windows',
        'windows-registry': 'source:windows', 'windows-sysmon': 'source:windows',
        'linux-auth': 'source:linux', 'firewall': 'source:firewall',
        'proxy': 'source:proxy', 'dns': 'source:dns', 'web': 'source:web',
        'edr': 'source:edr', 'mail': 'source:mail', 'vpn': 'source:vpn', 'ics': '', 'any': '',
    },
    'chronicle': {
        'windows-security': 'metadata.log_type = "WINEVTLOG"',
        'windows-logon': 'metadata.log_type = "WINEVTLOG"',
        'windows-process': 'metadata.log_type = "WINEVTLOG"',
        'windows-account': 'metadata.log_type = "WINEVTLOG"',
        'windows-service': 'metadata.log_type = "WINEVTLOG"',
        'windows-system': 'metadata.log_type = "WINEVTLOG"',
        'windows-registry': 'metadata.log_type = "SYSMON"',
        'windows-sysmon': 'metadata.log_type = "SYSMON"',
        'linux-auth': 'metadata.log_type = "LINUX_SYSLOG"',
        'firewall': 'metadata.log_type = "FIREWALL"',
        'proxy': 'metadata.log_type = "PROXY"', 'dns': 'metadata.log_type = "DNS"',
        'web': 'metadata.log_type = "WEB"', 'edr': 'metadata.log_type = "EDR"',
        'mail': 'metadata.log_type = "MAIL"', 'vpn': 'metadata.log_type = "VPN"',
        'ics': '', 'any': '',
    },
    'sumologic': {
        'windows-security': '_sourceCategory=windows/security',
        'windows-logon': '_sourceCategory=windows/security',
        'windows-process': '_sourceCategory=windows/security',
        'windows-account': '_sourceCategory=windows/security',
        'windows-service': '_sourceCategory=windows/system',
        'windows-system': '_sourceCategory=windows/system',
        'windows-registry': '_sourceCategory=windows/sysmon',
        'windows-sysmon': '_sourceCategory=windows/sysmon',
        'linux-auth': '_sourceCategory=linux/secure',
        'firewall': '_sourceCategory=firewall', 'proxy': '_sourceCategory=proxy',
        'dns': '_sourceCategory=dns', 'web': '_sourceCategory=web',
        'edr': '_sourceCategory=edr', 'mail': '_sourceCategory=mail',
        'vpn': '_sourceCategory=vpn', 'ics': '_sourceCategory=ics', 'any': '_sourceCategory=*',
    },
    'arcsight': {
        'windows-security': 'deviceVendor="Microsoft"', 'windows-logon': 'deviceVendor="Microsoft"',
        'windows-process': 'deviceVendor="Microsoft"', 'windows-account': 'deviceVendor="Microsoft"',
        'windows-service': 'deviceVendor="Microsoft"', 'windows-system': 'deviceVendor="Microsoft"',
        'windows-registry': 'deviceVendor="Microsoft"', 'windows-sysmon': 'deviceVendor="Microsoft"',
        'linux-auth': 'deviceVendor="Unix"', 'firewall': 'deviceProduct="Firewall"',
        'proxy': 'deviceProduct="Proxy"', 'dns': 'deviceProduct="DNS"',
        'web': 'deviceProduct="Web Server"', 'edr': 'deviceProduct="EDR"',
        'mail': 'deviceProduct="Mail"', 'vpn': 'deviceProduct="VPN"', 'ics': '', 'any': '',
    },
    'logscale': {
        'windows-security': '#type="wineventlog"', 'windows-logon': '#type="wineventlog"',
        'windows-process': '#type="wineventlog"', 'windows-account': '#type="wineventlog"',
        'windows-service': '#type="wineventlog"', 'windows-system': '#type="wineventlog"',
        'windows-registry': '#type="sysmon"', 'windows-sysmon': '#type="sysmon"',
        'linux-auth': '#type="syslog"', 'firewall': '#type="firewall"',
        'proxy': '#type="proxy"', 'dns': '#type="dns"', 'web': '#type="accesslog"',
        'edr': '#type="edr"', 'mail': '#type="mail"', 'vpn': '#type="vpn"', 'ics': '*', 'any': '*',
    },
}

# Defender XDR Windows EventID ishlatmaydi -- ActionType ga tarjima qilinadi.
# Bu yerda faqat hujjatlashtirilgan, ishonchli mosliklar bor; qolganlari uchun
# builder ogohlantirish qo'shadi.
EVENT_ID_TRANSLATION = {
    'defender': {
        1: 'ProcessCreated', 3: 'ConnectionSuccess', 11: 'FileCreated',
        12: 'RegistryKeyCreated', 13: 'RegistryValueSet',
        4624: 'LogonSuccess', 4625: 'LogonFailed', 4688: 'ProcessCreated',
        4698: 'ScheduledTaskCreated', 4720: 'UserAccountCreated',
        4728: 'UserAccountAddedToLocalGroup', 4732: 'UserAccountAddedToLocalGroup',
        4756: 'UserAccountAddedToLocalGroup', 7045: 'ServiceInstalled',
    },
}


def source_for(siem, logsource):
    smap = SOURCE_MAPS.get(siem, {})
    if logsource in smap:
        return smap[logsource]
    return smap.get('any', '')
