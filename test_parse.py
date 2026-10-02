import ipaddress
import re
import yaml
import os
from datetime import datetime, timedelta

_TEXT_FIELD_NAMES = None
def _get_text_field_names():
    global _TEXT_FIELD_NAMES
    if _TEXT_FIELD_NAMES: return _TEXT_FIELD_NAMES
    yaml_path = os.path.join(os.path.dirname(__file__), 'fieldmap.yaml')
    with open(yaml_path, 'r', encoding='utf-8') as f:
        full_map = yaml.safe_load(f)
    def_map = full_map.get('default', {})
    res = {'ts': 'timestamp', 'host': 'host', 'src_ip': 'src_ip', 'dest_ip': 'dest_ip'}
    for canon in res.keys():
        cols = def_map.get(canon, [])
        if res[canon] not in cols and cols:
            res[canon] = cols[0]
    _TEXT_FIELD_NAMES = res
    return res

MONTHS = {'Jan':1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6, 'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12}

def _parse_text_line(line, mtime):
    fields = _get_text_field_names()
    res = {}
    
    # 1. Apache / nginx
    m_apache = re.match(r'^([a-fA-F0-9\.\:]+)\s+.*\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\]', line)
    m_syslog = re.match(r'^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)', line)
    
    if m_apache:
        ip_str = m_apache.group(1)
        try:
            ipaddress.ip_address(ip_str)
            res[fields['src_ip']] = ip_str
        except ValueError:
            pass
        
        day = int(m_apache.group(2))
        month_str = m_apache.group(3)
        year = int(m_apache.group(4))
        hour = int(m_apache.group(5))
        minute = int(m_apache.group(6))
        sec = int(m_apache.group(7))
        sign = m_apache.group(8)
        off_h = int(m_apache.group(9))
        off_m = int(m_apache.group(10))
        
        if month_str in MONTHS:
            try:
                dt = datetime(year, MONTHS[month_str], day, hour, minute, sec)
                offset = timedelta(hours=off_h, minutes=off_m)
                if sign == '+':
                    dt -= offset
                else:
                    dt += offset
                res[fields['ts']] = dt.isoformat()
            except ValueError:
                pass
                
    elif m_syslog:
        month_str = m_syslog.group(1)
        day = int(m_syslog.group(2))
        hour = int(m_syslog.group(3))
        minute = int(m_syslog.group(4))
        sec = int(m_syslog.group(5))
        host = m_syslog.group(6)
        
        res[fields['host']] = host
        
        if month_str in MONTHS:
            mtime_dt = datetime.fromtimestamp(mtime)
            year = mtime_dt.year
            try:
                dt = datetime(year, MONTHS[month_str], day, hour, minute, sec)
                if dt > mtime_dt + timedelta(days=1):
                    dt = dt.replace(year=year-1)
                res[fields['ts']] = dt.isoformat()
            except ValueError:
                pass
                
        # postfix ip fallback
        m_postfix = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
        if m_postfix:
            ip_str = m_postfix.group(1)
            try:
                ipaddress.ip_address(ip_str)
                res[fields['src_ip']] = ip_str
            except ValueError:
                pass

    # iptables fallback
    m_src = re.search(r'\bSRC=(\S+)', line)
    if m_src:
        try:
            ipaddress.ip_address(m_src.group(1))
            res[fields['src_ip']] = m_src.group(1)
        except ValueError:
            pass
            
    m_dst = re.search(r'\bDST=(\S+)', line)
    if m_dst:
        try:
            ipaddress.ip_address(m_dst.group(1))
            res[fields['dest_ip']] = m_dst.group(1)
        except ValueError:
            pass
            
    return res
