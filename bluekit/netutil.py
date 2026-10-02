"""
IP manzillarni tahlil qilish va tekshirish uchun yordamchi vositalar.
is_global ishlatilmaydi, chunki u TEST-NET (192.0.2.0/24 kabi) va boshqa muhim tarmoqlarni ichki deb xato aniqlaydi.
"""
import ipaddress

_INTERNAL_NETS_V4 = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
]

_INTERNAL_NETS_V6 = [
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('::/128'),
    ipaddress.ip_network('fe80::/10'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('ff00::/8'),
]

def parse_ip(value):
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    if isinstance(value, str):
        val = value.strip()
        if val.startswith('[') and ']' in val:
            val = val[1:val.index(']')]
        elif val.count(':') == 1 and '.' in val:
            val = val.split(':')[0]
        
        try:
            ip_obj = ipaddress.ip_address(val)
        except ValueError:
            return None
            
        if ip_obj.version == 6 and ip_obj.ipv4_mapped:
            return ip_obj.ipv4_mapped
        return ip_obj
    return None

def is_external_ip(value) -> bool:
    ip_obj = parse_ip(value)
    if ip_obj is None:
        return False
        
    if ip_obj.version == 4:
        for net in _INTERNAL_NETS_V4:
            if ip_obj in net:
                return False
    else:
        for net in _INTERNAL_NETS_V6:
            if ip_obj in net:
                return False
                
    return True

def is_internal_ip(value) -> bool:
    ip_obj = parse_ip(value)
    return ip_obj is not None and not is_external_ip(value)
