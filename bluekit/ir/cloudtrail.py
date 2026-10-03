import re
from collections import defaultdict
from bluekit.ir.models import AttackStage

def get_nested(d, path, default=None):
    if isinstance(d, dict) and path in d:
        return d[path]
    parts = path.split('.')
    cur = d
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def cloud_audit_stages(raw_events, extract_canonical, is_external_ip):
    stages = []
    handled_idx = set()
    
    # groups: (principal, src_ip) -> list of (event_idx, canonical_event, raw_ts, ts, eventName, errorCode, userAgent, is_iam, is_log)
    groups = defaultdict(list)
    
    for i, ev in enumerate(raw_events):
        c = extract_canonical(ev)
        
        # Check if cloudtrail
        win_chan = str(get_nested(ev, 'winlog.channel') or '').lower()
        dataset = str(c.get('dataset') or '').lower()
        ev_dataset = str(get_nested(ev, 'event.dataset') or '').lower()
        msg = str(c.get('message') or '')
        
        is_cloudtrail = ('cloudtrail' in win_chan) or ('cloudtrail' in dataset) or ('cloudtrail' in ev_dataset) or ('eventName=' in msg) or ('eventName' in ev)
        
        if not is_cloudtrail:
            continue
            
        # Extract fields
        eventName = None
        if 'eventName' in ev:
            eventName = ev['eventName']
        elif get_nested(ev, 'event.code'):
            eventName = get_nested(ev, 'event.code')
        else:
            m = re.search(r'eventName=(\w+)', msg)
            if m:
                eventName = m.group(1)
                
        if not eventName:
            continue
            
        principal = None
        ui = ev.get('userIdentity', {})
        if isinstance(ui, dict):
            if ui.get('userName'):
                principal = ui['userName']
            elif ui.get('arn'):
                principal = str(ui['arn']).split('/')[-1]
                
        if not principal:
            if c.get('user'):
                principal = c['user']
            else:
                principal = "unknown"
                
        src_ip = ev.get('sourceIPAddress') or c.get('src_ip') or ""
        
        userAgent = None
        if 'userAgent' in ev:
            userAgent = str(ev['userAgent'])
        else:
            m = re.search(r'userAgent=(.*?)(?:\s+params=|$)', msg)
            if m:
                userAgent = m.group(1)
                
        userAgent = userAgent or ""
        
        errorCode = None
        if 'errorCode' in ev:
            errorCode = str(ev['errorCode'])
        else:
            m = re.search(r'errorCode=(\S+)', msg)
            if m:
                errorCode = m.group(1)
                
        errorCode = errorCode or "-"
        
        # Rejection
        ua_lower = userAgent.lower()
        if re.search(r'(aws-sdk|awsinternal|aws internal|lambda|ec2|ecs|codebuild|codepipeline|cloudformation|console\.amazonaws|amazonaws\.com|terraform)', ua_lower):
            continue
            
        if not src_ip or not is_external_ip(src_ip):
            continue
            
        is_iam = bool(re.match(r'^(Create(User|AccessKey|LoginProfile|Role|Policy)|Attach\w*Policy|Put\w*Policy|AddUserToGroup|UpdateAssumeRolePolicy)$', eventName, re.I))
        is_log = bool(re.match(r'^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors)$', eventName, re.I))
        
        from bluekit.logs.parse import parse_ts
        ts_str = c.get('timestamp')
        ts = parse_ts(ts_str) if ts_str else None
        
        groups[(principal, src_ip)].append({
            'idx': i,
            'c': c,
            'raw_ts': ts_str,
            'ts': ts,
            'eventName': eventName,
            'errorCode': errorCode,
            'userAgent': userAgent,
            'is_iam': is_iam,
            'is_log': is_log
        })
        
    for (principal, src_ip), events in groups.items():
        # group by 30-minute window. We can sort by ts.
        events = sorted([e for e in events if e['ts']], key=lambda x: x['ts'])
        if not events:
            continue
            
        windows = []
        curr_win = []
        for e in events:
            if not curr_win:
                curr_win.append(e)
            else:
                if (e['ts'] - curr_win[0]['ts']).total_seconds() <= 1800:
                    curr_win.append(e)
                else:
                    windows.append(curr_win)
                    curr_win = [e]
        if curr_win:
            windows.append(curr_win)
            
        for win in windows:
            t1530_cnt = 0
            t1619_cnt = 0
            t1619_matched = False
            has_iam_or_log = False
            first_iam_log_ev = None
            
            t1530_idxs = []
            t1619_idxs = []
            
            first_ts = win[0]['raw_ts']
            host = win[0]['c'].get('host') or "cloud"
            ua_list = set()
            
            for e in win:
                ename = e['eventName']
                ecode = e['errorCode']
                ua = e['userAgent']
                ua_list.add(ua)
                
                is_success = (ecode == "-" or ecode == "" or ecode is None)
                
                if is_success and re.match(r'^(GetObject|CopyObject|GetObjectVersion|SelectObjectContent|GetObjectTorrent)$', ename, re.I):
                    t1530_cnt += 1
                    t1530_idxs.append(e['idx'])
                    
                if re.match(r'^(ListBuckets|ListObjects|ListObjectsV2|ListObjectVersions|GetBucketLocation|GetBucketAcl)$', ename, re.I):
                    if re.search(r'(aws-cli|boto|botocore|pacu|s3cmd|rclone|python-requests|curl|go-http|cyberduck)', ua, re.I):
                        t1619_cnt += 1
                        t1619_idxs.append(e['idx'])
                        
                if e['is_iam'] or e['is_log']:
                    has_iam_or_log = True
                    if not first_iam_log_ev:
                        first_iam_log_ev = e['eventName']
                        
            st_created = False
            
            ua_str = next(iter(ua_list)) if ua_list else ""
            
            if t1530_cnt >= 10:
                evidence = f"{principal} tashqi IP {src_ip} dan {t1530_cnt} ta GetObject (UA {ua_str})"
                st = AttackStage(
                    stage_id="TEMP",
                    timestamp=first_ts,
                    host=host,
                    phase="Collection",
                    technique_id="T1530",
                    technique_name="Data from Cloud Storage",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=evidence,
                    iocs={'principal': principal, 'src_ip': src_ip, 'attempts': t1530_cnt, 'ua': ua_str},
                    source_dataset=win[0]['c'].get('dataset', '')
                )
                stages.append((st, src_ip))
                handled_idx.update(t1530_idxs)
                st_created = True
                
            if t1619_cnt >= 1:
                st = AttackStage(
                    stage_id="TEMP",
                    timestamp=first_ts,
                    host=host,
                    phase="Discovery",
                    technique_id="T1619",
                    technique_name="Cloud Storage Object Discovery",
                    confidence="MEDIUM",
                    status="CONFIRMED",
                    evidence=f"{principal} tashqi IP {src_ip} dan ob'yekt qidiruvi",
                    iocs={'principal': principal, 'src_ip': src_ip, 'ua': ua_str},
                    source_dataset=win[0]['c'].get('dataset', '')
                )
                stages.append((st, src_ip))
                handled_idx.update(t1619_idxs)
                st_created = True
                
            if st_created or has_iam_or_log:
                evid = ""
                if has_iam_or_log:
                    evid = f"{principal}, IP {src_ip}, UA {ua_str}, birinchi hodisa: {first_iam_log_ev}"
                else:
                    evid = f"{principal}, IP {src_ip}, UA {ua_str}, birinchi hodisa: {win[0]['eventName']}"
                    
                st = AttackStage(
                    stage_id="TEMP",
                    timestamp=first_ts,
                    host=host,
                    phase="Initial Access",
                    technique_id="T1078.004",
                    technique_name="Valid Accounts: Cloud Accounts",
                    confidence="MEDIUM",
                    status="CONFIRMED",
                    evidence=evid,
                    iocs={'principal': principal, 'src_ip': src_ip, 'ua': ua_str},
                    source_dataset=win[0]['c'].get('dataset', '')
                )
                stages.append((st, src_ip))
                
    return stages, handled_idx
