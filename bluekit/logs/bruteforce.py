from datetime import timedelta
from collections import defaultdict, Counter

WINDOW = timedelta(minutes=10)
THRESHOLD = 10
SUCCESS_WINDOW = timedelta(minutes=60)
SPRAY_MIN_USERS = 5
SPRAY_MAX_PER_USER = 3

def correlate_bruteforce(events, hits_by_index, window=WINDOW, threshold=THRESHOLD,
                         success_window=SUCCESS_WINDOW) -> list:
    
    # Group events by key
    # Only keep 4625 and 4624 with ts and correct channel
    
    key_4625 = defaultdict(list)
    key_4624 = defaultdict(list)
    
    for i, ev in enumerate(events):
        ts = ev.get('ts')
        if not ts:
            continue
            
        eid = str(ev.get('event_id') or '').strip()
        if eid not in ('4625', '4624'):
            continue
            
        channel = ev.get('channel')
        if channel and 'security' not in channel.lower():
            continue
            
        account = (ev.get('target') or ev.get('user') or '').strip()
        src_ip = ev.get('src_ip')
        host = ev.get('host')
        
        key = None
        if src_ip and src_ip not in {'-', '::1', '127.0.0.1', '0.0.0.0'}:
            key = ('ip', src_ip)
        elif account and host:
            key = ('host_user', host.lower(), account.lower())
        else:
            continue
            
        if eid == '4625':
            key_4625[key].append((i, ts, ev, account, host))
        else:
            key_4624[key].append((i, ts, ev, account, host))
            
    bursts_info = []
    
    window_min = int(window.total_seconds() / 60)
    
    for key, fails in key_4625.items():
        fails.sort(key=lambda x: x[1])
        
        flagged = set()
        
        # two pointer
        left = 0
        for right in range(len(fails)):
            while fails[right][1] - fails[left][1] > window:
                left += 1
            if right - left + 1 >= threshold:
                for k in range(left, right + 1):
                    flagged.add(k)
                    
        if not flagged:
            continue
            
        # Group consecutive flagged into bursts
        flagged_sorted = sorted(list(flagged))
        bursts = []
        current_burst = [flagged_sorted[0]]
        
        for i in range(1, len(flagged_sorted)):
            prev_idx = current_burst[-1]
            curr_idx = flagged_sorted[i]
            
            # neighbor difference <= window
            if fails[curr_idx][1] - fails[prev_idx][1] <= window:
                current_burst.append(curr_idx)
            else:
                bursts.append(current_burst)
                current_burst = [curr_idx]
        bursts.append(current_burst)
        
        for b_indices in bursts:
            b_fails = [fails[idx] for idx in b_indices]
            
            accounts_counter = Counter()
            for _, _, _, acc, _ in b_fails:
                if acc:
                    accounts_counter[acc.lower()] += 1
                    
            unique_accounts = len(accounts_counter)
            max_attempts = max(accounts_counter.values()) if accounts_counter else 0
            
            if unique_accounts >= SPRAY_MIN_USERS and max_attempts <= SPRAY_MAX_PER_USER:
                technique = 'T1110.003'
                tech_name = 'Password Spraying'
            else:
                technique = 'T1110.001'
                tech_name = 'Password Guessing'
                
            n = len(b_fails)
            
            label = key[1] if key[0] == 'ip' else f"{key[1]}/{key[2]}"
            evidence = f"{n} ta 4625 <={window_min} daqiqada, manba {label}"
            
            for f_idx, _, _, _, _ in b_fails:
                if f_idx not in hits_by_index:
                    hits_by_index[f_idx] = []
                
                # check if exactly this technique already exists
                existing = next((h for h in hits_by_index[f_idx] if h.get('technique') == technique), None)
                if existing:
                    existing['confidence'] = 'high'
                    existing['source'] = 'correlation'
                    existing['evidence'] = evidence
                else:
                    hits_by_index[f_idx].append({
                        'technique': technique,
                        'name': tech_name,
                        'confidence': 'high',
                        'score': 1.0,
                        'source': 'correlation',
                        'evidence': evidence
                    })
                    
            first_ts = b_fails[0][1]
            last_ts = b_fails[-1][1]
            
            # Success
            success = False
            success_ts = None
            success_account = None
            success_host = None
            success_disp = ""
            
            from bluekit.tz import display_ts
            first_ev = b_fails[0][2]
            last_ev = b_fails[-1][2]
            first_disp = (first_ev.get('ts_disp') or display_ts(first_ts)) if isinstance(first_ev, dict) else display_ts(first_ts)
            last_disp = (last_ev.get('ts_disp') or display_ts(last_ts)) if isinstance(last_ev, dict) else display_ts(last_ts)
            
            # kalit bir xil: 'ip' — shu src_ip (hisobdan qat'iy nazar), 'host_user' — shu host+hisob
            for s_idx, s_ts, s_ev, s_acc, s_host in key_4624.get(key, []):
                if first_ts <= s_ts <= last_ts + success_window:
                    success = True
                    success_ts = s_ts
                    success_account = s_acc
                    success_host = s_host
                    success_disp = (s_ev.get('ts_disp') or display_ts(success_ts)) if isinstance(s_ev, dict) else display_ts(success_ts)
                    
                    s_evidence = f"BRUTE-FORCE MUVAFFAQIYATLI: {n} ta 4625 dan keyin 4624 ({label}, hisob {s_acc})"
                    
                    if s_idx not in hits_by_index:
                        hits_by_index[s_idx] = []
                        
                    existing_s = next((h for h in hits_by_index[s_idx] if h.get('technique') == technique), None)
                    if existing_s:
                        existing_s['confidence'] = 'high'
                        existing_s['source'] = 'correlation'
                        existing_s['evidence'] = s_evidence
                    else:
                        hits_by_index[s_idx].append({
                            'technique': technique,
                            'name': tech_name,
                            'confidence': 'high',
                            'score': 1.0,
                            'source': 'correlation',
                            'evidence': s_evidence
                        })
                    break
                    
            host_counter = Counter(h for _, _, _, _, h in b_fails if h)
            freq_host = host_counter.most_common(1)[0][0] if host_counter else None
            
            sorted_accounts = sorted([acc for acc in accounts_counter.keys() if acc])[:10]
            
            bursts_info.append({
                'technique': technique,
                'name': tech_name,
                'key_type': key[0],
                'source': label,
                'host': freq_host,
                'accounts': sorted_accounts,
                'failures': n,
                'first': first_ts,
                'last': last_ts,
                'first_disp': first_disp,
                'last_disp': last_disp,
                'success': success,
                'success_ts': success_ts,
                'success_disp': success_disp,
                'success_account': success_account,
                'success_host': success_host
            })
            
    bursts_info.sort(key=lambda x: x['first'])
    return bursts_info
