import statistics
from datetime import datetime
from typing import List, Tuple, Optional

def parse_dt(t):
    from bluekit.logs.parse import parse_ts
    parsed = parse_ts(t)
    return parsed if parsed is not None else t

def calculate_beacon_metrics(timestamps: List[any]) -> Optional[Tuple[float, float]]:
    """
    Returns (median_interval, cv_ratio) if enough data, else None.

    cv_ratio = stdev(filtrlangan intervallar) / median -- ya'ni variatsiya
    koeffitsiyenti (CV), haqiqiy MAD emas. Nomi shuning uchun `cv`; ostona
    qiymatlari (0.3 / 0.6 / 0.5) aynan shu o'lchovga moslab tanlangan.
    """
    if len(timestamps) < 2:
        return None
    
    raw_intervals = [(parse_dt(timestamps[i]) - parse_dt(timestamps[i-1])).total_seconds() for i in range(1, len(timestamps))]
    raw_intervals = [i for i in raw_intervals if i and i > 0]
    
    # Needs at least 10 valid intervals according to correlator.py logic
    if len(raw_intervals) < 10:
        return None
        
    median = statistics.median(raw_intervals)
    if median <= 0:
        return None
        
    filtered = [i for i in raw_intervals if 0.5 * median <= i <= 2.0 * median]
    if len(filtered) < 10:
        return None
        
    stdev = statistics.stdev(filtered)
    med_f = statistics.median(filtered)
    if med_f <= 0:
        return None
        
    cv_ratio = stdev / med_f
    return med_f, cv_ratio
