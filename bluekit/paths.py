"""
Blue-kit Paths
"""
import os
import sys

def get_data_dir() -> str:
    # 1. Environment variable
    env_dir = os.environ.get("BLUEKIT_DATA")
    if env_dir and os.path.exists(env_dir):
        return env_dir

    # 2. Frozen (PyInstaller) build: data ships next to the .exe, not inside _MEIPASS.
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "data")

    # 3. Fallback <dir of bk.py>/data
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fallback_dir = os.path.join(current_dir, "data")
    return fallback_dir

def get_resource_path(rel_path: str) -> str:
    """Paket bilan birga keladigan resurs fayli (yaml va h.k.) yo'li.

    Frozen (PyInstaller) holatda _MEIPASS ichidan, aks holda repo ildizidan
    olinadi -- shuning uchun exe ni istalgan papkadan ishga tushirish mumkin.
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *rel_path.split("/"))

def get_kb_path(data_dir: str = None) -> str:
    d = data_dir or get_data_dir()
    return os.path.join(d, "kb", "kb.sqlite")
