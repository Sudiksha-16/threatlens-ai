"""
ThreatLens AI - Dataset Downloader
Downloads real, publicly available, labeled malware datasets:
1. ClaMP (Classification of Malware with PE headers) - 5,210 real PE samples with 69 features (Benign vs Malicious).
2. DA-Proj PE Malware Dataset - 18,550+ PE samples with malware family labels (Ransomware, Spyware, Downloader, Backdoor, Generic Malware).
"""

import os
import sys
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

CLAMP_URL = "https://raw.githubusercontent.com/urwithajit9/ClaMP/master/dataset/ClaMP_Integrated-5184.csv"
DAPROJ_HEADER_URL = "https://raw.githubusercontent.com/DA-Proj/PE-Malware-Dataset1/main/Header.csv"

DATA_DIRS = [
    os.path.join(os.path.dirname(__file__), "data"),
    os.path.join(os.path.dirname(__file__), "..", "backend", "app", "ml", "datasets")
]

def download_file(url: str, dest_path: str):
    logger.info(f"Downloading from {url} to {dest_path}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as response, open(dest_path, "wb") as out_file:
        data = response.read()
        out_file.write(data)
    logger.info(f"Saved {dest_path} ({os.path.getsize(dest_path):,} bytes)")

def main():
    for d in DATA_DIRS:
        os.makedirs(d, exist_ok=True)

    target_dir = DATA_DIRS[0]
    clamp_path = os.path.join(target_dir, "clamp_integrated.csv")
    daproj_path = os.path.join(target_dir, "daproj_headers.csv")

    if not os.path.exists(clamp_path) or os.path.getsize(clamp_path) < 1000:
        download_file(CLAMP_URL, clamp_path)
    else:
        logger.info(f"ClaMP dataset already exists at {clamp_path}")

    if not os.path.exists(daproj_path) or os.path.getsize(daproj_path) < 1000:
        download_file(DAPROJ_HEADER_URL, daproj_path)
    else:
        logger.info(f"DA-Proj dataset already exists at {daproj_path}")

    # Copy to backend ml datasets dir as well
    backend_data_dir = DATA_DIRS[1]
    import shutil
    shutil.copy2(clamp_path, os.path.join(backend_data_dir, "clamp_integrated.csv"))
    shutil.copy2(daproj_path, os.path.join(backend_data_dir, "daproj_headers.csv"))
    logger.info("Datasets synced to backend/app/ml/datasets/")

if __name__ == "__main__":
    main()
