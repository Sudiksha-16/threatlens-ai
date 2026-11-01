"""
ThreatLens AI - Dataset Exploration (EDA)
Performs dataset inspection, missing-value analysis, duplicate checks,
class distributions, and summary statistics.
"""

import os
import json
import pandas as pd
import numpy as np

def explore():
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    clamp_path = os.path.join(data_dir, "clamp_integrated.csv")
    daproj_path = os.path.join(data_dir, "daproj_headers.csv")

    report = {"clamp": {}, "daproj": {}}

    print("=" * 60)
    print("EXPLORING CLAMP DATASET (Binary Classification: Benign vs Malicious)")
    print("=" * 60)
    df_clamp = pd.read_csv(clamp_path)
    print(f"ClaMP Shape: {df_clamp.shape} (Rows: {df_clamp.shape[0]}, Features: {df_clamp.shape[1]})")
    
    # Missing values
    missing_clamp = df_clamp.isnull().sum().to_dict()
    total_missing_clamp = int(df_clamp.isnull().sum().sum())
    print(f"Total missing values in ClaMP: {total_missing_clamp}")
    
    # Class balance
    class_dist = df_clamp['class'].value_counts().to_dict()
    print(f"Class Distribution: {class_dist} (0 = Benign: {class_dist.get(0, 0)}, 1 = Malicious: {class_dist.get(1, 0)})")
    
    # Duplicate check
    duplicates_clamp = int(df_clamp.duplicated().sum())
    print(f"Duplicate rows in ClaMP: {duplicates_clamp}")
    
    report["clamp"] = {
        "rows": int(df_clamp.shape[0]),
        "features": int(df_clamp.shape[1]),
        "missing_values": total_missing_clamp,
        "duplicates": duplicates_clamp,
        "class_distribution": {str(k): int(v) for k, v in class_dist.items()},
        "columns": df_clamp.columns.tolist()
    }

    print("\n" + "=" * 60)
    print("EXPLORING DA-PROJ DATASET (Multiclass Malware Families)")
    print("=" * 60)
    df_daproj = pd.read_csv(daproj_path, encoding='utf-8-sig')
    print(f"DA-Proj Shape: {df_daproj.shape} (Rows: {df_daproj.shape[0]}, Features: {df_daproj.shape[1]})")
    
    family_dist = df_daproj['Malware_Type'].value_counts().to_dict()
    print(f"Malware Families Distribution:\n{df_daproj['Malware_Type'].value_counts()}")
    total_missing_daproj = int(df_daproj.isnull().sum().sum())
    duplicates_daproj = int(df_daproj.duplicated().sum())
    
    report["daproj"] = {
        "rows": int(df_daproj.shape[0]),
        "features": int(df_daproj.shape[1]),
        "missing_values": total_missing_daproj,
        "duplicates": duplicates_daproj,
        "family_distribution": {str(k): int(v) for k, v in family_dist.items()},
        "columns": df_daproj.columns.tolist()
    }

    # Save summary report to JSON
    report_path = os.path.join(data_dir, "eda_summary.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved EDA Summary to {report_path}")

if __name__ == "__main__":
    explore()
