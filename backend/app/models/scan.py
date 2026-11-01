
from datetime import datetime
from typing import Optional, List, Dict, Any, Literal

from pydantic import BaseModel, Field, ConfigDict


class ScanCreateRequest(BaseModel):
    scan_mode: Literal["standard", "deep"] = Field(
        default="standard",
        description="Scan mode: standard or deep",
    )


class StaticFeatures(BaseModel):
    model_config = ConfigDict(extra="allow")

    file_name: str = "Unknown"
    file_size: int = Field(default=0, ge=0)
    file_type: str = "Unknown"
    sha256: str = ""
    md5: str = ""
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    is_pe: bool = False
    magic_info: str = "Unknown"

    pe_headers: Optional[Dict[str, Any]] = None
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    imported_apis: List[str] = Field(default_factory=list)
    embedded_urls: List[str] = Field(default_factory=list)
    embedded_ips: List[str] = Field(default_factory=list)
    suspicious_strings: List[str] = Field(default_factory=list)
    obfuscation_indicators: List[str] = Field(default_factory=list)


class YaraMatch(BaseModel):
    model_config = ConfigDict(extra="allow")

    rule_name: str
    category: str = "Unknown"
    severity: str = "Low"
    tags: List[str] = Field(default_factory=list)
    description: str = ""


class MLPrediction(BaseModel):
    model_config = ConfigDict(extra="allow")

    classification: Literal["Benign", "Malicious"]
    is_malicious: bool
    confidence: float = Field(ge=0.0, le=1.0)
    class_probabilities: Dict[str, float] = Field(
        default_factory=dict
    )
    malware_family: Optional[str] = None
    model_name: str = "Unknown"
    model_version: str = "Unknown"


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="allow")

    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["Low", "Medium", "High", "Critical"]
    reasons: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(
        default_factory=list
    )


class VirusTotalResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    used_fallback: bool = False
    status: str = "UNKNOWN"
    positives: int = Field(default=0, ge=0)
    total_engines: int = Field(default=0, ge=0)
    permalink: Optional[str] = None
    scans: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str
    file_name: str
    file_hash: str
    file_size: int
    file_type: str
    scan_mode: Literal["standard", "deep"] = "standard"
    scan_status: str = "COMPLETED"

    # Unclassified is valid when neither analysis source
    # can establish a conclusive result.
    classification: Literal[
        "Benign",
        "Malicious",
        "Unclassified",
    ]

    malware_family: Optional[str] = None

    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["Low", "Medium", "High", "Critical"]

    result_source: str = "No conclusive result"
    model_version: str = "N/A"

    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanDetailResponse(ScanResponse):
    static_analysis: StaticFeatures = Field(
        default_factory=StaticFeatures
    )

    yara_results: List[YaraMatch] = Field(
        default_factory=list
    )

    ml_prediction: Optional[MLPrediction] = None

    risk_assessment: RiskAssessment

    virustotal: Optional[VirusTotalResult] = None

    processing_errors: Optional[List[str]] = None