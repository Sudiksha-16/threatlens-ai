

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.database.mongodb import get_database
from backend.app.security.authentication import get_current_user


router = APIRouter(
    prefix="/analytics",
    tags=["Malware Analytics"],
)


@router.get("")
async def get_analytics(
    time_range: str = Query(
        "30d",
        pattern="^(24h|7d|30d|90d|all)$",
    ),
    severity: Optional[str] = None,
    classification: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

    user_id = current_user.get(
        "user_id",
        current_user.get("_id"),
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable",
        )

    query = {
        "user_id": user_id,
    }

    now = datetime.now(timezone.utc)

    # Apply selected date range.
    if time_range == "24h":
        query["created_at"] = {
            "$gte": now - timedelta(hours=24)
        }

    elif time_range == "7d":
        query["created_at"] = {
            "$gte": now - timedelta(days=7)
        }

    elif time_range == "30d":
        query["created_at"] = {
            "$gte": now - timedelta(days=30)
        }

    elif time_range == "90d":
        query["created_at"] = {
            "$gte": now - timedelta(days=90)
        }

    # Apply optional filters.
    if severity and severity.upper() != "ALL":
        query["risk_level"] = severity.capitalize()

    if classification and classification.upper() != "ALL":
        query["classification"] = classification.capitalize()

    # Get scan IDs matching the selected filters.
    # These IDs are used to keep scan_results analytics in sync
    # with the selected dashboard filters.
    matching_scan_ids = await db.scans.distinct(
        "scan_id",
        query,
    )

    # 1. Total scans.
    total_scans = await db.scans.count_documents(query)

    # 2. Benign vs Malicious distribution.
    p_class = [
        {"$match": query},
        {
            "$group": {
                "_id": "$classification",
                "count": {"$sum": 1},
            }
        },
    ]

    res_class = await db.scans.aggregate(
        p_class
    ).to_list(length=10)

    binary_dist = [
        {
            "name": r["_id"] or "Unknown",
            "count": r["count"],
        }
        for r in res_class
    ]

    # 3. Severity distribution.
    p_sev = [
        {"$match": query},
        {
            "$group": {
                "_id": "$risk_level",
                "count": {"$sum": 1},
            }
        },
    ]

    res_sev = await db.scans.aggregate(
        p_sev
    ).to_list(length=10)

    severity_dist = [
        {
            "level": r["_id"] or "Unknown",
            "count": r["count"],
        }
        for r in res_sev
    ]

    # 4. Malware family distribution.
    family_query = {
        **query,
        "classification": "Malicious",
    }

    p_fam = [
        {"$match": family_query},
        {
            "$group": {
                "_id": "$malware_family",
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
    ]

    res_fam = await db.scans.aggregate(
        p_fam
    ).to_list(length=15)

    family_dist = [
        {
            "family": r["_id"] or "Unknown",
            "count": r["count"],
        }
        for r in res_fam
    ]

    # 5. YARA rule frequencies.
    yara_frequency = []

    if matching_scan_ids:
        p_yara = [
            {
                "$match": {
                    "user_id": user_id,
                    "scan_id": {
                        "$in": matching_scan_ids
                    },
                }
            },
            {"$unwind": "$yara_results"},
            {
                "$group": {
                    "_id": "$yara_results.rule_name",
                    "count": {"$sum": 1},
                    "category": {
                        "$first": "$yara_results.category"
                    },
                }
            },
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ]

        res_yara = await db.scan_results.aggregate(
            p_yara
        ).to_list(length=10)

        yara_frequency = [
            {
                "rule": r["_id"],
                "count": r["count"],
                "category": r.get("category", ""),
            }
            for r in res_yara
        ]

    # 6. Common suspicious indicators.
    common_indicators = []

    if matching_scan_ids:
        p_ind = [
            {
                "$match": {
                    "user_id": user_id,
                    "scan_id": {
                        "$in": matching_scan_ids
                    },
                }
            },
            {
                "$unwind": "$risk_assessment.reasons"
            },
            {
                "$group": {
                    "_id": "$risk_assessment.reasons",
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"count": -1}},
            {"$limit": 8},
        ]

        res_ind = await db.scan_results.aggregate(
            p_ind
        ).to_list(length=8)

        common_indicators = [
            {
                "indicator": r["_id"],
                "count": r["count"],
            }
            for r in res_ind
        ]

    # 7. Scan activity trends.
    p_trends = [
        {"$match": query},
        {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$created_at",
                        "timezone": "UTC",
                    }
                },
                "total": {"$sum": 1},
                "malicious": {
                    "$sum": {
                        "$cond": [
                            {
                                "$eq": [
                                    "$classification",
                                    "Malicious",
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "benign": {
                    "$sum": {
                        "$cond": [
                            {
                                "$eq": [
                                    "$classification",
                                    "Benign",
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        },
        {"$sort": {"_id": 1}},
    ]

    # Avoid truncating 90-day and all-time results at 30 days.
    if time_range == "24h":
        p_trends.append({"$limit": 2})
    elif time_range == "7d":
        p_trends.append({"$limit": 7})
    elif time_range == "30d":
        p_trends.append({"$limit": 30})
    elif time_range == "90d":
        p_trends.append({"$limit": 90})
    else:
        p_trends.append({"$limit": 366})

    res_trends = await db.scans.aggregate(
        p_trends
    ).to_list(length=366)

    trends = [
        {
            "date": r["_id"],
            "total": r["total"],
            "malicious": r["malicious"],
            "benign": r["benign"],
        }
        for r in res_trends
    ]

    return {
        "total_scans": total_scans,
        "binary_distribution": binary_dist,
        "severity_distribution": severity_dist,
        "family_distribution": family_dist,
        "yara_rule_frequency": yara_frequency,
        "common_indicators": common_indicators,
        "trends": trends,
    }
