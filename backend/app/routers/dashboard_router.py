

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.database.mongodb import get_database
from backend.app.security.authentication import get_current_user


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


def get_time_filter(range_str: str) -> Optional[datetime]:
    """Return the UTC cutoff for the selected time range."""

    now = datetime.now(timezone.utc)

    if range_str == "24h":
        return now - timedelta(hours=24)

    elif range_str == "7d":
        return now - timedelta(days=7)

    elif range_str == "30d":
        return now - timedelta(days=30)

    elif range_str == "90d":
        return now - timedelta(days=90)

    return None


def build_scan_query(user_id: str, time_range: str) -> dict:
    """Build a user-specific scan query with an optional date filter."""

    query = {
        "user_id": user_id,
    }

    cutoff = get_time_filter(time_range)

    if cutoff:
        query["created_at"] = {
            "$gte": cutoff,
        }

    return query


def get_user_id(current_user: dict):
    """Extract and validate the authenticated user's ID."""

    user_id = current_user.get(
        "user_id",
        current_user.get("_id"),
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="User identity unavailable",
        )

    return user_id


@router.get("/stats")
async def get_dashboard_stats(
    time_range: str = Query(
        "30d",
        pattern="^(24h|7d|30d|90d|all)$",
    ),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

    user_id = get_user_id(current_user)

    query = build_scan_query(
        user_id,
        time_range,
    )

    # Aggregate statistics from MongoDB.
    total_scanned = await db.scans.count_documents(query)

    benign_count = await db.scans.count_documents({
        **query,
        "classification": "Benign",
    })

    malicious_count = await db.scans.count_documents({
        **query,
        "classification": "Malicious",
    })

    high_risk_count = await db.scans.count_documents({
        **query,
        "risk_level": "High",
    })

    critical_risk_count = await db.scans.count_documents({
        **query,
        "risk_level": "Critical",
    })

    # Fetch recent scans within the selected time range.
    recent_cursor = (
        db.scans
        .find(query)
        .sort("created_at", -1)
        .limit(5)
    )

    recent_scans = await recent_cursor.to_list(length=5)

    for scan in recent_scans:
        scan["_id"] = str(scan["_id"])

    return {
        "time_range": time_range,
        "total_files_scanned": total_scanned,
        "benign_files": benign_count,
        "malicious_files": malicious_count,
        "high_risk_threats": high_risk_count,
        "critical_threats": critical_risk_count,
        "recent_scans": recent_scans,
    }


@router.get("/charts")
async def get_dashboard_charts(
    time_range: str = Query(
        "30d",
        pattern="^(24h|7d|30d|90d|all)$",
    ),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable",
        )

    user_id = get_user_id(current_user)

    query = build_scan_query(
        user_id,
        time_range,
    )

    # 1. Classification Distribution.
    pipeline_class = [
        {"$match": query},
        {
            "$group": {
                "_id": "$classification",
                "count": {"$sum": 1},
            }
        },
    ]

    class_res = await db.scans.aggregate(
        pipeline_class
    ).to_list(length=10)

    classification_dist = [
        {
            "name": r["_id"] or "Unclassified",
            "value": r["count"],
        }
        for r in class_res
    ]

    # 2. Threat Severity Distribution.
    pipeline_sev = [
        {"$match": query},
        {
            "$group": {
                "_id": "$risk_level",
                "count": {"$sum": 1},
            }
        },
    ]

    sev_res = await db.scans.aggregate(
        pipeline_sev
    ).to_list(length=10)

    severity_dist = [
        {
            "name": r["_id"] or "Unknown",
            "value": r["count"],
        }
        for r in sev_res
    ]

    # 3. Malware Category Distribution.
    pipeline_cat = [
        {
            "$match": {
                **query,
                "classification": "Malicious",
            }
        },
        {
            "$group": {
                "_id": "$malware_family",
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
    ]

    cat_res = await db.scans.aggregate(
        pipeline_cat
    ).to_list(length=20)

    category_dist = [
        {
            "name": r["_id"] or "Unknown",
            "value": r["count"],
        }
        for r in cat_res
    ]

    # 4. Daily Scan Trends.
    pipeline_trends = [
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

    # Apply an appropriate limit for each time range.
    if time_range == "24h":
        pipeline_trends.append({"$limit": 2})

    elif time_range == "7d":
        pipeline_trends.append({"$limit": 7})

    elif time_range == "30d":
        pipeline_trends.append({"$limit": 30})

    elif time_range == "90d":
        pipeline_trends.append({"$limit": 90})

    else:
        pipeline_trends.append({"$limit": 366})

    trend_res = await db.scans.aggregate(
        pipeline_trends
    ).to_list(length=366)

    scan_trends = [
        {
            "date": r["_id"],
            "total": r["total"],
            "malicious": r["malicious"],
            "benign": r["benign"],
        }
        for r in trend_res
    ]

    return {
        "classification_distribution": classification_dist,
        "severity_distribution": severity_dist,
        "category_distribution": category_dist,
        "scan_trends": scan_trends,
    }
