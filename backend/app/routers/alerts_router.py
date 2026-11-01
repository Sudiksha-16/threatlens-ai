from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.app.database.mongodb import get_database
from backend.app.models.alert import AlertResponse, AlertUpdate
from backend.app.security.authentication import get_current_user

router = APIRouter(prefix="/alerts", tags=["Alerts & Notifications"])

@router.get("")
async def get_alerts(
    read_status: Optional[bool] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user_id = current_user.get("user_id", current_user.get("_id"))
    query = {"user_id": user_id}

    if read_status is not None:
        query["read_status"] = read_status

    if severity and severity != "ALL":
        query["severity"] = severity

    total = await db.alerts.count_documents(query)
    unread_count = await db.alerts.count_documents({"user_id": user_id, "read_status": False})

    cursor = db.alerts.find(query).sort("created_at", -1).limit(limit)
    alerts = await cursor.to_list(length=limit)

    for a in alerts:
        a["_id"] = str(a["_id"])

    return {
        "total": total,
        "unread_count": unread_count,
        "alerts": alerts
    }

@router.put("/{alert_id}/read")
async def mark_alert_read(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user_id = current_user.get("user_id", current_user.get("_id"))
    res = await db.alerts.update_one(
        {"alert_id": alert_id, "user_id": user_id},
        {"$set": {"read_status": True}}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"message": "Alert marked as read"}

@router.put("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user_id = current_user.get("user_id", current_user.get("_id"))
    res = await db.alerts.update_one(
        {"alert_id": alert_id, "user_id": user_id},
        {"$set": {"resolution_status": True, "read_status": True}}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"message": "Alert marked as resolved"}

@router.put("/read-all")
async def mark_all_read(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user_id = current_user.get("user_id", current_user.get("_id"))
    await db.alerts.update_many({"user_id": user_id}, {"$set": {"read_status": True}})
    return {"message": "All alerts marked as read"}
