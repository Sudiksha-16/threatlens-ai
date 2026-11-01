import os
import json
import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from backend.app.config.settings import settings

logger = logging.getLogger("threatlens.database")

class Database:
    client: AsyncIOMotorClient = None
    db: AsyncIOMotorDatabase = None

db_instance = Database()

async def get_database() -> AsyncIOMotorDatabase:
    return db_instance.db

async def connect_to_mongo():
    logger.info(f"Connecting to MongoDB at {settings.MONGODB_URL}...")
    try:
        db_instance.client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=5000
        )
        db_instance.db = db_instance.client[settings.DATABASE_NAME]
        # Ping database
        await db_instance.client.admin.command('ping')
        logger.info(f"Connected to MongoDB database '{settings.DATABASE_NAME}' successfully!")
        
        await create_indexes()
        await seed_model_registry()
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        # Note: server may still start, but DB queries will fail until mongod is started

async def close_mongo_connection():
    if db_instance.client:
        logger.info("Closing MongoDB connection...")
        db_instance.client.close()

async def create_indexes():
    if db_instance.db is None:
        return
    try:
        # Users indexes
        await db_instance.db.users.create_index("email", unique=True)
        
        # Scans indexes
        await db_instance.db.scans.create_index([("user_id", 1), ("created_at", -1)])
        await db_instance.db.scans.create_index("scan_id", unique=True)
        await db_instance.db.scans.create_index("file_hash")
        await db_instance.db.scans.create_index("risk_level")
        await db_instance.db.scans.create_index("classification")
        
        # Scan Results indexes
        await db_instance.db.scan_results.create_index("scan_id", unique=True)
        
        # Alerts indexes
        await db_instance.db.alerts.create_index([("user_id", 1), ("read_status", 1)])
        await db_instance.db.alerts.create_index("alert_id", unique=True)
        await db_instance.db.alerts.create_index("scan_id")
        
        # Reports indexes
        await db_instance.db.reports.create_index("scan_id")
        
        # Model Registry indexes
        await db_instance.db.model_registry.create_index("model_name")
        await db_instance.db.model_registry.create_index("active_status")

        # Audit Logs indexes
        await db_instance.db.audit_logs.create_index([("user_id", 1), ("timestamp", -1)])
        
        logger.info("MongoDB indexes verified and created successfully.")
    except Exception as e:
        logger.warning(f"Error creating MongoDB indexes: {e}")

async def seed_model_registry():
    if db_instance.db is None:
        return
    try:
        count = await db_instance.db.model_registry.count_documents({})
        if count == 0:
            meta_path = os.path.join(settings.ML_MODELS_DIR, "model_metadata.json")
            if os.path.exists(meta_path):
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                
                # Active model
                active_entry = {
                    "model_name": meta.get("active_model", "Random_Forest"),
                    "model_version": meta.get("version", "1.0.0"),
                    "model_type": "Binary Classifier (Benign vs Malicious)",
                    "dataset_name": meta.get("dataset_name", "ClaMP Integrated PE Dataset"),
                    "training_records": meta.get("training_records", 5207),
                    "feature_names": meta.get("num_features", 69),
                    "evaluation_metrics": meta.get("models_comparison", {}).get(meta.get("active_model", "Random_Forest"), {}),
                    "model_location": os.path.join(settings.ML_MODELS_DIR, "active_binary_model.joblib"),
                    "training_date": meta.get("training_date", ""),
                    "active_status": True
                }
                await db_instance.db.model_registry.insert_one(active_entry)
                
                # Seed other models
                for m_name, m_metrics in meta.get("models_comparison", {}).items():
                    if m_name != meta.get("active_model"):
                        entry = {
                            "model_name": m_name,
                            "model_version": meta.get("version", "1.0.0"),
                            "model_type": "Binary Classifier Candidate",
                            "dataset_name": meta.get("dataset_name"),
                            "training_records": meta.get("training_records"),
                            "feature_names": meta.get("num_features"),
                            "evaluation_metrics": m_metrics,
                            "model_location": os.path.join(settings.ML_MODELS_DIR, f"{m_name.lower()}.joblib"),
                            "training_date": meta.get("training_date", ""),
                            "active_status": False
                        }
                        await db_instance.db.model_registry.insert_one(entry)
                logger.info("Seeded model_registry with trained models and metrics.")
    except Exception as e:
        logger.warning(f"Error seeding model registry: {e}")

