from fastapi import APIRouter, Depends, HTTPException
from .models import ConfigCreate
from .database import configs_collection
from .auth import get_current_user
from bson import ObjectId

router = APIRouter()

@router.post("/")
def upload_config(config: ConfigCreate, user=Depends(get_current_user)):
    config_doc = {
        "user_id": user["user_id"],
        "game": config.game,
        "title": config.title,
        "description": config.description,
        "parameters": config.parameters,
        "tags": config.tags,
    }
    result = configs_collection.insert_one(config_doc)
    return {"msg": "Configurazione caricata", "id": str(result.inserted_id)}

@router.get("/{config_id}")
def get_config(config_id: str):
    config = configs_collection.find_one({"_id": ObjectId(config_id)})
    if not config:
        raise HTTPException(status_code=404, detail="Configurazione non trovata")
    config["_id"] = str(config["_id"])
    return config

@router.get("/")
def search_configs(game: str = None):
    query = {"game": {"$regex": game, "$options": "i"}} if game else {}
    configs = list(configs_collection.find(query).limit(10))
    for c in configs:
        c["_id"] = str(c["_id"])
    return configs
