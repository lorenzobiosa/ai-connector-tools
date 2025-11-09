import os
import re
import json
import time
import urllib.parse
import azure.functions as func
from pydantic import BaseModel, Field, validator

from typing import Optional

from function_app import app, logger
from keyvault import _kv_get
from settings import (
    MONGO_AUTH_PREFERENCE, MONGO_URI_SECRET_NAME,
    MONGO_USERNAME_SECRET_NAME, MONGO_PASSWORD_SECRET_NAME,
    MONGO_HOST, MONGO_HOST_SECRET_NAME, MONGO_SCHEME, MONGO_AUTH_DB,
    MONGO_OPTIONS, MONGO_TLS
)

# pymongo opzionale (gestito a runtime)
try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None

# ======= Modello =======
class MongoExecRequest(BaseModel):
    uri: Optional[str] = Field(None, description="Connection string MongoDB (se non fornita verrà letta da Key Vault)")
    database: str = Field(..., description="Nome database")
    script: str = Field(..., description="Script JSON serializzato: {collection, operation, ...}")
    auth_method: Optional[str] = Field(None, description="userpass|uri|auto")
    timeout_sec: Optional[float] = Field(120.0, description="Timeout in secondi")
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout_mongo(cls, v):
        if v is None:
            return 120.0
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v

# ======= Helpers =======
def _choose_mongo_auth_method(uri: str, usr: str, pwd: str, host: str) -> str:
    pref = MONGO_AUTH_PREFERENCE if MONGO_AUTH_PREFERENCE in ("userpass", "uri", "auto") else "auto"
    if pref == "userpass":
        if usr and pwd and host:
            return "userpass"
        raise RuntimeError("MONGO_AUTH_PREFERENCE=userpass ma mancano username/password/host")
    if pref == "uri":
        if uri:
            return "uri"
        raise RuntimeError("MONGO_AUTH_PREFERENCE=uri ma URI non disponibile")
    if usr and pwd and host:
        return "userpass"
    if uri:
        return "uri"
    raise RuntimeError("Nessuna credenziale Mongo disponibile")

def _get_mongo_host() -> str:
    if MONGO_HOST:
        return MONGO_HOST
    if MONGO_HOST_SECRET_NAME:
        return _kv_get(MONGO_HOST_SECRET_NAME)
    return ""

def _build_mongo_uri_from_userpass(username: str, password: str, host: str) -> str:
    if not (username and password and host):
        raise ValueError("username, password e host richiesti per userpass")
    u = urllib.parse.quote_plus(username)
    p = urllib.parse.quote_plus(password)
    scheme = MONGO_SCHEME or "mongodb+srv"
    auth_db = MONGO_AUTH_DB or "admin"
    options = (MONGO_OPTIONS or "").strip()
    if options and not options.startswith("?"):
        options = "?" + options
    if scheme == "mongodb" and MONGO_TLS:
        if options:
            if "tls=" not in options and "ssl=" not in options:
                sep = "&" if "?" in options else "?"
                options = options + f"{sep}tls=true"
        else:
            options = "?tls=true"
    return f"{scheme}://{u}:{p}@{host}/{auth_db}{options}"

# ======= Route =======
@app.route(route="mongo/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def mongo_exec(req: func.HttpRequest) -> func.HttpResponse:
    """
    Esegue operazioni MongoDB tramite pymongo.
    script: JSON serializzato (find/distinct/aggregate)
    """
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse(json.dumps({"error": "BadRequest", "message": "Corpo JSON non valido", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    try:
        data = MongoExecRequest(**body)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    uri = data.uri or ""
    if not uri and MONGO_URI_SECRET_NAME:
        try:
            uri = _kv_get(MONGO_URI_SECRET_NAME) or ""
        except Exception as e:
            logger.exception("Errore lettura MONGO uri da KeyVault: %s", e)
            return func.HttpResponse(json.dumps({"error": "KVError", "message": str(e), "request_id": request_id}),
                                     status_code=500, mimetype="application/json")

    usr = ""
    pwd = ""
    try:
        if MONGO_USERNAME_SECRET_NAME:
            usr = _kv_get(MONGO_USERNAME_SECRET_NAME) or ""
        if MONGO_PASSWORD_SECRET_NAME:
            pwd = _kv_get(MONGO_PASSWORD_SECRET_NAME) or ""
    except Exception as e:
        logger.exception("Errore lettura MONGO user/password da KeyVault: %s", e)
        return func.HttpResponse(json.dumps({"error": "KVError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    try:
        host = _get_mongo_host() or ""
    except Exception as e:
        logger.exception("Errore lettura MONGO host: %s", e)
        return func.HttpResponse(json.dumps({"error": "KVError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    try:
        method = (data.auth_method or "").lower() if data.auth_method else _choose_mongo_auth_method(uri, usr, pwd, host)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "AuthSelectionError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    if method == "userpass":
        try:
            final_uri = _build_mongo_uri_from_userpass(usr, pwd, host)
        except Exception as e:
            return func.HttpResponse(json.dumps({"error": "UriBuildError", "message": str(e), "request_id": request_id}),
                                     status_code=400, mimetype="application/json")
    elif method == "uri":
        if not uri:
            return func.HttpResponse(json.dumps({"error": "MissingUri", "message": "Nessuna URI MongoDB disponibile", "request_id": request_id}),
                                     status_code=400, mimetype="application/json")
        final_uri = uri
    else:
        return func.HttpResponse(json.dumps({"error": "BadAuthMethod", "message": f"auth_method non valido: {method}", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    if MongoClient is None:
        logger.error("pymongo non installato nel sistema runtime")
        return func.HttpResponse(json.dumps({"error": "MissingDependency", "message": "pymongo non installato sul runtime", "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    try:
        script_json = json.loads(data.script)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ScriptParseError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    collection = script_json.get("collection")
    operation = script_json.get("operation")
    if not collection or not operation:
        return func.HttpResponse(json.dumps({"error": "BadScript", "message": "script JSON deve contenere 'collection' e 'operation'", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    try:
        client = MongoClient(final_uri, serverSelectionTimeoutMS=int(min((data.timeout_sec or 120.0) * 1000, 30000)))
        db = client[data.database]
        col = db[collection]

        if operation == "find":
            filt = script_json.get("filter", {})
            results = list(col.find(filt))
            return func.HttpResponse(json.dumps({"result": results, "auth_mode": method, "request_id": request_id}, default=str),
                                     status_code=200, mimetype="application/json")
        elif operation == "distinct":
            field = script_json.get("field")
            if not field:
                return func.HttpResponse(json.dumps({"error": "BadScript", "message": "distinct richiede 'field'", "request_id": request_id}),
                                         status_code=400, mimetype="application/json")
            filt = script_json.get("filter", {})
            results = col.distinct(field, filt)
            return func.HttpResponse(json.dumps({"result": results, "auth_mode": method, "request_id": request_id}, default=str),
                                     status_code=200, mimetype="application/json")
        elif operation == "aggregate":
            pipeline = script_json.get("pipeline", [])
            results = list(col.aggregate(pipeline))
            return func.HttpResponse(json.dumps({"result": results, "auth_mode": method, "request_id": request_id}, default=str),
                                     status_code=200, mimetype="application/json")
        else:
            return func.HttpResponse(json.dumps({"error": "UnsupportedOperation", "message": f"Operazione non supportata: {operation}", "request_id": request_id}),
                                     status_code=400, mimetype="application/json")

    except Exception as e:
        logger.exception("Errore esecuzione mongo operation")
        return func.HttpResponse(json.dumps({"error": "MongoError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")