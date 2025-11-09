# mongo_exec.py
import os
import json
import urllib.parse
import azure.functions as func
from pydantic import BaseModel, Field, validator
from typing import Optional, Any, Dict, Tuple, List

from . import app, logger
from .keyvault import _kv_get
from .settings import (
    MONGO_AUTH_PREFERENCE, MONGO_URI_SECRET_NAME,
    MONGO_USERNAME_SECRET_NAME, MONGO_PASSWORD_SECRET_NAME,
    MONGO_HOST, MONGO_HOST_SECRET_NAME, MONGO_SCHEME, MONGO_AUTH_DB,
    MONGO_OPTIONS, MONGO_TLS, MONGO_PORTS
)

# pymongo opzionale (gestito a runtime)
try:
    from pymongo import MongoClient
    from pymongo.cursor import Cursor
    from pymongo.command_cursor import CommandCursor
    from pymongo.results import (
        InsertOneResult, InsertManyResult, UpdateResult, DeleteResult, BulkWriteResult
    )
except Exception:
    MongoClient = None
    Cursor = CommandCursor = tuple()
    InsertOneResult = InsertManyResult = UpdateResult = DeleteResult = BulkWriteResult = tuple()


class MongoExecRequest(BaseModel):
    # Parametri controllati dall'LLM
    database: str = Field(..., description="Nome database su cui eseguire il comando")
    host: Optional[str] = Field(None, description="Hostname o lista separata da virgole (override)")
    ports: Optional[str] = Field(None, description="Porta o lista separata da virgole (override, solo schema 'mongodb')")
    command: Any = Field(..., description="Comando MongoDB da eseguire (JSON). Nessun guardrail lato server.")
    timeout_sec: Optional[float] = Field(120.0, description="Timeout in secondi")
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout(cls, v):
        return 120.0 if v is None else max(1.0, float(v))


def _kv_safe_get(name: Optional[str]) -> str:
    return _kv_get(name) or "" if name else ""


def _get_mongo_host_from_env_or_kv() -> str:
    return MONGO_HOST or _kv_safe_get(MONGO_HOST_SECRET_NAME)


def _infer_scheme(host: str) -> str:
    return "mongodb+srv" if ".mongodb.net" in (host or "").lower() else "mongodb"


def _resolve_scheme(host: str) -> str:
    return MONGO_SCHEME or _infer_scheme(host)


def _apply_ports(host_csv: str, ports_csv: str, scheme: str) -> str:
    """
    Applica porte solo per schema 'mongodb'.
    Regole:
      - host singolo + N porte -> host:porta1, host:porta2, ...
      - N host + N porte -> pairing posizionale
      - N host + 1 porta -> applica la porta a tutti gli host senza porta
      - Altrimenti -> host invariato
    """
    if scheme != "mongodb":
        return host_csv

    host_csv = (host_csv or "").strip()
    ports_csv = (ports_csv or "").strip()
    if not host_csv or not ports_csv:
        return host_csv

    hosts = [h.strip() for h in host_csv.split(",") if h.strip()]
    ports = [p.strip() for p in ports_csv.split(",") if p.strip()]
    if not hosts:
        return host_csv

    def has_port(seg: str) -> bool:
        if ":" not in seg:
            return False
        last = seg.rsplit(":", 1)[-1]
        return last.isdigit()

    if len(hosts) == 1 and len(ports) > 1:
        base = hosts[0].split(":")[0]
        return ",".join(f"{base}:{p}" for p in ports)

    if len(hosts) == len(ports):
        out = []
        for h, p in zip(hosts, ports):
            if has_port(h):
                out.append(h)
            else:
                out.append(f"{h.split(':')[0]}:{p}")
        return ",".join(out)

    if len(ports) == 1:
        p = ports[0]
        out = []
        for h in hosts:
            if has_port(h):
                out.append(h)
            else:
                out.append(f"{h.split(':')[0]}:{p}")
        return ",".join(out)

    return host_csv


def _build_uri_and_meta(username: str, password: str, host: str, ports: str) -> Tuple[str, str, str]:
    """
    Ritorna (uri, scheme, host_final).
    - Normalizza MONGO_OPTIONS (sostituisce &amp; con &)
    - Imposta tls=true per schema 'mongodb' se MONGO_TLS true e non già presente
    """
    scheme = _resolve_scheme(host)
    host_final = _apply_ports(host, ports, scheme)

    u = urllib.parse.quote_plus(username)
    p = urllib.parse.quote_plus(password)
    options = (MONGO_OPTIONS or "").replace("&amp;", "&").strip()
    if options and not options.startswith("?"):
        options = "?" + options
    if scheme == "mongodb" and MONGO_TLS and "tls=" not in options and "ssl=" not in options:
        sep = "&" if "?" in options else "?"
        options += f"{sep}tls=true"
    uri = f"{scheme}://{u}:{p}@{host_final}/{MONGO_AUTH_DB}{options}"
    return uri, scheme, host_final


def _select_auth_uri(host_override: Optional[str], ports_override: Optional[str]) -> Tuple[str, str, str, str]:
    """
    Seleziona auth/URI in base a MONGO_AUTH_PREFERENCE.
    Ritorna: (auth_mode, uri, scheme, host_final)
    """
    pref = (MONGO_AUTH_PREFERENCE or "auto").lower()
    usr = _kv_safe_get(MONGO_USERNAME_SECRET_NAME)
    pwd = _kv_safe_get(MONGO_PASSWORD_SECRET_NAME)
    host_base = host_override or _get_mongo_host_from_env_or_kv()
    ports = ports_override or MONGO_PORTS

    if pref == "userpass":
        if not (usr and pwd and host_base):
            raise RuntimeError("MONGO_AUTH_PREFERENCE=userpass ma username/password/host non disponibili")
        uri, scheme, host_final = _build_uri_and_meta(usr, pwd, host_base, ports)
        return "userpass", uri, scheme, host_final

    if pref == "uri":
        uri = _kv_safe_get(MONGO_URI_SECRET_NAME)
        if not uri:
            raise RuntimeError("MONGO_AUTH_PREFERENCE=uri ma la URI non è disponibile")
        # Best-effort per ricavare scheme+host_final (solo per meta)
        scheme = "mongodb+srv" if uri.startswith("mongodb+srv://") else "mongodb"
        host_final = host_base or "<from-uri>"
        return "uri", uri, scheme, host_final

    # auto
    if usr and pwd and host_base:
        uri, scheme, host_final = _build_uri_and_meta(usr, pwd, host_base, ports)
        return "userpass", uri, scheme, host_final

    uri = _kv_safe_get(MONGO_URI_SECRET_NAME)
    if uri:
        scheme = "mongodb+srv" if uri.startswith("mongodb+srv://") else "mongodb"
        host_final = host_base or "<from-uri>"
        return "uri", uri, scheme, host_final

    raise RuntimeError("Nessuna credenziale disponibile (userpass/uri)")


def _serialize_result(res: Any) -> Any:
    """Serializza risultati PyMongo (cursor, write results, ecc.)."""
    # Cursor
    if isinstance(res, (Cursor, CommandCursor)):
        return list(res)

    # Write results
    if isinstance(res, InsertOneResult):
        return {"inserted_id": res.inserted_id}
    if isinstance(res, InsertManyResult):
        return {"inserted_ids": res.inserted_ids}
    if isinstance(res, UpdateResult):
        return {
            "acknowledged": res.acknowledged,
            "matched_count": res.matched_count,
            "modified_count": res.modified_count,
            "upserted_id": res.upserted_id
        }
    if isinstance(res, DeleteResult):
        return {
            "acknowledged": res.acknowledged,
            "deleted_count": res.deleted_count
        }
    if isinstance(res, BulkWriteResult):
        return {
            "acknowledged": res.acknowledged,
            "inserted_count": res.inserted_count,
            "matched_count": res.matched_count,
            "modified_count": res.modified_count,
            "deleted_count": res.deleted_count,
            "upserted_count": res.upserted_count,
            "upserted_ids": res.upserted_ids
        }

    # Oggetti con raw_result
    raw = getattr(res, "raw_result", None)
    if raw is not None:
        return raw

    # Qualsiasi altra cosa (scalar/dict/list)
    return res


@app.route(route="mongo/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def mongo_exec(req: func.HttpRequest) -> func.HttpResponse:
    """
    Esegue un comando MongoDB SENZA guardrail lato server.
    Payload:
    {
      "database": "<db>",
      "host": "<host[,host2,...]>",          # opzionale (override)
      "ports": "<27017[,27018,...]>",        # opzionale (override; solo schema 'mongodb')
      "command": <JSON>,                     # db.command(dict) oppure invocazione generica
      "timeout_sec": 120,
      "correlation_id": "<opzionale>"
    }

    Modalità 'command':
      1) db.command(dict) — se 'command' è un dict senza 'target'/'name'
      2) invocazione generica:
         {
           "target": "client" | "db" | "collection",
           "name": "<metodo pymongo>",
           "collection": "<nome>",      # richiesto se target=collection
           "args": [ ... ],
           "kwargs": { ... }
         }
    """
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    corr_id = request_id

    if MongoClient is None:
        logger.error("pymongo non installato nel runtime")
        return func.HttpResponse(
            json.dumps({"error": "MissingDependency", "message": "pymongo non installato", "request_id": request_id}),
            status_code=500, mimetype="application/json"
        )

    # Parse body
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse(
            json.dumps({"error": "BadRequest", "message": "Corpo JSON non valido", "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    try:
        data = MongoExecRequest(**body)
        if data.correlation_id:
            corr_id = data.correlation_id
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    # Selezione URI
    try:
        auth_mode, uri, scheme, host_final = _select_auth_uri(data.host, data.ports)
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "AuthError", "message": str(e), "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    # Connessione
    try:
        server_selection_ms = int(min(float(data.timeout_sec) * 1000, 30000))
        client = MongoClient(uri, serverSelectionTimeoutMS=server_selection_ms)
        db = client[data.database]
    except Exception as e:
        logger.exception("Errore creazione client Mongo")
        return func.HttpResponse(
            json.dumps({"error": "MongoClientError", "message": str(e), "request_id": request_id}),
            status_code=500, mimetype="application/json"
        )

    # Esecuzione comando
    try:
        cmd = data.command
        if isinstance(cmd, str):
            cmd = json.loads(cmd)

        # Caso 1: db.command(dict)
        if isinstance(cmd, dict) and "target" not in cmd and "name" not in cmd:
            res = db.command(cmd)
            out = _serialize_result(res)
            return func.HttpResponse(
                json.dumps({
                    "result": out,
                    "auth_mode": auth_mode,
                    "scheme": scheme,
                    "host": host_final,
                    "request_id": request_id,
                    "correlation_id": corr_id,
                    "executed": {"mode": "db.command"}
                }, default=str),
                status_code=200, mimetype="application/json"
            )

        # Caso 2: invocazione generica
        if not isinstance(cmd, dict):
            return func.HttpResponse(
                json.dumps({"error": "BadCommand", "message": "command deve essere un oggetto JSON o stringa JSON", "request_id": request_id}),
                status_code=400, mimetype="application/json"
            )

        target = (cmd.get("target") or "db").lower()
        name = cmd.get("name")
        args = cmd.get("args") or []
        kwargs = cmd.get("kwargs") or {}

        if target == "client":
            obj = client
        elif target == "db":
            obj = db
        elif target == "collection":
            coll = cmd.get("collection")
            if not coll:
                return func.HttpResponse(
                    json.dumps({"error": "BadCommand", "message": "target=collection richiede 'collection'", "request_id": request_id}),
                    status_code=400, mimetype="application/json"
                )
            obj = db[coll]
        else:
            return func.HttpResponse(
                json.dumps({"error": "BadCommand", "message": f"target sconosciuto: {target}", "request_id": request_id}),
                status_code=400, mimetype="application/json"
            )

        if not name:
            return func.HttpResponse(
                json.dumps({"error": "BadCommand", "message": "Manca 'name' del metodo da invocare", "request_id": request_id}),
                status_code=400, mimetype="application/json"
            )

        meth = getattr(obj, name)
        res = meth(*args, **kwargs)
        out = _serialize_result(res)

        return func.HttpResponse(
            json.dumps({
                "result": out,
                "auth_mode": auth_mode,
                "scheme": scheme,
                "host": host_final,
                "request_id": request_id,
                "correlation_id": corr_id,
                "executed": {"mode": "call", "target": target, "name": name}
            }, default=str),
            status_code=200, mimetype="application/json"
        )

    except Exception as e:
        logger.exception("Errore esecuzione comando Mongo")
        return func.HttpResponse(
            json.dumps({"error": "MongoError", "message": str(e), "request_id": request_id}),
            status_code=500, mimetype="application/json"
        )