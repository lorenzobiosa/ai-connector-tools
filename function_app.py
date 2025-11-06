import os
import io
import json
import time
import logging
import base64
import tempfile
import stat
import urllib.request
import re
import subprocess
from typing import Optional

import azure.functions as func
from pydantic import BaseModel, Field, validator
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import paramiko
import yaml

# =========================
# Configurazione (ENV VARS)
# =========================
APP_NAME = os.getenv("APP_NAME", "ai-foundry-ssh-tool")
KEY_VAULT_URL = os.getenv("KEY_VAULT_URL", "")  # es: https://my-kv.vault.azure.net/

# Secret names in Key Vault (VALORI = NOME DEL SECRET, non il contenuto)
SSH_USERNAME_SECRET_NAME = os.getenv("SSH_USERNAME_SECRET_NAME", "")
SSH_PASSWORD_SECRET_NAME = os.getenv("SSH_PASSWORD_SECRET_NAME", "")                   # opzionale
SSH_PRIVATE_KEY_SECRET_NAME = os.getenv("SSH_PRIVATE_KEY_SECRET_NAME", "")             # opzionale
SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME = os.getenv("SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME", "")  # opzionale

# K8s secret names
KUBE_CONFIG_SECRET_NAME = os.getenv("KUBE_CONFIG_SECRET_NAME", "")  # nome del secret contenente kubeconfig (yaml o base64)
KUBE_TOKEN_SECRET_NAME = os.getenv("KUBE_TOKEN_SECRET_NAME", "")
KUBE_USERNAME_SECRET_NAME = os.getenv("KUBE_USERNAME_SECRET_NAME", "")
KUBE_PASSWORD_SECRET_NAME = os.getenv("KUBE_PASSWORD_SECRET_NAME", "")

# Preferenza autenticazione SSH: "auto" (preferisce chiave se presente), "key", "password"
AUTH_PREFERENCE = os.getenv("AUTH_PREFERENCE", "auto").lower()

# Preferenza autenticazione Kubernetes: "auto" (sceglie kubeconfig > token > userpass)
K8S_AUTH_PREFERENCE = os.getenv("K8S_AUTH_PREFERENCE", "auto").lower()

# Host sconosciuti: per richiesta utente -> abilitato di default
ALLOW_UNKNOWN_HOSTS = os.getenv("ALLOW_UNKNOWN_HOSTS", "true").lower() == "true"

DEFAULT_PORT = int(os.getenv("SSH_DEFAULT_PORT", "22"))
CONNECT_TIMEOUT = float(os.getenv("SSH_CONNECT_TIMEOUT_SEC", "10"))
COMMAND_TIMEOUT = float(os.getenv("SSH_COMMAND_TIMEOUT_SEC", "300"))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", str(256 * 1024)))  # 256 KiB

# kubectl download config and paths (suitable for Premium App Service)
DEFAULT_KUBECTL_VERSION = os.getenv("DEFAULT_KUBECTL_VERSION", "v1.30.0")
KUBECTL_DOWNLOAD_URL_TEMPLATE = os.getenv("KUBECTL_DOWNLOAD_URL_TEMPLATE",
                                         "https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl")
KUBECTL_PATH_DEFAULT = os.getenv("KUBECTL_PATH", "/home/site/tools/kubectl")
KUBECTL_FALLBACK_PATH = os.getenv("KUBECTL_FALLBACK_PATH", "/tmp/kubectl")

# Azure Key Vault client (lazy init)
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)

credential = None
kv_client = None
if KEY_VAULT_URL:
    try:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        kv_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
    except Exception as e:
        raise RuntimeError("Key Vault client init failed: %s", e)

# =========================
# Helpers - Key Vault / Secrets
# =========================
def _kv_get(secret_name: str) -> str:
    if not secret_name:
        raise RuntimeError("Nome secret non configurato")
    if not kv_client:
        raise RuntimeError("KEY_VAULT_URL non configurato")
    try:
        return kv_client.get_secret(secret_name).value
    except Exception as e:
        raise RuntimeError("Errore lettura secret %s: %s", secret_name, e)

# =========================
# SSH Section
# =========================
class SSHRequest(BaseModel):
    host: str
    port: int = DEFAULT_PORT
    command: str  # obbligatorio
    timeout_sec: float = COMMAND_TIMEOUT
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout(cls, v):
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v

def _get_username() -> str:
    val = _kv_get(SSH_USERNAME_SECRET_NAME)
    if not val:
        raise RuntimeError("SSH username non configurato in Key Vault")
    return val

def _get_password() -> Optional[str]:
    if not SSH_PASSWORD_SECRET_NAME:
        return None
    return _kv_get(SSH_PASSWORD_SECRET_NAME) or None

def _get_private_key() -> Optional[tuple]:
    if not SSH_PRIVATE_KEY_SECRET_NAME:
        return None
    raw = _kv_get(SSH_PRIVATE_KEY_SECRET_NAME)
    if not raw:
        return None
    # detect pem vs base64
    pem = None
    try:
        if raw.strip().startswith("-----BEGIN"):
            pem = raw
        else:
            pem = base64.b64decode(raw).decode("utf-8")
    except Exception:
        pem = raw
    passphrase = _kv_get(SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME) if SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME else None
    return (pem, passphrase)

def _load_pkey(pem: str, passphrase: Optional[str]):
    # Prova RSA, poi ED25519
    try:
        return paramiko.RSAKey.from_private_key(io.StringIO(pem), password=passphrase)
    except Exception:
        try:
            return paramiko.Ed25519Key.from_private_key(io.StringIO(pem), password=passphrase)
        except Exception as e:
            raise RuntimeError("Chiave privata non valida o passphrase errata: %s" % e)

def _choose_auth():
    """Sceglie metodo auth SSH basato su AUTH_PREFERENCE e secret disponibili."""
    key_tuple = _get_private_key()
    pwd = _get_password()
    mode = AUTH_PREFERENCE if AUTH_PREFERENCE in ("auto", "key", "password") else "auto"
    if mode == "key":
        if not key_tuple:
            raise RuntimeError("AUTH_PREFERENCE=key ma la chiave non è configurata in Key Vault")
        pkey = _load_pkey(*key_tuple)
        return {"mode": "key", "pkey": pkey}
    if mode == "password":
        if not pwd:
            raise RuntimeError("AUTH_PREFERENCE=password ma la password non è configurata in Key Vault")
        return {"mode": "password", "password": pwd}
    # auto
    if key_tuple:
        pkey = _load_pkey(*key_tuple)
        return {"mode": "key", "pkey": pkey}
    if pwd:
        return {"mode": "password", "password": pwd}
    raise RuntimeError("Nessuna credenziale SSH configurata (né chiave né password)")

def _prepare_ssh_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if ALLOW_UNKNOWN_HOSTS:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client

def _exec_command(client: paramiko.SSHClient, command: str, timeout_sec: float):
    started = time.time()
    stdin, stdout, stderr = client.exec_command(command.strip(), timeout=timeout_sec)
    if stdin:
        try:
            stdin.close()
        except Exception:
            pass

    def read_limited(stream):
        buf = bytearray()
        truncated = False
        deadline = started + timeout_sec
        while True:
            now = time.time()
            if now > deadline:
                raise TimeoutError("Timeout lettura output")
            # preferire non bloccare: controlla readiness
            chan = getattr(stream, "channel", None)
            if chan is not None and (chan.recv_ready() or chan.recv_stderr_ready()):
                chunk = stream.read(min(4096, MAX_OUTPUT_BYTES - len(buf)))
                if not chunk:
                    break
                if not isinstance(chunk, (bytes, bytearray)):
                    chunk = chunk.encode()
                buf += chunk
                if len(buf) >= MAX_OUTPUT_BYTES:
                    truncated = True
                    break
            # exit condition
            if chan is not None and chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            time.sleep(0.01)
        return bytes(buf), truncated

    out_bytes, out_trunc = read_limited(stdout)
    err_bytes, err_trunc = read_limited(stderr)
    exit_status = None
    try:
        exit_status = stdout.channel.recv_exit_status()
    except Exception:
        exit_status = None
    finished = time.time()
    return {
        "exit_status": exit_status,
        "stdout": out_bytes.decode(errors="replace"),
        "stderr": err_bytes.decode(errors="replace"),
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
        "started_at": started,
        "finished_at": finished,
        "duration_ms": int((finished - started) * 1000)
    }

# ==============
# HTTP Functions (FunctionApp)
# ==============
app = func.FunctionApp()

@app.route(route="ssh/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def ssh_exec(req: func.HttpRequest) -> func.HttpResponse:
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse(json.dumps({"error": "JSON non valido", "request_id": request_id}), status_code=400, mimetype="application/json")

    try:
        data = SSHRequest(**payload)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    try:
        username = _get_username()
        auth = _choose_auth()
    except Exception as e:
        logger.error("KV/credentials error: %s", str(e))
        return func.HttpResponse(json.dumps({"error": "CredentialsError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    client = _prepare_ssh_client()
    try:
        if auth["mode"] == "password":
            client.connect(
                hostname=data.host, port=data.port, username=username,
                password=auth["password"],
                timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT
            )
        else:
            client.connect(
                hostname=data.host, port=data.port, username=username,
                pkey=auth["pkey"],
                timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT
            )

        result = _exec_command(client, data.command, data.timeout_sec)
        resp = {
            "host": data.host,
            "port": data.port,
            "username_source": "KeyVault",
            "auth_mode": auth["mode"],
            "command_executed": data.command.strip(),
            **result,
            "request_id": request_id
        }
        status = 200 if result["exit_status"] == 0 else 207
        return func.HttpResponse(json.dumps(resp), status_code=status, mimetype="application/json")

    except TimeoutError as te:
        return func.HttpResponse(json.dumps({"error": "Timeout", "message": str(te), "request_id": request_id}),
                                 status_code=408, mimetype="application/json")
    except paramiko.AuthenticationException:
        return func.HttpResponse(json.dumps({"error": "AuthFailed", "message": "Autenticazione SSH fallita", "request_id": request_id}),
                                 status_code=401, mimetype="application/json")
    except paramiko.SSHException as se:
        return func.HttpResponse(json.dumps({"error": "SSHError", "message": str(se), "request_id": request_id}),
                                 status_code=502, mimetype="application/json")
    except Exception:
        logger.exception("Unhandled error in ssh_exec")
        return func.HttpResponse(json.dumps({"error": "InternalError", "message": "Errore interno", "request_id": request_id}),
                                 status_code=500, mimetype="application/json")
    finally:
        try:
            client.close()
        except Exception:
            pass

# ----------------------
# Kubernetes: kubectl runtime download and command executor
# ----------------------
class K8SCommandRequest(BaseModel):
    api_server: str = Field(..., description='API server (es: https://1.2.3.4:6443)')
    auth_method: str = Field('kubeconfig', description="Metodo di autenticazione: kubeconfig|token|userpass")
    command: str = Field(..., description='Comando kubectl testuale da eseguire (es: \"kubectl get pods -A\")')
    kubeconfig: Optional[str] = Field(None, description='Contenuto kubeconfig (yaml) o base64; se assente verrà letto da Key Vault con KUBE_CONFIG_SECRET_NAME')
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_sec: Optional[float] = Field(60.0, description="Timeout per l'esecuzione del comando in secondi")
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout_k8s(cls, v):
        if v is None:
            return 60.0
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v

def _ensure_kubectl_installed(version: str = DEFAULT_KUBECTL_VERSION, force: bool = False) -> str:
    """Scarica kubectl nella directory persistente se possibile; fallback su /tmp in caso di errore.
    Restituisce il percorso al binario eseguibile."""
    target_path = KUBECTL_PATH_DEFAULT
    try:
        test_dir = os.path.dirname(target_path)
        os.makedirs(test_dir, exist_ok=True)
        if not os.access(test_dir, os.W_OK | os.X_OK):
            logger.warning("Directory %s non scrivibile/exec, uso fallback %s.", test_dir, KUBECTL_FALLBACK_PATH)
            target_path = KUBECTL_FALLBACK_PATH
    except Exception as e:
        logger.warning("Errore creazione dir persistente: %s, uso fallback %s.", e, KUBECTL_FALLBACK_PATH)
        target_path = KUBECTL_FALLBACK_PATH

    # se già presente e non forzato, restituisci
    if os.path.exists(target_path) and not force:
        try:
            st = os.stat(target_path)
            if st.st_mode & stat.S_IXUSR:
                return target_path
        except Exception:
            pass

    url = KUBECTL_DOWNLOAD_URL_TEMPLATE.format(version=version)
    logger.info("Scaricando kubectl da %s ...", url)
    try:
        tmp_path = target_path + ".download"
        urllib.request.urlretrieve(url, tmp_path)
        os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, target_path)
        return target_path
    except Exception as e:
        logger.exception("Errore durante il download di kubectl: %s", e)
        raise RuntimeError("Unable to download kubectl: %s" % e)

def _choose_k8s_auth_method(kc: str, tok: str, usr: str, pwd: str) -> str:
    """
    Determina quale metodo Kubernetes usare in base a K8S_AUTH_PREFERENCE e alle credenziali disponibili.
    Ordine di sicurezza: kubeconfig > token > userpass.
    """
    pref = K8S_AUTH_PREFERENCE if K8S_AUTH_PREFERENCE in ("auto", "kubeconfig", "token", "userpass") else "auto"

    if pref == "kubeconfig":
        if kc:
            return "kubeconfig"
        raise RuntimeError("K8S_AUTH_PREFERENCE=kubeconfig ma kubeconfig non presente")

    if pref == "token":
        if tok:
            return "token"
        raise RuntimeError("K8S_AUTH_PREFERENCE=token ma token non presente")

    if pref == "userpass":
        if usr and pwd:
            return "userpass"
        raise RuntimeError("K8S_AUTH_PREFERENCE=userpass ma username/password non presenti")

    # AUTO MODE → priorità: kubeconfig > token > userpass
    if kc:
        return "kubeconfig"
    if tok:
        return "token"
    if usr and pwd:
        return "userpass"

    raise RuntimeError("Nessuna credenziale Kubernetes disponibile (né kubeconfig, né token, né username/password)")

def _build_kubeconfig_from_parts(api_server: str, token: str = None, username: str = None, password: str = None) -> str:
    cfg = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "cluster",
                "cluster": {"server": api_server, "insecure-skip-tls-verify": True}
            }
        ],
        "contexts": [
            {
                "name": "ctx",
                "context": {"cluster": "cluster", "user": "user"}
            }
        ],
        "current-context": "ctx",
        "users": [
            {"name": "user", "user": {}}
        ]
    }
    user = cfg["users"][0]["user"]
    if token:
        user["token"] = token
    elif username and password:
        user["username"] = username
        user["password"] = password
    else:
        raise ValueError("token o username/password richiesti per auth_method diverso da kubeconfig")
    return yaml.safe_dump(cfg)

def _write_temp_kubeconfig(content: str) -> str:
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml")
    tf.write(content.encode("utf-8"))
    tf.flush()
    tf.close()
    return tf.name

@app.route(route="k8s/command", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def kubectl_exec(req: func.HttpRequest) -> func.HttpResponse:
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse(json.dumps({"error": "BadRequest", "message": "Corpo JSON non valido", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    try:
        data = K8SCommandRequest(**body)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    # Recupera credenziali da request o Key Vault
    kc = data.kubeconfig or ""
    tok = data.token or ""
    usr = data.username or ""
    pwd = data.password or ""

    if not kc and KUBE_CONFIG_SECRET_NAME:
        kc = _kv_get(KUBE_CONFIG_SECRET_NAME) or ""
    if not tok and KUBE_TOKEN_SECRET_NAME:
        tok = _kv_get(KUBE_TOKEN_SECRET_NAME) or ""
    if not usr and KUBE_USERNAME_SECRET_NAME:
        usr = _kv_get(KUBE_USERNAME_SECRET_NAME) or ""
    if not pwd and KUBE_PASSWORD_SECRET_NAME:
        pwd = _kv_get(KUBE_PASSWORD_SECRET_NAME) or ""

    # 🔹 Determina metodo di autenticazione
    try:
        auth_method = data.auth_method or _choose_k8s_auth_method(kc, tok, usr, pwd)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "AuthSelectionError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    kubeconfig_path = None
    try:
        if auth_method == "kubeconfig":
            s = kc.strip()
            try:
                if not s.startswith("apiVersion") and not s.startswith("kind") and "clusters:" not in s:
                    kc = base64.b64decode(s).decode("utf-8")
            except Exception:
                pass
            kubeconfig_path = _write_temp_kubeconfig(kc)

        elif auth_method == "token":
            kube_yaml = _build_kubeconfig_from_parts(data.api_server, token=tok)
            kubeconfig_path = _write_temp_kubeconfig(kube_yaml)

        elif auth_method == "userpass":
            kube_yaml = _build_kubeconfig_from_parts(data.api_server, username=usr, password=pwd)
            kubeconfig_path = _write_temp_kubeconfig(kube_yaml)

        else:
            return func.HttpResponse(json.dumps({"error": "BadAuthMethod", "message": f"auth_method non valido: {auth_method}", "request_id": request_id}),
                                     status_code=400, mimetype="application/json")

    except Exception as e:
        logger.exception("Errore nella costruzione del kubeconfig")
        return func.HttpResponse(json.dumps({"error": "KubeConfigError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    try:
        kubectl_path = _ensure_kubectl_installed()
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "KubectlInstallFailed", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    # Prepare environment for subprocess (set KUBECONFIG explicitly)
    env = os.environ.copy()
    env["KUBECONFIG"] = kubeconfig_path

    # Ensure command uses the downloaded kubectl binary
    cmd = data.command.strip()
    # Replace only the first occurrence of 'kubectl' as a token
    cmd_replaced = re.sub(r'(^|\\s)kubectl(\\s|$)', lambda m: (m.group(1) or "") + kubectl_path + (m.group(2) or " "), cmd, count=1)
    if cmd_replaced == cmd:
        cmd_replaced = kubectl_path + " " + cmd

    logger.info("Eseguo comando: %s", cmd_replaced)
    start = time.time()
    try:
        proc = subprocess.run(cmd_replaced, shell=True, executable="/bin/sh",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=data.timeout_sec)
        finished = time.time()
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as te:
        finished = time.time()
        stdout = te.stdout.decode("utf-8", errors="ignore") if te.stdout else ""
        stderr = te.stderr.decode("utf-8", errors="ignore") if te.stderr else ""
        exit_code = None
        logger.warning("kubectl command timeout")
    except Exception as e:
        finished = time.time()
        stdout = ""
        stderr = str(e)
        exit_code = None
        logger.exception("Errore esecuzione kubectl")

    # cleanup kubeconfig temporary file
    try:
        if kubeconfig_path and os.path.exists(kubeconfig_path):
            os.unlink(kubeconfig_path)
    except Exception:
        pass

    resp = {
        "command_executed": data.command.strip(),
        "exit_status": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "started_at": start,
        "finished_at": finished,
        "duration_ms": int((finished - start) * 1000),
        "request_id": request_id
    }
    return func.HttpResponse(json.dumps(resp), status_code=200, mimetype="application/json")