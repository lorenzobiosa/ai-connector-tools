# settings.py
import os

# =========================
# Configurazione e Costanti
# =========================
APP_NAME = os.getenv("APP_NAME", "ai-foundry-ssh-tool")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

KEY_VAULT_URL = os.getenv("KEY_VAULT_URL", "")  # es: https://my-kv.vault.azure.net/

# ---- SSH
SSH_USERNAME_SECRET_NAME = os.getenv("SSH_USERNAME_SECRET_NAME", "")
SSH_PASSWORD_SECRET_NAME = os.getenv("SSH_PASSWORD_SECRET_NAME", "")
SSH_PRIVATE_KEY_SECRET_NAME = os.getenv("SSH_PRIVATE_KEY_SECRET_NAME", "")
SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME = os.getenv("SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME", "")
AUTH_PREFERENCE = os.getenv("AUTH_PREFERENCE", "auto").lower()  # auto|key|password

ALLOW_UNKNOWN_HOSTS = os.getenv("ALLOW_UNKNOWN_HOSTS", "true").lower() == "true"
DEFAULT_PORT = int(os.getenv("SSH_DEFAULT_PORT", "22"))
CONNECT_TIMEOUT = float(os.getenv("SSH_CONNECT_TIMEOUT_SEC", "10"))
COMMAND_TIMEOUT = float(os.getenv("SSH_COMMAND_TIMEOUT_SEC", "300"))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", str(256 * 1024)))  # 256 KiB

# ---- K8s
KUBE_CONFIG_SECRET_NAME = os.getenv("KUBE_CONFIG_SECRET_NAME", "")
KUBE_TOKEN_SECRET_NAME = os.getenv("KUBE_TOKEN_SECRET_NAME", "")
KUBE_USERNAME_SECRET_NAME = os.getenv("KUBE_USERNAME_SECRET_NAME", "")
KUBE_PASSWORD_SECRET_NAME = os.getenv("KUBE_PASSWORD_SECRET_NAME", "")
K8S_AUTH_PREFERENCE = os.getenv("K8S_AUTH_PREFERENCE", "auto").lower()  # auto|kubeconfig|token|userpass

DEFAULT_KUBECTL_VERSION = os.getenv("DEFAULT_KUBECTL_VERSION", "v1.30.0")
KUBECTL_DOWNLOAD_URL_TEMPLATE = os.getenv(
    "KUBECTL_DOWNLOAD_URL_TEMPLATE",
    "https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl"
)
KUBECTL_PATH_DEFAULT = os.getenv("KUBECTL_PATH", "/home/site/tools/kubectl")
KUBECTL_FALLBACK_PATH = os.getenv("KUBECTL_FALLBACK_PATH", "/tmp/kubectl")

# ---- Atlas CLI / Mongo
# Atlas
ATLAS_PUBLIC_KEY_SECRET_NAME = os.getenv("ATLAS_PUBLIC_KEY_SECRET_NAME", "")
ATLAS_PRIVATE_KEY_SECRET_NAME = os.getenv("ATLAS_PRIVATE_KEY_SECRET_NAME", "")
ATLAS_AUTH_PREFERENCE = os.getenv("ATLAS_AUTH_PREFERENCE", "auto").lower()  # api_key|profile|auto
ATLAS_DEFAULT_PROFILE = os.getenv("ATLAS_DEFAULT_PROFILE", "")

ATLAS_CLI_VERSION = os.getenv("ATLAS_CLI_VERSION", "1.50.0")
ATLAS_CLI_DOWNLOAD_URL_TEMPLATE = os.getenv(
    "ATLAS_CLI_DOWNLOAD_URL_TEMPLATE",
    "https://fastdl.mongodb.org/mongocli/mongodb-atlas-cli_{version}_linux_x86_64.tar.gz"
)
ATLAS_CLI_PATH = os.getenv("ATLAS_CLI_PATH", "/home/site/tools/mongodb-atlas-cli")
ATLAS_CLI_FALLBACK_PATH = os.getenv("ATLAS_CLI_FALLBACK_PATH", "/tmp/mongodb-atlas-cli")

# ---- Mongo (per mongo_exec)
MONGO_AUTH_PREFERENCE = os.getenv("MONGO_AUTH_PREFERENCE", "auto").lower()  # userpass|uri|auto
MONGO_URI_SECRET_NAME = os.getenv("MONGO_URI_SECRET_NAME", "")
MONGO_USERNAME_SECRET_NAME = os.getenv("MONGO_USERNAME_SECRET_NAME", "")
MONGO_PASSWORD_SECRET_NAME = os.getenv("MONGO_PASSWORD_SECRET_NAME", "")

MONGO_HOST = os.getenv("MONGO_HOST", "")
MONGO_HOST_SECRET_NAME = os.getenv("MONGO_HOST_SECRET_NAME", "")

# SCHEMA: se non impostato, verrà inferito dall'host (Atlas -> mongodb+srv, altrimenti mongodb)
MONGO_SCHEME = os.getenv("MONGO_SCHEME")  # "mongodb+srv" | "mongodb" | None

# Porte opzionali (popolabili dall'LLM) — applicate solo per schema 'mongodb'
# Esempi: "27017" oppure "27017,27018,27019"
MONGO_PORTS = os.getenv("MONGO_PORTS", "")

MONGO_AUTH_DB = os.getenv("MONGO_AUTH_DB", "admin")

# Se valorizzato con HTML-safe (&amp;), mongo_exec normalizza -> '&'
MONGO_OPTIONS = os.getenv("MONGO_OPTIONS", "retryWrites=true&amp;w=majority")

# TLS per 'mongodb' (per 'mongodb+srv' è implicito)
MONGO_TLS = os.getenv("MONGO_TLS", "true").lower() == "true"