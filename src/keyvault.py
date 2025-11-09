import logging
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from .settings import KEY_VAULT_URL, APP_NAME

logger = logging.getLogger(APP_NAME)

credential = None
kv_client = None

if KEY_VAULT_URL:
    try:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        kv_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
    except Exception as e:
        raise RuntimeError(f"Key Vault client init failed: {e}")

def _kv_get(secret_name: str) -> str:
    if not secret_name:
        raise RuntimeError("Nome secret non configurato")
    if not kv_client:
        raise RuntimeError("KEY_VAULT_URL non configurato")
    try:
        return kv_client.get_secret(secret_name).value
    except Exception as e:
        raise RuntimeError(f"Errore lettura secret {secret_name}: {e}")