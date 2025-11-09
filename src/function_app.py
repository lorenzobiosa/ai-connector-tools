from .app import app  # espone l'istanza FunctionApp
# Import dei moduli che registrano le route
from . import ssh_api, k8s_api, atlas_api, mongo_api  # noqa: F401