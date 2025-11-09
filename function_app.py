import logging
import azure.functions as func
from settings import APP_NAME, LOG_LEVEL

# Istanza condivisa di FunctionApp (Python v2 programming model)
app = func.FunctionApp()

# Logger centralizzato
logger = logging.getLogger(APP_NAME)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Import dei moduli che registrano le route
from . import ssh_api, k8s_api, atlas_api, mongo_api  # noqa: F401