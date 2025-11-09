import logging
import azure.functions as func
from .settings import APP_NAME, LOG_LEVEL

app = func.FunctionApp()

logger = logging.getLogger(APP_NAME)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Import moduli che registrano le route
from . import ssh_api  # noqa: F401
from . import k8s_api  # noqa: F401
from . import atlas_api  # noqa: F401
from . import mongo_api  # noqa: F401