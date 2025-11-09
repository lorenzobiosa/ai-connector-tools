import logging
import azure.functions as func
from .settings import APP_NAME, LOG_LEVEL

# Istanza condivisa di FunctionApp (Python v2 programming model)
app = func.FunctionApp()

# Logger centralizzato
logger = logging.getLogger(APP_NAME)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))