# reset_db.py -- run this ONCE, then delete it. Dropping tables + letting
# next server start rebuilds them fresh from the current model definitions,
# picking up every column added since the database was originally created.
from core.database import Base, engine
import models.cbdc_model
import models.clientshield_model
import models.compliance_model
import models.income_model
import models.ledger_model
import models.ticket_model
import models.user_model
import models.virtual_account_model  # noqa: F401

Base.metadata.drop_all(bind=engine)
print("Done. All tables dropped -- restart your server.")