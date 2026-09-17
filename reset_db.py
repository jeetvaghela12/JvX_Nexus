"""
reset_db.py — drops every table, then the next server start rebuilds them
from the current model definitions.

DESTRUCTIVE. Every row is lost. This exists because create_all() in
main.py is additive: it creates missing tables and silently ignores a
table whose model has since gained a column. Against a database that
already holds these tables, a new column never appears and the failure
surfaces later as a missing-column error nobody can place.

Run this after a model change, during development, against a disposable
database. Never against anything holding data you need.

Real schema evolution needs Alembic. This is the development shortcut.
"""
from core.database import Base, engine

# Imported for their side effect: each registers its table on
# Base.metadata. A model not imported here is a table drop_all() will not
# find, which leaves it behind holding a stale schema.
import models.compliance_model  # noqa: F401
import models.declaration_model  # noqa: F401
import models.payment_model  # noqa: F401
import models.user_model  # noqa: F401
import models.virtual_account_model  # noqa: F401

Base.metadata.drop_all(bind=engine)
print("All tables dropped. Restart the server to rebuild them.")