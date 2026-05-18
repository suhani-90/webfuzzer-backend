"""
app/db/base.py
───────────────
SQLAlchemy declarative base that all ORM models inherit from.
Also imports all models here so Alembic's autogenerate can discover them.
"""

from backend.app.db.base_class import Base

# Import all models below so Alembic sees them during migrations.
# Order matters: parent models before children.
from backend.app.models.user import User  # noqa: F401, E402
from backend.app.models.target import Target  # noqa: F401, E402
from backend.app.models.scan import Scan  # noqa: F401, E402
from backend.app.models.endpoint import DiscoveredEndpoint  # noqa: F401, E402
from backend.app.models.payload import Payload  # noqa: F401, E402
from backend.app.models.vulnerability import Vulnerability  # noqa: F401, E402
from backend.app.models.report import Report  # noqa: F401, E402
