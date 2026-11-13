"""Create the benchmark schema plus one lab organization and analyst user.

  DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/aegis_bench \
    PYTHONPATH=backend python harness/scripts/setup_bench_db.py

Use a dedicated, disposable database: this creates every model's table.
Prints the organization and user IDs to pass to compare_lab.
"""

import importlib
import os
import pkgutil

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("SECRET_KEY", "benchmark-only-secret-key-with-32-plus-characters")

import app.models  # noqa: E402
from app.db.database import Base  # noqa: E402

for module in pkgutil.iter_modules(app.models.__path__):
    importlib.import_module(f"app.models.{module.name}")  # register every table

from app.models.organization import Organization  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402

engine = create_engine(os.environ["DATABASE_URL"])
Base.metadata.create_all(engine)
db = sessionmaker(bind=engine)()
org = db.query(Organization).filter_by(name="Benchmark Lab").first() or Organization(name="Benchmark Lab")
db.add(org)
db.commit()
db.refresh(org)
user = db.query(User).filter_by(username="bench").first() or User(
    email="bench@lab.invalid", username="bench", hashed_password="!",
    role=UserRole.ANALYST, organization_id=org.id, is_active=True,
)
db.add(user)
db.commit()
db.refresh(user)
print(f"tables={len(Base.metadata.tables)} organization_id={org.id} user_id={user.id}")
