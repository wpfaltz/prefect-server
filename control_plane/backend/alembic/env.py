from __future__ import annotations
import os
from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool
from app.db.session import Base
from app.db import models

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

def get_url() -> str:
    """Obtém a URL de conexão do banco de dados para o Alembic.

    Lê a variável de ambiente ``CONTROL_PLANE_DB_URL`` que deve conter
    a URL SQLAlchemy válida para o banco de dados do control-plane.

    Returns:
        str: URL de conexão SQLAlchemy.

    Raises:
        RuntimeError: Se a variável ``CONTROL_PLANE_DB_URL`` não estiver
            definida.
    """
    url = os.getenv("CONTROL_PLANE_DB_URL", "")
    if not url:
        raise RuntimeError("CONTROL_PLANE_DB_URL not set for Alembic.")
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Executa as migrations do Alembic em modo 'online'.

    Cria uma engine SQLAlchemy a partir da configuração do ``alembic.ini``,
    sobrescrevendo a ``sqlalchemy.url`` com o valor retornado por
    ``get_url()``. Estabelece uma conexão real com o banco e executa
    as migrations dentro de uma transação.

    Este é o modo padrão quando o Alembic é executado normalmente
    (não em modo offline).
    """
    configuration = config.get_section(config.config_ini_section)

    # garante que é dict
    if configuration is None:
        configuration = {}
    else:
        configuration = dict(configuration)

    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
