"""The AI analyst's SQL connection must not be able to modify data."""
import pytest
from sqlalchemy.exc import OperationalError

from backend.src.database import init_db
from backend.src.llm import DataAnalyst


def test_agent_database_is_read_only():
    init_db()
    analyst = DataAnalyst()  # builds the client only; no Ollama call is made
    analyst.db.run("SELECT count(*) FROM sleep")  # reads work
    for statement in ("DELETE FROM sleep", "DROP TABLE sleep"):
        with pytest.raises(OperationalError, match="readonly"):
            analyst.db.run(statement)


def test_agent_is_built_with_limits():
    init_db()
    executor = DataAnalyst().build_agent()  # no Ollama call at construction
    assert executor.max_iterations == 8
    assert executor.max_execution_time == 120
