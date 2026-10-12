import os

from neo4j import GraphDatabase

import config


def get_connection_settings():
    """
    Return the Neo4j connection settings currently in use.

    Settings are read every time this is called, so a connection
    entered on the web page (stored in the process environment)
    takes effect immediately. The values loaded from the .env file
    are the fallback.
    """
    return {
        "uri": os.getenv("NEO4J_URI") or config.NEO4J_URI,
        "username": os.getenv("NEO4J_USERNAME") or config.NEO4J_USERNAME,
        "password": os.getenv("NEO4J_PASSWORD") or config.NEO4J_PASSWORD,
        "database": (
            os.getenv("NEO4J_DATABASE")
            or config.NEO4J_DATABASE
            or "neo4j"
        ),
    }


class _DatabaseDriver:
    """
    Thin wrapper around a Neo4j driver.

    driver.session() opens the configured database by default, so the
    existing code (which calls driver.session() with no arguments) works
    against a named database such as "attackcase".
    """

    def __init__(self, driver, database):
        self._driver = driver
        self._database = database

    def session(self, **kwargs):
        if self._database:
            kwargs.setdefault("database", self._database)
        return self._driver.session(**kwargs)

    def __getattr__(self, name):
        return getattr(self._driver, name)


def get_driver():
    """
    Create and return a Neo4j driver for the configured database.
    """
    settings = get_connection_settings()

    if not settings["uri"] or not settings["username"]:
        raise ValueError(
            "Neo4j connection is not configured. "
            "Set the URI and username first."
        )

    driver = GraphDatabase.driver(
        settings["uri"],
        auth=(
            settings["username"],
            settings["password"] or ""
        )
    )

    return _DatabaseDriver(driver, settings["database"])


class Neo4jConnection:
    """
    Handles the connection to Neo4j.
    """

    def __init__(self):
        self.driver = get_driver()

    def verify_connection(self):
        """
        Verify connectivity to Neo4j.
        """
        self.driver.verify_connectivity()
        print("Neo4j connection successful!")

    def close(self):
        """
        Close the Neo4j connection.
        """
        self.driver.close()

    def session(self):
        """
        Create a session using the configured database.
        """
        return self.driver.session()


if __name__ == "__main__":

    db = Neo4jConnection()

    try:
        db.verify_connection()

    finally:
        db.close()
