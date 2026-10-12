import os
from pathlib import Path

from dotenv import load_dotenv


# The project root is the folder that contains app.py and the .env files.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Which environment file to read:
#   .env           -> original Streamlit version (default)
#   .env_pipeline  -> Phase 2 pipeline (app.py sets ATTACK_CASE_ENV_FILE)
ENV_FILE = os.getenv("ATTACK_CASE_ENV_FILE", ".env")

# Values already present in the process environment are kept, so settings
# entered on the web page take priority over the file.
load_dotenv(PROJECT_ROOT / ENV_FILE)


NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def validate_config():

    if not NEO4J_URI:
        raise ValueError(f"NEO4J_URI is missing from {ENV_FILE}")

    if not NEO4J_USERNAME:
        raise ValueError(f"NEO4J_USERNAME is missing from {ENV_FILE}")

    if not NEO4J_PASSWORD:
        raise ValueError(f"NEO4J_PASSWORD is missing from {ENV_FILE}")


if __name__ == "__main__":

    validate_config()

    print("Configuration loaded successfully.")
