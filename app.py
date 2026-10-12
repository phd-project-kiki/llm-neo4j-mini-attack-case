"""
Phase 2 pipeline: FastAPI back end.

    Browser (static/index.html)
        |
        v
    FastAPI (this file)
        |
        +--> Ollama        local LLM and embeddings
        +--> LlamaIndex    document -> knowledge graph, retrieval
        +--> Neo4j         graph storage

Run with:

    python app.py

then open http://127.0.0.1:8001
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
DATA_DIR = ROOT_DIR / "data"
STATIC_DIR = ROOT_DIR / "static"

# Use the pipeline configuration file instead of .env.
# This must be set before the src modules are imported.
os.environ.setdefault("ATTACK_CASE_ENV_FILE", ".env_pipeline")

sys.path.insert(0, str(SRC_DIR))

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable
from pydantic import BaseModel

import config  # noqa: F401  (loads .env_pipeline)
from build_attack_graph import build_attack_graph
from neo4j_connection import get_connection_settings, get_driver
from query_attack import get_attack_summary, get_attack_timeline


app = FastAPI(title="LLM + Neo4j Attack Case Pipeline")

# Neo4j warns about labels that do not exist yet (for example before the
# first extraction). Those warnings are expected, so keep the log quiet.
logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)


# ============================================================
# In-memory state
# ============================================================

STATE = {
    "connected": False,
    "server": None,
}

SIMULATION = {
    "process": None,
}

EXTRACTION = {
    "status": "idle",       # idle | running | completed | failed
    "message": "",
    "file": None,
    "started_at": None,
    "finished_at": None,
    "result": None,
}

EXTRACTION_LOCK = threading.Lock()

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".md"}


# ============================================================
# Request bodies
# ============================================================

class ConnectionRequest(BaseModel):
    uri: str
    username: str
    password: str = ""
    database: str = "neo4j"


class ExtractRequest(BaseModel):
    filename: str
    strict: bool = True


class ChatRequest(BaseModel):
    question: str


# ============================================================
# Helpers
# ============================================================

def require_connection():
    """
    Stop the request if no Neo4j connection has been made yet.
    """
    if not STATE["connected"]:
        raise HTTPException(
            status_code=400,
            detail="Connect to Neo4j first (section 1).",
        )


def resolve_password(request: ConnectionRequest):
    """
    Use the password typed on the page. If it was left empty, fall back
    to the one from .env_pipeline or from the previous connection.
    """
    return request.password or os.getenv("NEO4J_PASSWORD") or ""


def check_connection(uri, username, password, database):
    """
    Try to connect to Neo4j and run a query in the chosen database.

    Returns:
        dict: ok flag, a message, and server details when it worked.
    """
    uri = (uri or "").strip()
    username = (username or "").strip()
    database = (database or "").strip() or "neo4j"

    if not uri or not username:
        return {
            "ok": False,
            "message": "URI and username are required.",
        }

    driver = None

    try:

        driver = GraphDatabase.driver(
            uri,
            auth=(username, password),
            connection_timeout=8,
        )

        driver.verify_connectivity()

        with driver.session(database=database) as session:

            session.run("RETURN 1").consume()

            component = session.run("""
                CALL dbms.components()
                YIELD name, versions, edition
                RETURN name, versions[0] AS version, edition
                LIMIT 1
            """).single()

            node_count = session.run(
                "MATCH (n) RETURN count(n) AS nodes"
            ).single()["nodes"]

            try:
                apoc_version = session.run(
                    "RETURN apoc.version() AS version"
                ).single()["version"]
            except Exception:
                apoc_version = None

        message = (
            f"Connected to {component['name']} {component['version']} "
            f"({component['edition']}), database '{database}'."
        )

        if not apoc_version:
            message += (
                " APOC was not found: the LlamaIndex extraction "
                "needs the APOC plugin."
            )

        return {
            "ok": True,
            "message": message,
            "server": {
                "name": component["name"],
                "version": component["version"],
                "edition": component["edition"],
                "apoc": apoc_version,
                "nodes": node_count,
            },
        }

    except AuthError:

        return {
            "ok": False,
            "message": "Authentication failed. Check the username "
                       "and password.",
        }

    except ServiceUnavailable:

        return {
            "ok": False,
            "message": f"Could not reach Neo4j at {uri}. Check that "
                       "the database is started in Neo4j Desktop and "
                       "that the URI is correct.",
        }

    except Neo4jError as error:

        if "DatabaseNotFound" in (error.code or ""):

            return {
                "ok": False,
                "message": f"Database '{database}' does not exist. "
                           "Create it in Neo4j Desktop or use 'neo4j'.",
            }

        return {"ok": False, "message": error.message or str(error)}

    except Exception as error:

        return {"ok": False, "message": str(error)}

    finally:

        if driver is not None:
            driver.close()


def simulation_running():
    process = SIMULATION["process"]
    return process is not None and process.poll() is None


def ollama_config():
    return {
        "base_url": os.getenv(
            "OLLAMA_BASE_URL", "http://localhost:11434"
        ).rstrip("/"),
        "llm_model": os.getenv("OLLAMA_LLM_MODEL", "llama3.2"),
        "embed_model": os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
    }


def model_installed(model, installed):
    """
    'llama3.2' matches an installed 'llama3.2:latest'.
    """
    wanted = model if ":" in model else f"{model}:latest"
    return wanted in installed or model in installed


def safe_data_file(filename):
    """
    Return the path of a file inside data/, rejecting anything else.
    """
    name = Path(filename or "").name

    if not name or name != filename:
        raise HTTPException(status_code=400, detail="Invalid file name.")

    path = DATA_DIR / name

    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"{name} was not found in the data folder.",
        )

    return path


def clean_value(value):
    """
    Make a Neo4j property value safe to send as JSON.
    """
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


# ============================================================
# Page
# ============================================================

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


# ============================================================
# Configuration and status
# ============================================================

@app.get("/api/config")
def get_config():
    """
    Defaults shown on the page. The password is never sent back.
    """
    connection = get_connection_settings()

    return {
        "connection": {
            "uri": connection["uri"] or "",
            "username": connection["username"] or "",
            "database": connection["database"] or "neo4j",
            "has_password": bool(connection["password"]),
        },
        "ollama": ollama_config(),
        "env_file": os.environ["ATTACK_CASE_ENV_FILE"],
    }


@app.get("/api/status")
def get_status():

    connection = get_connection_settings()

    status = {
        "connected": STATE["connected"],
        "connection": {
            "uri": connection["uri"] or "",
            "username": connection["username"] or "",
            "database": connection["database"] or "neo4j",
        },
        "server": STATE["server"],
        "simulation_running": simulation_running(),
        "extraction": dict(EXTRACTION),
        "counts": None,
    }

    if STATE["connected"]:

        try:

            driver = get_driver()

            try:
                with driver.session() as session:
                    record = session.run("""
                        OPTIONAL MATCH (e:Event) WHERE NOT e:__Node__
                        WITH count(e) AS events
                        OPTIONAL MATCH (h) WHERE h:Host AND NOT h:__Node__
                        WITH events, count(h) AS hosts
                        OPTIONAL MATCH (x:__Entity__)
                        RETURN events, hosts, count(x) AS extracted
                    """).single()

                    status["counts"] = {
                        "events": record["events"],
                        "hosts": record["hosts"],
                        "extracted": record["extracted"],
                    }
            finally:
                driver.close()

        except Exception as error:

            status["counts_error"] = str(error)

    return status


# ============================================================
# 1. Neo4j connection
# ============================================================

@app.post("/api/connection/test")
def test_connection(request: ConnectionRequest):
    """
    Test the connection without changing what the app is using.
    """
    return check_connection(
        request.uri,
        request.username,
        resolve_password(request),
        request.database,
    )


@app.post("/api/connection/connect")
def connect(request: ConnectionRequest):
    """
    Test the connection and, if it works, use it for everything else.

    The settings are kept in memory for this run of the app only.
    """
    if simulation_running():
        raise HTTPException(
            status_code=409,
            detail="Stop the simulation before changing the connection.",
        )

    if EXTRACTION["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="Wait for the extraction to finish before changing "
                   "the connection.",
        )

    password = resolve_password(request)

    result = check_connection(
        request.uri,
        request.username,
        password,
        request.database,
    )

    if result["ok"]:

        os.environ["NEO4J_URI"] = request.uri.strip()
        os.environ["NEO4J_USERNAME"] = request.username.strip()
        os.environ["NEO4J_PASSWORD"] = password
        os.environ["NEO4J_DATABASE"] = (
            request.database.strip() or "neo4j"
        )

        STATE["connected"] = True
        STATE["server"] = result["server"]

    return result


@app.post("/api/connection/disconnect")
def disconnect():

    if simulation_running():
        raise HTTPException(
            status_code=409,
            detail="Stop the simulation before disconnecting.",
        )

    STATE["connected"] = False
    STATE["server"] = None

    return {"ok": True}


# ============================================================
# Ollama
# ============================================================

@app.get("/api/ollama/check")
def check_ollama():
    """
    Check that Ollama is running and that both models are installed.
    """
    settings = ollama_config()

    try:

        with urllib.request.urlopen(
            settings["base_url"] + "/api/tags",
            timeout=5,
        ) as response:

            payload = json.loads(response.read().decode("utf-8"))

    except (urllib.error.URLError, OSError, ValueError) as error:

        return {
            "ok": False,
            "message": f"Could not reach Ollama at "
                       f"{settings['base_url']}: {error}",
            **settings,
        }

    installed = [
        model.get("name", "")
        for model in payload.get("models", [])
    ]

    llm_ok = model_installed(settings["llm_model"], installed)
    embed_ok = model_installed(settings["embed_model"], installed)

    missing = []

    if not llm_ok:
        missing.append(settings["llm_model"])

    if not embed_ok:
        missing.append(settings["embed_model"])

    if missing:
        message = "Ollama is running, but these models are missing: " + \
            ", ".join(missing) + ". Install with: " + \
            " ; ".join(f"ollama pull {name}" for name in missing)
    else:
        message = "Ollama is running and both models are installed."

    return {
        "ok": llm_ok and embed_ok,
        "message": message,
        "llm_installed": llm_ok,
        "embed_installed": embed_ok,
        "installed": installed,
        **settings,
    }


# ============================================================
# 2. Documents and LlamaIndex extraction
# ============================================================

@app.get("/api/documents")
def list_documents():

    DATA_DIR.mkdir(exist_ok=True)

    documents = [
        {
            "name": path.name,
            "size_kb": round(path.stat().st_size / 1024, 1),
        }
        for path in sorted(DATA_DIR.iterdir())
        if path.is_file() and path.suffix.lower() in ALLOWED_EXTENSIONS
    ]

    return {"documents": documents}


@app.post("/api/documents/upload")
async def upload_document(file: UploadFile = File(...)):
    """
    Save an uploaded .txt or .md file into the data folder.
    """
    original = Path(file.filename or "").name

    name = re.sub(r"[^A-Za-z0-9._ -]", "_", original).strip()

    if not name or Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Only .txt and .md files are supported.",
        )

    content = await file.read(MAX_UPLOAD_BYTES + 1)

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail="File is larger than 2 MB.",
        )

    if not content.strip():
        raise HTTPException(status_code=400, detail="File is empty.")

    DATA_DIR.mkdir(exist_ok=True)

    (DATA_DIR / name).write_bytes(content)

    return {"ok": True, "name": name}


def run_extraction_job(path, strict):
    """
    Background thread: run the LlamaIndex extraction.
    """
    def progress(message):
        EXTRACTION["message"] = message

    try:

        from extract_graph import extract_document

        result = extract_document(
            path,
            strict=strict,
            on_progress=progress,
        )

        EXTRACTION.update({
            "status": "completed",
            "message": "Extraction completed.",
            "result": result,
        })

    except Exception as error:

        EXTRACTION.update({
            "status": "failed",
            "message": f"{type(error).__name__}: {error}",
        })

    finally:

        EXTRACTION["finished_at"] = time.time()


@app.post("/api/extract")
def start_extraction(request: ExtractRequest):
    """
    Start extracting a document from data/ into Neo4j.

    Extraction runs in the background; poll /api/extract/status.
    """
    require_connection()

    path = safe_data_file(request.filename)

    with EXTRACTION_LOCK:

        if EXTRACTION["status"] == "running":
            raise HTTPException(
                status_code=409,
                detail="An extraction is already running.",
            )

        EXTRACTION.update({
            "status": "running",
            "message": "Starting",
            "file": path.name,
            "started_at": time.time(),
            "finished_at": None,
            "result": None,
        })

    threading.Thread(
        target=run_extraction_job,
        args=(path, request.strict),
        daemon=True,
    ).start()

    return {"ok": True, "file": path.name}


@app.get("/api/extract/status")
def extraction_status():

    status = dict(EXTRACTION)

    if status["started_at"]:
        end = status["finished_at"] or time.time()
        status["elapsed_seconds"] = int(end - status["started_at"])

    return status


@app.post("/api/extract/clear")
def clear_extraction():
    """
    Delete the extracted knowledge graph. The simulation graph stays.
    """
    require_connection()

    if EXTRACTION["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="An extraction is running.",
        )

    from extract_graph import clear_extracted_graph

    clear_extracted_graph()

    return {"ok": True}


# ============================================================
# 3. Attack environment and simulation
# ============================================================

@app.post("/api/attack/build")
def build_environment():
    """
    Build the hand-written attack environment (hosts, FIN7, techniques,
    and the eight baseline events).
    """
    require_connection()

    if simulation_running():
        raise HTTPException(
            status_code=409,
            detail="Stop the simulation before rebuilding.",
        )

    try:
        build_attack_graph()
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))

    return {"ok": True, "message": "Attack environment created."}


@app.post("/api/simulation/start")
def start_simulation():

    require_connection()

    if simulation_running():
        raise HTTPException(
            status_code=409,
            detail="The simulation is already running.",
        )

    # The simulator needs the hosts and techniques to exist.
    driver = get_driver()

    try:
        with driver.session() as session:
            ready = session.run("""
                MATCH (h:Host {name: "WS01"})
                WHERE NOT h:__Node__
                RETURN count(h) AS hosts
            """).single()["hosts"]
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))
    finally:
        driver.close()

    if not ready:
        raise HTTPException(
            status_code=400,
            detail="Build the attack environment first.",
        )

    # The child process inherits the connection settings through the
    # environment. UTF-8 output avoids console encoding errors on Windows.
    environment = dict(os.environ)
    environment["PYTHONIOENCODING"] = "utf-8"

    SIMULATION["process"] = subprocess.Popen(
        [sys.executable, str(SRC_DIR / "simulate_attack.py")],
        cwd=str(ROOT_DIR),
        env=environment,
    )

    return {"ok": True, "message": "Simulation started."}


@app.post("/api/simulation/stop")
def stop_simulation():

    if simulation_running():

        SIMULATION["process"].terminate()

        try:
            SIMULATION["process"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            SIMULATION["process"].kill()

    SIMULATION["process"] = None

    return {"ok": True, "message": "Simulation stopped."}


# ============================================================
# 4. Timeline and graph
# ============================================================

@app.get("/api/timeline")
def timeline():

    require_connection()

    try:
        events = get_attack_timeline()
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))

    return {
        "events": events,
        "simulation_running": simulation_running(),
    }


GRAPH_SCOPES = {
    "all": "NOT n:Chunk",
    "extracted": "n:__Entity__",
    "simulation": "NOT n:__Node__",
}

HIDDEN_LABELS = {"__Node__", "__Entity__"}
HIDDEN_PROPERTIES = {"embedding", "triplet_source_id"}


@app.get("/api/graph")
def graph(scope: str = "all", limit: int = 400):
    """
    Nodes and relationships for the graph view.

        all         everything except text chunks
        extracted   what LlamaIndex extracted from documents
        simulation  the hand-built environment and events
    """
    require_connection()

    if scope not in GRAPH_SCOPES:
        raise HTTPException(status_code=400, detail="Unknown scope.")

    limit = max(1, min(int(limit), 1000))

    driver = get_driver()

    try:

        with driver.session() as session:

            node_records = session.run(
                f"""
                MATCH (n)
                WHERE {GRAPH_SCOPES[scope]}
                RETURN
                    elementId(n) AS id,
                    labels(n) AS labels,
                    properties(n) AS properties
                LIMIT $limit
                """,
                limit=limit,
            )

            nodes = []

            for record in node_records:

                labels = [
                    label for label in record["labels"]
                    if label not in HIDDEN_LABELS
                ]

                properties = {
                    key: clean_value(value)
                    for key, value in record["properties"].items()
                    if key not in HIDDEN_PROPERTIES
                }

                caption = (
                    properties.get("name")
                    or properties.get("id")
                    or (labels[0] if labels else "node")
                )

                nodes.append({
                    "id": record["id"],
                    "caption": str(caption),
                    "type": labels[0] if labels else "Node",
                    "extracted": "__Node__" in record["labels"],
                    "properties": properties,
                })

            node_ids = [node["id"] for node in nodes]

            edge_records = session.run(
                """
                MATCH (a)-[r]->(b)
                WHERE elementId(a) IN $ids AND elementId(b) IN $ids
                RETURN
                    elementId(r) AS id,
                    elementId(a) AS source,
                    elementId(b) AS target,
                    type(r) AS type
                LIMIT 5000
                """,
                ids=node_ids,
            )

            edges = [
                {
                    "id": record["id"],
                    "source": record["source"],
                    "target": record["target"],
                    "type": record["type"],
                }
                for record in edge_records
            ]

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))
    finally:
        driver.close()

    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": len(nodes) >= limit,
    }


# ============================================================
# 5. LLM analysis and chat
# ============================================================

@app.post("/api/analysis")
def analysis():
    """
    Send the attack evidence from Neo4j to the local model.
    """
    require_connection()

    try:

        from llm_analysis import analyze_attack

        evidence = get_attack_summary()

        if not evidence["timeline"]:
            raise HTTPException(
                status_code=400,
                detail="There are no attack events to analyze. Build "
                       "the attack environment first.",
            )

        return {
            "analysis": analyze_attack(evidence),
            "events": len(evidence["timeline"]),
        }

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {error}. Check that Ollama is "
                   "running.",
        )


@app.post("/api/chat")
def chat(request: ChatRequest):

    require_connection()

    if not request.question.strip():
        raise HTTPException(
            status_code=400,
            detail="Please enter a question.",
        )

    try:

        from chat import answer_question

        return answer_question(request.question)

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Chat failed: {error}. Check that Ollama is running.",
        )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":

    import uvicorn

    print()
    print("Open http://127.0.0.1:8001 in your browser.")
    print()

    uvicorn.run(app, host="127.0.0.1", port=8001)
