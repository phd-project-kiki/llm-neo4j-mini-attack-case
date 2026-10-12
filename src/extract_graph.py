"""
LlamaIndex extraction.

Reads a text document, sends it chunk by chunk to a local Ollama model,
and writes the extracted entities and relationships to Neo4j.

    Document -> LlamaIndex -> Ollama (Llama 3.2) -> Neo4j

Extracted nodes are written with upper-case labels (TECHNIQUE, HOST, ...)
plus the LlamaIndex marker labels __Node__ and __Entity__. This keeps them
separate from the hand-built simulation graph (Technique, Host, ...), so
the two can live in the same database without interfering.
"""

import os
from pathlib import Path
from typing import Literal

from neo4j_connection import get_connection_settings, get_driver


# ============================================================
# Schema the LLM is asked to follow
# ============================================================

EntityType = Literal[
    "THREAT_ACTOR",
    "TECHNIQUE",
    "TACTIC",
    "HOST",
    "DATABASE",
    "DATA_ASSET",
    "EVENT",
]

RelationType = Literal[
    "USES",
    "PART_OF",
    "INDICATES",
    "OCCURRED_ON",
    "FOLLOWED_BY",
    "CAN_REACH",
    "CONTAINS",
    "TARGETS",
    "USED_ON",
]

# Which relationships are allowed between which entity types.
VALIDATION_SCHEMA = [
    ("THREAT_ACTOR", "USES", "TECHNIQUE"),
    ("THREAT_ACTOR", "TARGETS", "HOST"),
    ("THREAT_ACTOR", "TARGETS", "DATABASE"),
    ("THREAT_ACTOR", "TARGETS", "DATA_ASSET"),
    ("TECHNIQUE", "PART_OF", "TACTIC"),
    ("TECHNIQUE", "USED_ON", "HOST"),
    ("TECHNIQUE", "USED_ON", "DATABASE"),
    ("EVENT", "INDICATES", "TECHNIQUE"),
    ("EVENT", "OCCURRED_ON", "HOST"),
    ("EVENT", "OCCURRED_ON", "DATABASE"),
    ("EVENT", "FOLLOWED_BY", "EVENT"),
    ("HOST", "CAN_REACH", "HOST"),
    ("HOST", "CAN_REACH", "DATABASE"),
    ("DATABASE", "CONTAINS", "DATA_ASSET"),
]

SUPPORTED_EXTENSIONS = {".txt", ".md"}


# ============================================================
# Ollama and Neo4j helpers
# ============================================================

def ollama_settings():
    """
    Ollama settings, read from the environment (.env_pipeline).
    """
    return {
        "base_url": os.getenv(
            "OLLAMA_BASE_URL", "http://localhost:11434"
        ).rstrip("/"),
        "llm_model": os.getenv("OLLAMA_LLM_MODEL", "llama3.2"),
        "embed_model": os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
        "timeout": float(os.getenv("OLLAMA_REQUEST_TIMEOUT", "600")),
    }


def get_llm():
    """
    Local chat model served by Ollama.
    """
    from llama_index.llms.ollama import Ollama

    settings = ollama_settings()

    return Ollama(
        model=settings["llm_model"],
        base_url=settings["base_url"],
        request_timeout=settings["timeout"],
        temperature=0.0,
    )


def get_embed_model():
    """
    Local embedding model served by Ollama.
    """
    from llama_index.embeddings.ollama import OllamaEmbedding

    settings = ollama_settings()

    return OllamaEmbedding(
        model_name=settings["embed_model"],
        base_url=settings["base_url"],
    )


def get_graph_store():
    """
    LlamaIndex property graph store backed by Neo4j.

    Requires the APOC plugin in the Neo4j database.
    """
    from llama_index.graph_stores.neo4j import Neo4jPropertyGraphStore

    connection = get_connection_settings()

    return Neo4jPropertyGraphStore(
        username=connection["username"],
        password=connection["password"] or "",
        url=connection["uri"],
        database=connection["database"],
    )


def close_graph_store(store):
    """
    Close the store's Neo4j driver if it exposes one.
    """
    try:
        if hasattr(store, "close"):
            store.close()
    except Exception:
        pass


# ============================================================
# Counting and clearing the extracted graph
# ============================================================

def get_extracted_counts():
    """
    Count what the LlamaIndex extraction has written to Neo4j.
    """
    driver = get_driver()

    try:
        with driver.session() as session:
            record = session.run("""
                OPTIONAL MATCH (e:__Entity__)
                WITH count(e) AS entities
                OPTIONAL MATCH (:__Entity__)-[r]->(:__Entity__)
                WITH entities, count(r) AS relationships
                OPTIONAL MATCH (c:__Node__:Chunk)
                RETURN entities, relationships, count(c) AS chunks
            """).single()

            return {
                "entities": record["entities"],
                "relationships": record["relationships"],
                "chunks": record["chunks"],
            }

    finally:
        driver.close()


def clear_extracted_graph():
    """
    Remove everything the LlamaIndex extraction created.

    The hand-built simulation graph is not touched.
    """
    driver = get_driver()

    try:
        with driver.session() as session:
            session.run("""
                MATCH (n:__Node__)
                DETACH DELETE n
            """).consume()

    finally:
        driver.close()


# ============================================================
# Extraction
# ============================================================

def extract_document(file_path, strict=True, on_progress=None):
    """
    Extract a knowledge graph from one document and store it in Neo4j.

    Parameters:
        file_path:
            Path to a .txt or .md file.

        strict:
            True  -> keep only entities and relationships that match
                     the schema above (cleaner graph).
            False -> let the model add other types as well.

        on_progress:
            Optional function called with a short status message.

    Returns:
        dict: counts of what is in the extracted graph afterwards.
    """
    from llama_index.core import Document, PropertyGraphIndex
    from llama_index.core.indices.property_graph import (
        SchemaLLMPathExtractor,
    )
    from llama_index.core.node_parser import SentenceSplitter

    def report(message):
        if on_progress:
            on_progress(message)

    path = Path(file_path)

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{path.suffix}'. "
            "Use a .txt or .md file."
        )

    report("Reading document")

    text = path.read_text(encoding="utf-8", errors="ignore").strip()

    if not text:
        raise ValueError(f"{path.name} is empty.")

    documents = [
        Document(
            text=text,
            metadata={"file_name": path.name},
        )
    ]

    settings = ollama_settings()

    report("Connecting to Ollama and Neo4j")

    llm = get_llm()
    embed_model = get_embed_model()
    graph_store = get_graph_store()

    try:

        extractor = SchemaLLMPathExtractor(
            llm=llm,
            possible_entities=EntityType,
            possible_relations=RelationType,
            kg_validation_schema=VALIDATION_SCHEMA,
            strict=strict,
            max_triplets_per_chunk=15,
            num_workers=1,
        )

        report(
            f"Extracting entities with {settings['llm_model']} "
            "(this can take several minutes)"
        )

        PropertyGraphIndex.from_documents(
            documents,
            llm=llm,
            embed_model=embed_model,
            kg_extractors=[extractor],
            property_graph_store=graph_store,
            transformations=[
                SentenceSplitter(
                    chunk_size=512,
                    chunk_overlap=50,
                )
            ],
            show_progress=False,
            # Synchronous mode: the async mode opens and closes several
            # event loops while reusing one Ollama client, which fails
            # with "Event loop is closed".
            use_async=False,
        )

    finally:
        close_graph_store(graph_store)

    report("Counting extracted nodes")

    return get_extracted_counts()


if __name__ == "__main__":

    import sys

    default_file = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "fin7_attack_case_report.txt"
    )

    target = sys.argv[1] if len(sys.argv) > 1 else default_file

    print(f"Extracting graph from {target} ...")

    counts = extract_document(target, on_progress=print)

    print()
    print("Extraction complete.")
    print(counts)
