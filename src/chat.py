"""
Question answering over the attack graph.

The answer is written by the local Ollama model using two kinds of
evidence taken from Neo4j:

1. Passages and facts retrieved by LlamaIndex from the extracted
   knowledge graph (the document that was uploaded).
2. The attack timeline, attack paths and sensitive assets from the
   simulation graph.
"""

import json

from extract_graph import (
    close_graph_store,
    get_embed_model,
    get_extracted_counts,
    get_graph_store,
    get_llm,
)
from query_attack import get_attack_summary


MAX_PASSAGES = 8
MAX_PASSAGE_CHARS = 1500
MAX_TIMELINE_EVENTS = 40


def retrieve_graph_context(question, llm, embed_model):
    """
    Use LlamaIndex to retrieve relevant content from the extracted graph.

    Returns:
        list[str]: retrieved passages / graph facts.
    """
    from llama_index.core import PropertyGraphIndex

    graph_store = get_graph_store()

    try:

        index = PropertyGraphIndex.from_existing(
            property_graph_store=graph_store,
            llm=llm,
            embed_model=embed_model,
            use_async=False,
        )

        retriever = index.as_retriever(include_text=True)

        results = retriever.retrieve(question)

        passages = []

        for result in results:

            content = (result.get_content() or "").strip()

            if content and content not in passages:
                passages.append(content[:MAX_PASSAGE_CHARS])

        return passages[:MAX_PASSAGES]

    finally:
        close_graph_store(graph_store)


def build_chat_prompt(question, passages, evidence):
    """
    Build the prompt sent to the local model.
    """
    if passages:
        passages_text = "\n\n".join(
            f"[{number}] {passage}"
            for number, passage in enumerate(passages, start=1)
        )
    else:
        passages_text = "(nothing retrieved)"

    if evidence and evidence.get("timeline"):
        evidence_text = json.dumps(evidence, indent=2, default=str)
    else:
        evidence_text = "(no simulated attack events in the database)"

    return f"""
You are a cybersecurity analyst answering questions about a SYNTHETIC
attack scenario stored in a Neo4j knowledge graph.

Answer the question using ONLY the evidence below.
If the evidence does not contain the answer, say so plainly.
Do not invent events, hosts, techniques or actors.
Keep the answer short and specific, and mention MITRE ATT&CK
technique IDs where they are relevant.

EVIDENCE FROM THE EXTRACTED KNOWLEDGE GRAPH (LlamaIndex retrieval):

{passages_text}

EVIDENCE FROM THE ATTACK SIMULATION GRAPH (timeline, paths, assets):

{evidence_text}

QUESTION:

{question}

ANSWER:
"""


def answer_question(question):
    """
    Answer a question about the attack graph.

    Returns:
        dict with the answer, how much evidence was used, and any notes
        about evidence that could not be retrieved.
    """
    question = (question or "").strip()

    if not question:
        raise ValueError("Please enter a question.")

    notes = []

    llm = get_llm()

    # --------------------------------------------------------
    # 1. Retrieval from the extracted knowledge graph
    # --------------------------------------------------------

    passages = []

    try:

        counts = get_extracted_counts()

        if counts["entities"] or counts["chunks"]:

            passages = retrieve_graph_context(
                question,
                llm,
                get_embed_model(),
            )

        else:

            notes.append(
                "No extracted knowledge graph yet. "
                "Run an extraction to add document knowledge."
            )

    except Exception as error:

        notes.append(f"Graph retrieval was skipped: {error}")

    # --------------------------------------------------------
    # 2. Evidence from the simulation graph
    # --------------------------------------------------------

    evidence = None

    try:

        evidence = get_attack_summary()

        if len(evidence["timeline"]) > MAX_TIMELINE_EVENTS:

            evidence["timeline"] = (
                evidence["timeline"][-MAX_TIMELINE_EVENTS:]
            )

            notes.append(
                f"Only the latest {MAX_TIMELINE_EVENTS} events "
                "were used."
            )

    except Exception as error:

        notes.append(f"Attack timeline was skipped: {error}")

    # --------------------------------------------------------
    # 3. Ask the local model
    # --------------------------------------------------------

    prompt = build_chat_prompt(question, passages, evidence)

    response = llm.complete(prompt)

    return {
        "answer": (response.text or "").strip(),
        "graph_passages": len(passages),
        "timeline_events": (
            len(evidence["timeline"]) if evidence else 0
        ),
        "notes": notes,
    }


if __name__ == "__main__":

    import sys

    asked = " ".join(sys.argv[1:]) or "Which techniques did FIN7 use?"

    print(f"Question: {asked}")
    print()

    result = answer_question(asked)

    print(result["answer"])
