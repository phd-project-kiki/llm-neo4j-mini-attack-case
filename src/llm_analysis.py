import json
import os

from openai import OpenAI

from query_attack import get_attack_summary


# ============================================================
# Ollama / Llama 3.2 Configuration
# ============================================================

OLLAMA_BASE_URL = (
    os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    + "/v1"
)

MODEL = os.getenv("OLLAMA_LLM_MODEL", "llama3.2")


client = OpenAI(
    base_url=OLLAMA_BASE_URL,
    api_key="ollama"
)


# ============================================================
# Build the LLM Prompt
# ============================================================

def build_analysis_prompt(attack_evidence):
    """
    Build the prompt that will be sent to Llama 3.2.

    The LLM receives evidence retrieved from Neo4j.
    It should analyze the evidence rather than invent
    additional attack activity.
    """

    evidence_json = json.dumps(
        attack_evidence,
        indent=2
    )

    prompt = f"""
You are a cybersecurity threat analyst.

You are analyzing a SYNTHETIC cybersecurity attack scenario
created for a research project involving:

- Neo4j knowledge graphs
- MITRE ATT&CK
- Large Language Models
- Cybersecurity attack investigation

IMPORTANT:

The information below was retrieved from a Neo4j knowledge graph.

Treat the information as evidence.

Do NOT invent events, systems, users, vulnerabilities,
or attack techniques that are not supported by the evidence.

Clearly distinguish between:

1. Observed evidence
2. Reasonable inference
3. Unknown information

The simulated threat actor is FIN7 (MITRE ATT&CK group G0046).

The scenario contains a simulated environment:

WS01
   |
   | CAN_REACH
   v
AppServer
   |
   | CAN_REACH
   v
CustomerDB
   |
   | CONTAINS
   v
CustomerData

Analyze the following Neo4j evidence:

{evidence_json}

Provide your analysis using the following structure:

1. ATTACK SUMMARY

Explain what happened in chronological order.

2. ATTACK TIMELINE

Identify the major stages of the attack and the
corresponding MITRE ATT&CK techniques.

3. ATTACK PATH

Explain how the attack moved through the environment.

4. MITRE ATT&CK ANALYSIS

For each observed technique, explain its role in
the attack.

5. AFFECTED SYSTEMS

Identify the systems involved and their importance.

6. SENSITIVE ASSETS

Identify sensitive assets that could potentially
be affected based only on the graph evidence.

7. ATTACK IMPACT

Explain the potential security impact.

8. DETECTION OPPORTUNITIES

Identify points in the attack where a security
monitoring system could potentially detect the activity.

9. RECOMMENDED RESPONSE

Provide defensive recommendations based on the
observed evidence.

10. CONFIDENCE AND LIMITATIONS

Explain what is directly supported by the graph
and what cannot be determined from the available evidence.

Remember:

This is a synthetic research scenario.

Do not present the simulated events as real-world
FIN7 activity.

Do not claim that FIN7 actually performed these
specific events in this specific environment.
"""

    return prompt


# ============================================================
# Analyze Attack
# ============================================================

def analyze_attack(attack_evidence=None):
    """
    Send Neo4j attack evidence to Llama 3.2.

    Parameters:
        attack_evidence:
            Structured evidence returned by
            get_attack_summary().

            If None, the function retrieves the
            evidence directly from Neo4j.

    Returns:
        str:
            LLM-generated cybersecurity analysis.
    """

    # --------------------------------------------------------
    # Get evidence from Neo4j if none was supplied
    # --------------------------------------------------------

    if attack_evidence is None:

        attack_evidence = get_attack_summary()

    # --------------------------------------------------------
    # Build the prompt
    # --------------------------------------------------------

    prompt = build_analysis_prompt(
        attack_evidence
    )

    # --------------------------------------------------------
    # Send request to local Llama 3.2
    # --------------------------------------------------------

    response = client.chat.completions.create(
        model=MODEL,

        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity threat "
                    "analysis assistant. "
                    "Analyze only the evidence provided."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],

        temperature=0
    )

    # --------------------------------------------------------
    # Extract LLM response
    # --------------------------------------------------------

    analysis = response.choices[0].message.content

    return analysis


# ============================================================
# Main Program
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 80)
    print("LLM + NEO4J ATTACK ANALYSIS")
    print("=" * 80)

    try:

        # ----------------------------------------------------
        # Step 1:
        # Retrieve evidence from Neo4j
        # ----------------------------------------------------

        print()
        print("Retrieving attack evidence from Neo4j...")

        attack_evidence = get_attack_summary()

        print("Attack evidence retrieved successfully.")

        # ----------------------------------------------------
        # Step 2:
        # Send evidence to Llama 3.2
        # ----------------------------------------------------

        print()
        print("Sending evidence to Llama 3.2...")

        analysis = analyze_attack(
            attack_evidence
        )

        # ----------------------------------------------------
        # Step 3:
        # Display analysis
        # ----------------------------------------------------

        print()
        print("=" * 80)
        print("SECURITY ANALYSIS")
        print("=" * 80)

        print()
        print(analysis)

        print()
        print("=" * 80)

    except Exception as error:

        print()
        print("=" * 80)
        print("ERROR")
        print("=" * 80)

        print()
        print(error)

        print()
        print("Make sure Ollama is running and that")
        print("the llama3.2 model is installed.")