import streamlit as st
import subprocess
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
sys.path.insert(0, str(SRC_DIR))

from build_attack_graph import build_attack_graph
from query_attack import get_attack_timeline
from llm_analysis import analyze_attack


# ============================================================
# Streamlit configuration
# ============================================================

st.set_page_config(
    page_title="LLM + Neo4j Attack Investigation",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# Header
# ============================================================

st.title("🔐 LLM + Neo4j Security Attack Graph")

st.write(
    """
    This application demonstrates a simulated cybersecurity
    attack using Neo4j Aura, MITRE ATT&CK techniques, and
    a local Llama 3.2 model running through Ollama.
    """
)


# ============================================================
# Session State
# ============================================================

if "simulation_started" not in st.session_state:
    st.session_state.simulation_started = False

if "simulation_process" not in st.session_state:
    st.session_state.simulation_process = None


# ============================================================
# Sidebar
# ============================================================

st.sidebar.header("Attack Simulation")

st.sidebar.write(
    """
    Simulated environment:

    WS01
      ↓
    AppServer
      ↓
    CustomerDB
      ↓
    CustomerData
    """
)

st.sidebar.divider()

st.sidebar.write("**Technology Stack**")

st.sidebar.write(
    """
    • Neo4j Aura  
    • MITRE ATT&CK  
    • Python  
    • Streamlit  
    • Ollama  
    • Llama 3.2
    """
)


# ============================================================
# 1. Initialize Attack Environment
# ============================================================

st.header("1. Initialize Attack Environment")

st.write(
    """
    Create the simulated security environment and MITRE ATT&CK
    technique relationships in Neo4j.
    """
)

if st.button(
    "🗄️ Create Attack Graph",
    use_container_width=True
):

    with st.spinner(
        "Creating attack graph in Neo4j Aura..."
    ):

        try:

            build_attack_graph()

            # Reset simulation state because we created
            # a fresh graph.
            st.session_state.simulation_started = False
            st.session_state.simulation_process = None

            st.success(
                "Attack graph successfully created in Neo4j Aura."
            )

        except Exception as e:

            st.error(
                f"Failed to create attack graph: {e}"
            )


# ============================================================
# 2. Live Attack Simulation
# ============================================================

st.header("2. Live Attack Simulation")

st.write(
    """
    Start a separate Python process that generates synthetic
    attack events and writes them into Neo4j Aura.
    """
)


# ------------------------------------------------------------
# Check whether the simulation process is still running
# ------------------------------------------------------------

process = st.session_state.simulation_process

if process is not None:

    return_code = process.poll()

    if return_code is None:

        st.info(
            "🟢 Live simulation is currently running. "
            "New events are being written to Neo4j Aura."
        )

    else:

        st.session_state.simulation_process = None

        if return_code == 0:

            st.success(
                "✅ Live attack simulation completed."
            )

        else:

            st.error(
                f"Simulation process stopped with "
                f"exit code {return_code}."
            )


# ------------------------------------------------------------
# Start simulation
# ------------------------------------------------------------

if st.button(
    "▶ Start Live Simulation",
    disabled=(
        st.session_state.simulation_process is not None
        and st.session_state.simulation_process.poll() is None
    ),
    use_container_width=True
):

    try:

        process = subprocess.Popen(
            [
                sys.executable,
                str(SRC_DIR / "simulate_attack.py")
            ]
        )

        st.session_state.simulation_process = process
        st.session_state.simulation_started = True

        st.success(
            "🚀 Live attack simulation started."
        )

        st.info(
            "Click **Refresh Events** below to retrieve "
            "new events from Neo4j."
        )

    except Exception as e:

        st.error(
            f"Unable to start simulation: {e}"
        )


# ============================================================
# 3. Retrieve Attack Events
# ============================================================

st.header("3. Live Attack Events")

try:

    timeline = get_attack_timeline()

except Exception as e:

    timeline = []

    st.error(
        f"Unable to retrieve attack events from Neo4j: {e}"
    )


# ============================================================
# Event Summary
# ============================================================

if timeline:

    st.success(
        f"🔎 {len(timeline)} attack event(s) detected in Neo4j."
    )

    # --------------------------------------------------------
    # Summary metrics
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    unique_hosts = list(
        dict.fromkeys(
            event["host"]
            for event in timeline
            if event.get("host")
        )
    )

    unique_techniques = list(
        dict.fromkeys(
            event["technique_id"]
            for event in timeline
            if event.get("technique_id")
        )
    )

    unique_tactics = list(
        dict.fromkeys(
            event["tactic"]
            for event in timeline
            if event.get("tactic")
        )
    )

    with col1:

        st.metric(
            "Events",
            len(timeline)
        )

    with col2:

        st.metric(
            "Hosts",
            len(unique_hosts)
        )

    with col3:

        st.metric(
            "Techniques",
            len(unique_techniques)
        )

    with col4:

        st.metric(
            "Tactics",
            len(unique_tactics)
        )

    st.divider()

    # --------------------------------------------------------
    # Display events
    # --------------------------------------------------------

    for event in timeline:

        stage = event.get("stage", "?")
        event_type = event.get(
            "event_type",
            "Unknown"
        )
        technique_id = event.get(
            "technique_id",
            "Unknown"
        )

        with st.expander(
            f"Stage {stage} — "
            f"{event_type} — "
            f"{technique_id}"
        ):

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    f"**Host:** "
                    f"{event.get('host', 'Unknown')}"
                )

                st.write(
                    f"**Event:** "
                    f"{event_type}"
                )

                st.write(
                    f"**Timestamp:** "
                    f"{event.get('timestamp', 'Unknown')}"
                )

            with col2:

                st.write(
                    f"**Technique:** "
                    f"{technique_id} - "
                    f"{event.get('technique', 'Unknown')}"
                )

                st.write(
                    f"**Tactic:** "
                    f"{event.get('tactic', 'Unknown')}"
                )

            st.write(
                f"**Evidence:** "
                f"{event.get('evidence', 'No evidence')}"
            )


else:

    st.info(
        """
        No attack events have been generated yet.

        Initialize the attack graph first, then start the
        live simulation.
        """
    )


# ============================================================
# Refresh Events
# ============================================================

st.header("Refresh Investigation")

if st.button(
    "🔄 Refresh Events",
    use_container_width=True
):

    st.rerun()


# ============================================================
# 4. Attack Path
# ============================================================

st.header("4. Attack Path")

if timeline:

    st.subheader("Observed Host Progression")

    hosts = list(
        dict.fromkeys(
            event["host"]
            for event in timeline
            if event.get("host")
        )
    )

    if hosts:

        st.success(
            " → ".join(hosts)
        )

    st.subheader("Infrastructure Path")

    st.code(
        """
WS01
  │
  │ CAN_REACH
  ▼
AppServer
  │
  │ CAN_REACH
  ▼
CustomerDB
  │
  │ CONTAINS
  ▼
CustomerData
        """,
        language="text"
    )

else:

    st.info(
        "Attack path will appear once attack events exist."
    )


# ============================================================
# 5. Llama Security Analysis
# ============================================================

st.header("5. 🧠 Llama Security Analysis")

st.write(
    """
    Llama 3.2 analyzes evidence retrieved from Neo4j.
    The model is instructed to use the graph evidence rather
    than inventing attack activity.
    """
)

question = st.text_input(
    "Ask the security analyst",
    placeholder=(
        "What is happening in this attack?"
    )
)


# ------------------------------------------------------------
# Analyze button
# ------------------------------------------------------------

if st.button(
    "🧠 Analyze Attack",
    use_container_width=True
):

    if not timeline:

        st.warning(
            "There are no attack events to analyze yet."
        )

    else:

        with st.spinner(
            "Llama is analyzing the Neo4j evidence..."
        ):

            try:

                analysis = analyze_attack()

                st.subheader(
                    "Security Analysis"
                )

                st.markdown(
                    analysis
                )

            except Exception as e:

                st.error(
                    f"Llama analysis failed: {e}"
                )


# ============================================================
# Footer
# ============================================================

st.divider()

st.caption(
    """
    PhD Research Prototype — LLM + Neo4j + MITRE ATT&CK
    | Synthetic security events only
    """
)