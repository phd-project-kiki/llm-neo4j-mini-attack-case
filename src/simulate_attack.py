import time
import uuid
from datetime import datetime, timezone

from neo4j_connection import get_driver


ATTACK_ID = "ATTACK-001"


ATTACK_EVENTS = [

    {
        "stage": 1,
        "event_type": "Execution",
        "description": "Suspicious PowerShell activity observed on WS01",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "host": "WS01"
    },

    {
        "stage": 2,
        "event_type": "Discovery",
        "description": "System information discovery observed on WS01",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "host": "WS01"
    },

    {
        "stage": 3,
        "event_type": "Discovery",
        "description": "Network service discovery activity observed",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery",
        "host": "WS01"
    },

    {
        "stage": 4,
        "event_type": "Credential Access",
        "description": "Suspicious credential-access activity detected on WS01",
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "host": "WS01"
    },

    {
        "stage": 5,
        "event_type": "Lateral Movement",
        "description": "WS01 initiated an unusual connection to AppServer",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "host": "AppServer"
    },

    {
        "stage": 6,
        "event_type": "Collection",
        "description": "Application server accessed sensitive customer records",
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "tactic": "Collection",
        "host": "AppServer"
    },

    {
        "stage": 7,
        "event_type": "Command and Control",
        "description": "Unusual outbound network communication detected",
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "Command and Control",
        "host": "AppServer"
    },

    {
        "stage": 8,
        "event_type": "Impact",
        "description": "Simulated suspicious modification of application data detected",
        "technique_id": "T1565",
        "technique_name": "Data Manipulation",
        "tactic": "Impact",
        "host": "AppServer"
    }
]


def create_event(
    tx,
    event,
    event_id,
    timestamp,
    previous_event_id
):
    """
    Create one event and connect it to:
    
    Event
       ├── OCCURRED_ON → Host
       └── INDICATES → Technique

    Events are also connected chronologically using
    FOLLOWED_BY.
    """

    result = tx.run("""
        MATCH (host:Host {
            name: $host
        })

        MATCH (technique:Technique {
            id: $technique_id
        })

        CREATE (event:Event {
            id: $event_id,
            attack_id: $attack_id,
            stage: $stage,
            timestamp: $timestamp,
            event_type: $event_type,
            description: $description,
            simulated: true
        })

        CREATE (event)-[:OCCURRED_ON]->(host)

        CREATE (event)-[:INDICATES]->(technique)

        WITH event

        OPTIONAL MATCH (previous:Event {
            id: $previous_event_id
        })

        FOREACH (_ IN CASE
            WHEN previous IS NOT NULL
            THEN [1]
            ELSE []
        END |
            CREATE (previous)-[:FOLLOWED_BY]->(event)
        )

        RETURN event.id AS event_id
    """,
    event_id=event_id,
    attack_id=ATTACK_ID,
    stage=event["stage"],
    timestamp=timestamp,
    event_type=event["event_type"],
    description=event["description"],
    host=event["host"],
    technique_id=event["technique_id"],
    previous_event_id=previous_event_id
    )

    return result.single()["event_id"]


def simulate_attack():

    driver = get_driver()

    previous_event_id = None

    print()
    print("=" * 70)
    print("             MINI ATTACK EVENT SIMULATOR")
    print("=" * 70)
    print()
    print("Environment:")
    print()
    print("    WS01")
    print("      |")
    print("      v")
    print("  AppServer")
    print("      |")
    print("      v")
    print(" CustomerDB")
    print("      |")
    print("      v")
    print("CustomerData")
    print()
    print("=" * 70)
    print()

    try:

        driver.verify_connectivity()

        print("[+] Connected to Neo4j Aura")
        print()

        with driver.session() as session:

            for event in ATTACK_EVENTS:

                event_id = (
                    f"{ATTACK_ID}-"
                    f"EVT-"
                    f"{uuid.uuid4().hex[:8]}"
                )

                timestamp = datetime.now(
                    timezone.utc
                ).isoformat()

                saved_id = session.execute_write(
                    create_event,
                    event,
                    event_id,
                    timestamp,
                    previous_event_id
                )

                print(
                    f"[{timestamp}] "
                    f"STAGE {event['stage']}"
                )

                print(
                    f"    Event:      {saved_id}"
                )

                print(
                    f"    Type:       {event['event_type']}"
                )

                print(
                    f"    Host:       {event['host']}"
                )

                print(
                    f"    ATT&CK:     "
                    f"{event['technique_id']} "
                    f"- "
                    f"{event['technique_name']}"
                )

                print(
                    f"    Evidence:   "
                    f"{event['description']}"
                )

                print(
                    "    Status:     "
                    "✓ Written to Neo4j Aura"
                )

                print("-" * 70)

                previous_event_id = saved_id

                if event["stage"] < len(ATTACK_EVENTS):

                    print(
                        "    Waiting 5 seconds..."
                    )

                    time.sleep(5)

    except KeyboardInterrupt:

        print()
        print("Simulation stopped by user.")

    finally:

        driver.close()

        print()
        print("Neo4j connection closed.")


if __name__ == "__main__":
    simulate_attack()