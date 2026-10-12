from neo4j_connection import get_driver


def clear_demo_graph(tx):
    """
    Remove the existing demonstration graph.

    Only the hand-built demonstration graph is removed. Nodes created
    by the LlamaIndex extraction carry the __Node__ label and are kept.
    """

    tx.run("""
        MATCH (n)
        WHERE NOT n:__Node__
        DETACH DELETE n
    """)


def create_environment(tx):
    """
    Create the simulated victim environment.

    Environment:

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
    """

    tx.run("""
        MERGE (ws:Host {
            name: "WS01"
        })
        SET
            ws.type = "Windows Workstation",
            ws.ip = "10.0.1.20",
            ws.criticality = "Medium"

        MERGE (app:Host {
            name: "AppServer"
        })
        SET
            app.type = "Application Server",
            app.ip = "10.0.2.10",
            app.criticality = "High"

        MERGE (db:Database {
            name: "CustomerDB"
        })
        SET
            db.type = "Customer Database",
            db.criticality = "Critical"

        MERGE (data:DataAsset {
            name: "CustomerData"
        })
        SET
            data.sensitivity = "High"

        MERGE (ws)-[:CAN_REACH]->(app)

        MERGE (app)-[:CAN_REACH]->(db)

        MERGE (db)-[:CONTAINS]->(data)
    """)


def create_attack_techniques(tx):
    """
    Create the MITRE ATT&CK threat actor, techniques,
    tactics, and relationships.

    Threat Actor:
        FIN7 (G0046)
    """

    # ---------------------------------------------------------
    # Create FIN7
    # ---------------------------------------------------------

    tx.run("""
        MERGE (fin7:ThreatActor {
            id: "G0046"
        })

        SET fin7.name = "FIN7"
    """)

    # ---------------------------------------------------------
    # ATT&CK techniques used in this synthetic scenario
    # ---------------------------------------------------------

    techniques = [

        {
            "id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution"
        },

        {
            "id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery"
        },

        {
            "id": "T1046",
            "name": "Network Service Scanning",
            "tactic": "Discovery"
        },

        {
            "id": "T1555",
            "name": "Credentials from Password Stores",
            "tactic": "Credential Access"
        },

        {
            "id": "T1021",
            "name": "Remote Services",
            "tactic": "Lateral Movement"
        },

        {
            "id": "T1213",
            "name": "Data from Information Repositories",
            "tactic": "Collection"
        },

        {
            "id": "T1071.001",
            "name": "Web Protocols",
            "tactic": "Command and Control"
        },

        {
            "id": "T1565",
            "name": "Data Manipulation",
            "tactic": "Impact"
        }
    ]

    # ---------------------------------------------------------
    # Create techniques, tactics, and relationships
    # ---------------------------------------------------------

    for technique in techniques:

        tx.run("""
            MERGE (fin7:ThreatActor {
                id: "G0046"
            })

            SET fin7.name = "FIN7"

            MERGE (t:Technique {
                id: $id
            })

            SET t.name = $name

            MERGE (tactic:Tactic {
                name: $tactic
            })

            MERGE (t)-[:PART_OF]->(tactic)

            MERGE (fin7)-[:USES]->(t)
        """,
        id=technique["id"],
        name=technique["name"],
        tactic=technique["tactic"])


def create_attack_relationships(tx):
    """
    Connect the simulated victim environment
    to the ATT&CK techniques.
    """

    tx.run("""
        MATCH
            (ws:Host {
                name: "WS01"
            }),

            (app:Host {
                name: "AppServer"
            }),

            (db:Database {
                name: "CustomerDB"
            }),

            (powershell:Technique {
                id: "T1059.001"
            }),

            (systemDiscovery:Technique {
                id: "T1082"
            }),

            (networkScanning:Technique {
                id: "T1046"
            }),

            (credentialStores:Technique {
                id: "T1555"
            }),

            (remoteServices:Technique {
                id: "T1021"
            }),

            (dataRepositories:Technique {
                id: "T1213"
            }),

            (webProtocols:Technique {
                id: "T1071.001"
            }),

            (dataManipulation:Technique {
                id: "T1565"
            })

        MERGE (ws)-[:ASSOCIATED_WITH]->(powershell)

        MERGE (ws)-[:ASSOCIATED_WITH]->(systemDiscovery)

        MERGE (ws)-[:ASSOCIATED_WITH]->(networkScanning)

        MERGE (ws)-[:ASSOCIATED_WITH]->(credentialStores)

        MERGE (ws)-[:ASSOCIATED_WITH]->(remoteServices)

        MERGE (app)-[:ASSOCIATED_WITH]->(remoteServices)

        MERGE (app)-[:ASSOCIATED_WITH]->(dataRepositories)

        MERGE (app)-[:ASSOCIATED_WITH]->(webProtocols)

        MERGE (db)-[:ASSOCIATED_WITH]->(dataManipulation)
    """)


def create_attack_events(tx):
    """
    Create simulated security events.

    These events are synthetic events for the
    research/demo attack scenario.

    Each event connects to:

        Event
          |
          | INDICATES
          v
        Technique

    and:

        Event
          |
          | OCCURRED_ON
          v
        Host
    """

    events = [

        {
            "id": "EVT001",
            "timestamp": "2026-09-03T10:01:00",
            "type": "Process Creation",
            "description": "PowerShell executed on WS01",
            "technique": "T1059.001",
            "host": "WS01"
        },

        {
            "id": "EVT002",
            "timestamp": "2026-09-03T10:05:00",
            "type": "Discovery",
            "description": "System information discovery performed on WS01",
            "technique": "T1082",
            "host": "WS01"
        },

        {
            "id": "EVT003",
            "timestamp": "2026-09-03T10:08:00",
            "type": "Network Activity",
            "description": "Network service scanning detected from WS01",
            "technique": "T1046",
            "host": "WS01"
        },

        {
            "id": "EVT004",
            "timestamp": "2026-09-03T10:12:00",
            "type": "Credential Access",
            "description": "Credential access activity associated with password stores",
            "technique": "T1555",
            "host": "WS01"
        },

        {
            "id": "EVT005",
            "timestamp": "2026-09-03T10:18:00",
            "type": "Lateral Movement",
            "description": "Remote service connection from WS01 to AppServer",
            "technique": "T1021",
            "host": "WS01"
        },

        {
            "id": "EVT006",
            "timestamp": "2026-09-03T10:25:00",
            "type": "Collection",
            "description": "Information repository accessed on AppServer",
            "technique": "T1213",
            "host": "AppServer"
        },

        {
            "id": "EVT007",
            "timestamp": "2026-09-03T10:30:00",
            "type": "Command and Control",
            "description": "Web protocol communication observed",
            "technique": "T1071.001",
            "host": "AppServer"
        },

        {
            "id": "EVT008",
            "timestamp": "2026-09-03T10:40:00",
            "type": "Impact",
            "description": "Data manipulation activity detected in CustomerDB",
            "technique": "T1565",
            "host": "CustomerDB"
        }
    ]

    # ---------------------------------------------------------
    # Insert each event into Neo4j
    # ---------------------------------------------------------

    for event in events:

        tx.run("""
            MERGE (e:Event {
                id: $id
            })

            SET
                e.timestamp = $timestamp,
                e.type = $type,
                e.description = $description

            WITH e

            MATCH (t:Technique {
                id: $technique
            })

            MATCH (host)
            WHERE host.name = $host

            MERGE (e)-[:INDICATES]->(t)

            MERGE (e)-[:OCCURRED_ON]->(host)
        """,
        id=event["id"],
        timestamp=event["timestamp"],
        type=event["type"],
        description=event["description"],
        technique=event["technique"],
        host=event["host"])


def build_attack_graph():
    """
    Main function that builds the complete
    synthetic cybersecurity attack graph.
    """

    driver = get_driver()

    try:

        with driver.session() as session:

            # -------------------------------------------------
            # STEP 1
            # Clear previous graph
            # -------------------------------------------------

            print("Clearing previous demonstration graph...")

            session.execute_write(
                clear_demo_graph
            )

            # -------------------------------------------------
            # STEP 2
            # Create victim environment
            # -------------------------------------------------

            print("Creating victim environment...")

            session.execute_write(
                create_environment
            )

            # -------------------------------------------------
            # STEP 3
            # Create FIN7 and ATT&CK techniques
            # -------------------------------------------------

            print("Creating ATT&CK techniques and FIN7...")

            session.execute_write(
                create_attack_techniques
            )

            # -------------------------------------------------
            # STEP 4
            # Connect environment to techniques
            # -------------------------------------------------

            print("Creating attack relationships...")

            session.execute_write(
                create_attack_relationships
            )

            # -------------------------------------------------
            # STEP 5
            # Create simulated attack events
            # -------------------------------------------------

            print("Creating simulated attack events...")

            session.execute_write(
                create_attack_events
            )

            # -------------------------------------------------
            # SUCCESS
            # -------------------------------------------------

            print()
            print("Attack graph created successfully.")

    finally:

        driver.close()


# =============================================================
# PROGRAM ENTRY POINT
# =============================================================

if __name__ == "__main__":
    build_attack_graph()