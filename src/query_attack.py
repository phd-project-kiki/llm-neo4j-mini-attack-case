from neo4j_connection import get_driver


def get_attack_timeline():
    """
    Retrieve the chronological attack timeline from Neo4j.

    Returns:
        list: A list of dictionaries containing:
            - event ID
            - timestamp
            - event type
            - description
            - MITRE ATT&CK technique
            - technique ID
            - tactic
            - host
    """

    driver = get_driver()

    query = """
        MATCH (e:Event)-[:INDICATES]->(t:Technique)
        MATCH (e)-[:OCCURRED_ON]->(host)

        OPTIONAL MATCH (t)-[:PART_OF]->(tactic:Tactic)

        RETURN
            e.id AS event_id,
            e.timestamp AS timestamp,
            coalesce(e.type, e.event_type) AS event_type,
            e.description AS description,

            t.id AS technique_id,
            t.name AS technique,

            tactic.name AS tactic,

            host.name AS host,
            host.type AS host_type,
            host.ip AS host_ip,
            host.criticality AS host_criticality

        ORDER BY e.timestamp
    """

    try:

        with driver.session() as session:

            result = session.run(query)

            timeline = []

            for record in result:

                timeline.append({
                    "event_id": record["event_id"],
                    "timestamp": record["timestamp"],
                    "event_type": record["event_type"],
                    "description": record["description"],
                    "technique_id": record["technique_id"],
                    "technique": record["technique"],
                    "tactic": record["tactic"],
                    "host": record["host"],
                    "host_type": record["host_type"],
                    "host_ip": record["host_ip"],
                    "host_criticality": record["host_criticality"]
                })

            return timeline

    finally:

        driver.close()


def get_attack_path():
    """
    Retrieve the infrastructure path associated with the attack.

    Current environment:

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

    Returns:
        list: Attack infrastructure paths.
    """

    driver = get_driver()

    query = """
        MATCH path =
            (source:Host {name: "WS01"})
            -[:CAN_REACH*1..]->
            (target)

        RETURN
            [node IN nodes(path) |
                {
                    name: node.name,
                    type: labels(node)[0],
                    criticality: node.criticality,
                    sensitivity: node.sensitivity
                }
            ] AS attack_path
    """

    try:

        with driver.session() as session:

            result = session.run(query)

            paths = []

            for record in result:

                paths.append(
                    record["attack_path"]
                )

            return paths

    finally:

        driver.close()


def get_sensitive_assets():
    """
    Find sensitive assets that may be reachable
    through the simulated environment.

    Returns:
        list: Sensitive data assets and their database path.
    """

    driver = get_driver()

    query = """
        MATCH path =
            (host:Host)
            -[:CAN_REACH*0..2]->
            (db:Database)
            -[:CONTAINS]->
            (data:DataAsset)

        RETURN
            host.name AS source_host,
            db.name AS database,
            db.criticality AS database_criticality,
            data.name AS data_asset,
            data.sensitivity AS sensitivity

        ORDER BY data.sensitivity DESC
    """

    try:

        with driver.session() as session:

            result = session.run(query)

            assets = []

            for record in result:

                assets.append({
                    "source_host": record["source_host"],
                    "database": record["database"],
                    "database_criticality": record["database_criticality"],
                    "data_asset": record["data_asset"],
                    "sensitivity": record["sensitivity"]
                })

            return assets

    finally:

        driver.close()


def get_attack_summary():
    """
    Retrieve a combined evidence package for the LLM.

    This function does NOT call the LLM.

    It only retrieves evidence from Neo4j.

    Returns:
        dict: Structured attack evidence.
    """

    timeline = get_attack_timeline()

    attack_paths = get_attack_path()

    sensitive_assets = get_sensitive_assets()

    return {
        "timeline": timeline,
        "attack_paths": attack_paths,
        "sensitive_assets": sensitive_assets
    }


def print_attack_timeline():
    """
    Print the attack timeline in a human-readable format.
    """

    timeline = get_attack_timeline()

    print()
    print("=" * 80)
    print("ATTACK TIMELINE")
    print("=" * 80)

    for event in timeline:

        print()
        print(f"Event ID:       {event['event_id']}")
        print(f"Timestamp:      {event['timestamp']}")
        print(f"Type:           {event['event_type']}")
        print(f"Description:    {event['description']}")
        print(f"Technique:      {event['technique_id']} - {event['technique']}")
        print(f"Tactic:         {event['tactic']}")
        print(f"Host:           {event['host']}")
        print(f"Host IP:        {event['host_ip']}")
        print(f"Criticality:    {event['host_criticality']}")

    print()
    print("=" * 80)


def print_sensitive_assets():
    """
    Print sensitive assets discovered through the graph.
    """

    assets = get_sensitive_assets()

    print()
    print("=" * 80)
    print("SENSITIVE ASSETS")
    print("=" * 80)

    for asset in assets:

        print()
        print(f"Source Host:        {asset['source_host']}")
        print(f"Database:           {asset['database']}")
        print(f"Database Criticality: {asset['database_criticality']}")
        print(f"Data Asset:         {asset['data_asset']}")
        print(f"Sensitivity:        {asset['sensitivity']}")

    print()
    print("=" * 80)


if __name__ == "__main__":

    print_attack_timeline()

    print_sensitive_assets()

    print()
    print("=" * 80)
    print("ATTACK PATHS")
    print("=" * 80)

    paths = get_attack_path()

    for path in paths:

        print()

        for node in path:

            print(
                f"{node['type']}: "
                f"{node['name']}"
            )