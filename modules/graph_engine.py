def get_impact_level(vulnerability_count):
    """
    Determine dependency impact level
    based on known vulnerabilities.
    """

    if vulnerability_count == 0:
        return "Low"

    elif vulnerability_count <= 4:
        return "Medium"

    else:
        return "High"


def build_dependency_graph(
    dependencies,
    relationships=None,
    scan_results=None
):
    """
    Build dependency graph using actual
    parent -> child relationships.

    Each node contains:
    - Dependency type
    - Installed version
    - Vulnerability count
    - Impact level
    - Risk score (when available)
    - Trust score (when available)

    Each edge contains:
    - Parent
    - Child
    - Direct / Transitive relationship
    """

    graph = {
        "nodes": [],
        "edges": []
    }

    # ---------------------------------------------------------
    # Build vulnerability / dependency lookup
    # ---------------------------------------------------------

    scan_lookup = {}

    if scan_results:

        for result in scan_results:

            if not isinstance(result, dict):
                continue

            name = result.get("name")

            if name:
                scan_lookup[name] = result

    # ---------------------------------------------------------
    # Project root node
    # ---------------------------------------------------------

    graph["nodes"].append({
        "id": "project",
        "label": "Project",
        "type": "project",
        "dependency_type": "project",
        "vulnerability_count": 0,
        "impact_level": "Low"
    })

    # ---------------------------------------------------------
    # Add dependency nodes
    # ---------------------------------------------------------

    for dependency in dependencies:

        result = scan_lookup.get(
            dependency,
            {}
        )

        # -----------------------------------------------------
        # Vulnerabilities
        # -----------------------------------------------------

        vulnerabilities = result.get(
            "vulnerabilities",
            []
        )

        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        vulnerability_count = len(
            vulnerabilities
        )

        impact_level = get_impact_level(
            vulnerability_count
        )

        # -----------------------------------------------------
        # Dependency type
        # -----------------------------------------------------

        dependency_type = "transitive"

        if relationships:

            for relationship in relationships:

                if not isinstance(
                    relationship,
                    dict
                ):
                    continue

                if (
                    relationship.get("child")
                    == dependency
                    and
                    relationship.get("parent")
                    == "project"
                ):
                    dependency_type = "direct"
                    break

        # -----------------------------------------------------
        # Installed version
        # -----------------------------------------------------

        installed_version = (
            result.get("installed_version")
            or result.get("version")
            or result.get("resolved_version")
            or result.get("current_version")
        )

        # -----------------------------------------------------
        # Risk score
        # -----------------------------------------------------

        risk_score = (
            result.get("risk_score")
            if result.get("risk_score") is not None
            else result.get("risk")
        )

        # -----------------------------------------------------
        # Trust score
        # -----------------------------------------------------

        trust_score = (
            result.get("trust_score")
            if result.get("trust_score") is not None
            else result.get("trust")
        )

        # -----------------------------------------------------
        # Create node
        # -----------------------------------------------------

        node = {

            "id": dependency,

            "label": dependency,

            "type": "dependency",

            "dependency_type":
                dependency_type,

            "vulnerability_count":
                vulnerability_count,

            "impact_level":
                impact_level,

            "installed_version":
                installed_version,

            "version":
                installed_version,

            "risk_score":
                risk_score,

            "trust_score":
                trust_score
        }

        graph["nodes"].append(node)

    # ---------------------------------------------------------
    # Add actual dependency relationships
    # ---------------------------------------------------------

    if relationships:

        for relationship in relationships:

            if not isinstance(
                relationship,
                dict
            ):
                continue

            parent = relationship.get(
                "parent"
            )

            child = relationship.get(
                "child"
            )

            relationship_type = relationship.get(
                "type",
                "dependency"
            )

            if not parent or not child:
                continue

            graph["edges"].append({

                "source":
                    parent,

                "target":
                    child,

                "type":
                    relationship_type
            })

    return graph