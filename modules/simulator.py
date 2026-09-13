from modules.risk_engine import calculate_risk


def simulate_version_change(
    current_vulnerabilities,
    target_vulnerabilities,
    trust_score,
    exposure_level="Medium",
    criticality="Medium"
):
    """
    Compare current dependency risk with the
    simulated risk after upgrading to another version.

    The simulator evaluates:

        1. Current risk
        2. Target-version risk
        3. Risk reduction
        4. Risk reduction percentage
        5. Vulnerability reduction
        6. Security status

    Existing return keys are preserved so that the
    current Flask application remains compatible.
    """

    # -------------------------------------------------
    # Safety checks
    # -------------------------------------------------

    if not isinstance(
        current_vulnerabilities,
        list
    ):
        current_vulnerabilities = []

    if not isinstance(
        target_vulnerabilities,
        list
    ):
        target_vulnerabilities = []

    # -------------------------------------------------
    # Current risk
    # -------------------------------------------------

    current_risk = calculate_risk(
        current_vulnerabilities,
        trust_score,
        exposure_level,
        criticality
    )

    # -------------------------------------------------
    # Target-version risk
    # -------------------------------------------------

    target_risk = calculate_risk(
        target_vulnerabilities,
        trust_score,
        exposure_level,
        criticality
    )

    # -------------------------------------------------
    # Vulnerability counts
    # -------------------------------------------------

    current_count = len(
        current_vulnerabilities
    )

    target_count = len(
        target_vulnerabilities
    )

    vulnerability_reduction = (
        current_count - target_count
    )

    # -------------------------------------------------
    # Risk reduction
    # -------------------------------------------------

    risk_reduction = round(
        current_risk - target_risk,
        2
    )

    # -------------------------------------------------
    # Risk reduction percentage
    #
    # Example:
    # Current risk = 80
    # Target risk  = 40
    #
    # Reduction = 40
    # Reduction % = 50%
    # -------------------------------------------------

    if current_risk > 0:

        risk_reduction_percentage = round(
            (
                risk_reduction
                / current_risk
            ) * 100,
            2
        )

    else:

        risk_reduction_percentage = 0.0

    # -------------------------------------------------
    # Security status
    # -------------------------------------------------

    if risk_reduction > 0:

        security_status = "Improved"

    elif risk_reduction < 0:

        security_status = "Increased"

    else:

        security_status = "No Change"

    # -------------------------------------------------
    # Vulnerability status
    # -------------------------------------------------

    if vulnerability_reduction > 0:

        vulnerability_status = (
            "Vulnerabilities Reduced"
        )

    elif vulnerability_reduction < 0:

        vulnerability_status = (
            "Vulnerabilities Increased"
        )

    else:

        vulnerability_status = (
            "No Vulnerability Change"
        )

    # -------------------------------------------------
    # Overall simulation result
    # -------------------------------------------------

    if (
        risk_reduction > 0
        and vulnerability_reduction > 0
    ):

        simulation_result = (
            "Upgrade improves the security posture."
        )

    elif (
        risk_reduction > 0
        and vulnerability_reduction == 0
    ):

        simulation_result = (
            "Risk is reduced, but the vulnerability "
            "count remains unchanged."
        )

    elif (
        risk_reduction == 0
        and vulnerability_reduction > 0
    ):

        simulation_result = (
            "Vulnerabilities are reduced, but the "
            "overall calculated risk remains unchanged."
        )

    elif risk_reduction < 0:

        simulation_result = (
            "The simulated target version results "
            "in higher calculated risk."
        )

    else:

        simulation_result = (
            "The simulated upgrade does not provide "
            "a measurable risk improvement."
        )

    # -------------------------------------------------
    # Return simulation result
    # -------------------------------------------------

    return {

        # Existing keys
        "current_risk":
            current_risk,

        "simulated_risk":
            target_risk,

        "risk_reduction":
            risk_reduction,

        "current_vulnerability_count":
            current_count,

        "simulated_vulnerability_count":
            target_count,

        # New analysis fields
        "risk_reduction_percentage":
            risk_reduction_percentage,

        "vulnerability_reduction":
            vulnerability_reduction,

        "security_status":
            security_status,

        "vulnerability_status":
            vulnerability_status,

        "simulation_result":
            simulation_result
    }