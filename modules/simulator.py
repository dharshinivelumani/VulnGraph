from modules.risk_engine import calculate_risk


def _safe_vulnerability_list(vulnerabilities):
    """
    Ensure vulnerability data is always handled as a list.
    """
    if not isinstance(vulnerabilities, list):
        return []

    return vulnerabilities


def _get_severity_counts(vulnerabilities):
    """
    Count vulnerabilities by severity.

    Supports common severity field names:
        severity
        level
        cvss_severity
    """

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for vulnerability in vulnerabilities:

        if not isinstance(vulnerability, dict):
            continue

        severity = (
            vulnerability.get("severity")
            or vulnerability.get("level")
            or vulnerability.get("cvss_severity")
            or ""
        )

        severity = str(severity).strip().title()

        if severity in counts:
            counts[severity] += 1

    return counts


def _get_security_recommendation(
    security_status,
    vulnerability_reduction,
    risk_reduction
):
    """
    Generate a security recommendation based on
    simulated risk and vulnerability changes.
    """

    if (
        risk_reduction > 0
        and vulnerability_reduction > 0
    ):
        return (
            "Upgrade recommended. "
            "The target version reduces both calculated "
            "risk and vulnerability exposure."
        )

    if (
        risk_reduction > 0
        and vulnerability_reduction == 0
    ):
        return (
            "Upgrade may be beneficial. "
            "The calculated risk decreases even though "
            "the vulnerability count remains unchanged."
        )

    if (
        risk_reduction == 0
        and vulnerability_reduction > 0
    ):
        return (
            "Upgrade requires further analysis. "
            "Vulnerabilities decrease, but the calculated "
            "risk remains unchanged."
        )

    if risk_reduction < 0:
        return (
            "Upgrade not recommended based on this simulation. "
            "The target version produces higher calculated risk."
        )

    if security_status == "No Change":
        return (
            "No measurable security improvement was observed. "
            "Consider evaluating another target version."
        )

    return (
        "Further security analysis is recommended "
        "before changing the dependency version."
    )


def _get_interpretation(
    current_count,
    target_count,
    current_risk,
    target_risk,
    risk_reduction,
    vulnerability_reduction
):
    """
    Generate an explainable interpretation of the
    What-If simulation.
    """

    if risk_reduction > 0:

        if vulnerability_reduction > 0:
            return (
                f"The simulated version reduces vulnerabilities "
                f"from {current_count} to {target_count}. "
                f"Calculated risk decreases from "
                f"{current_risk} to {target_risk}, "
                f"indicating an improved security posture."
            )

        return (
            f"The simulated version keeps the vulnerability "
            f"count at {target_count}, but calculated risk "
            f"decreases from {current_risk} to {target_risk}. "
            f"This indicates an improvement in the overall "
            f"risk posture."
        )

    if risk_reduction < 0:

        return (
            f"The simulated version increases calculated risk "
            f"from {current_risk} to {target_risk}. "
            f"The target version should therefore be reviewed "
            f"carefully before adoption."
        )

    if vulnerability_reduction > 0:

        return (
            f"The simulated version reduces vulnerabilities "
            f"from {current_count} to {target_count}, "
            f"but the overall calculated risk remains unchanged."
        )

    return (
        "The simulated version does not produce a measurable "
        "security improvement under the current risk model."
    )


def simulate_version_change(
    current_vulnerabilities,
    target_vulnerabilities,
    trust_score,
    exposure_level="Medium",
    criticality="Medium"
):
    """
    Compare current dependency risk with the simulated
    risk after changing to another dependency version.

    The simulator evaluates:

        1. Current risk
        2. Target-version risk
        3. Risk change
        4. Risk reduction
        5. Risk change percentage
        6. Vulnerability change
        7. Severity distribution
        8. Security status
        9. Vulnerability status
        10. Explainable interpretation
        11. Upgrade recommendation

    Existing return keys are preserved so that the
    current Flask application remains compatible.
    """

    # =================================================
    # SAFETY CHECKS
    # =================================================

    current_vulnerabilities = _safe_vulnerability_list(
        current_vulnerabilities
    )

    target_vulnerabilities = _safe_vulnerability_list(
        target_vulnerabilities
    )

    # =================================================
    # CURRENT RISK
    # =================================================

    current_risk = calculate_risk(
        current_vulnerabilities,
        trust_score,
        exposure_level,
        criticality
    )

    # =================================================
    # TARGET VERSION RISK
    # =================================================

    target_risk = calculate_risk(
        target_vulnerabilities,
        trust_score,
        exposure_level,
        criticality
    )

    # =================================================
    # VULNERABILITY COUNTS
    # =================================================

    current_count = len(
        current_vulnerabilities
    )

    target_count = len(
        target_vulnerabilities
    )

    vulnerability_reduction = (
        current_count - target_count
    )

    vulnerability_change = (
        target_count - current_count
    )

    # =================================================
    # RISK CHANGE
    # =================================================

    risk_change = round(
        target_risk - current_risk,
        2
    )

    # Positive value means security improvement.
    risk_reduction = round(
        current_risk - target_risk,
        2
    )

    # =================================================
    # RISK CHANGE PERCENTAGE
    # =================================================

    if current_risk > 0:

        risk_reduction_percentage = round(
            (
                risk_reduction
                / current_risk
            ) * 100,
            2
        )

        risk_change_percentage = round(
            (
                risk_change
                / current_risk
            ) * 100,
            2
        )

    else:

        risk_reduction_percentage = 0.0
        risk_change_percentage = 0.0

    # =================================================
    # VULNERABILITY CHANGE PERCENTAGE
    # =================================================

    if current_count > 0:

        vulnerability_reduction_percentage = round(
            (
                vulnerability_reduction
                / current_count
            ) * 100,
            2
        )

    else:

        vulnerability_reduction_percentage = 0.0

    # =================================================
    # SEVERITY ANALYSIS
    # =================================================

    current_severity_counts = _get_severity_counts(
        current_vulnerabilities
    )

    target_severity_counts = _get_severity_counts(
        target_vulnerabilities
    )

    severity_change = {}

    for severity in current_severity_counts:

        severity_change[severity] = (
            target_severity_counts[severity]
            - current_severity_counts[severity]
        )

    # =================================================
    # SECURITY STATUS
    # =================================================

    if risk_reduction > 0:

        security_status = "Improved"

    elif risk_reduction < 0:

        security_status = "Increased"

    else:

        security_status = "No Change"

    # =================================================
    # VULNERABILITY STATUS
    # =================================================

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

    # =================================================
    # OVERALL SIMULATION RESULT
    # =================================================

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

    elif vulnerability_reduction < 0:

        simulation_result = (
            "The simulated target version introduces "
            "additional vulnerabilities."
        )

    else:

        simulation_result = (
            "The simulated upgrade does not provide "
            "a measurable risk improvement."
        )

    # =================================================
    # RECOMMENDATION
    # =================================================

    recommendation = _get_security_recommendation(
        security_status,
        vulnerability_reduction,
        risk_reduction
    )

    # =================================================
    # EXPLAINABLE INTERPRETATION
    # =================================================

    interpretation = _get_interpretation(
        current_count,
        target_count,
        current_risk,
        target_risk,
        risk_reduction,
        vulnerability_reduction
    )

    # =================================================
    # RETURN SIMULATION RESULT
    # =================================================

    return {

        # -------------------------------------------------
        # EXISTING KEYS
        # -------------------------------------------------

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

        "risk_reduction_percentage":
            risk_reduction_percentage,

        "vulnerability_reduction":
            vulnerability_reduction,

        "security_status":
            security_status,

        "vulnerability_status":
            vulnerability_status,

        "simulation_result":
            simulation_result,

        # -------------------------------------------------
        # NEW WHAT-IF ANALYSIS KEYS
        # -------------------------------------------------

        "risk_change":
            risk_change,

        "risk_change_percentage":
            risk_change_percentage,

        "vulnerability_change":
            vulnerability_change,

        "vulnerability_reduction_percentage":
            vulnerability_reduction_percentage,

        "current_severity_counts":
            current_severity_counts,

        "simulated_severity_counts":
            target_severity_counts,

        "severity_change":
            severity_change,

        "recommendation":
            recommendation,

        "interpretation":
            interpretation,

        # -------------------------------------------------
        # SIMULATION METADATA
        # -------------------------------------------------

        "trust_score":
            trust_score,

        "exposure":
            exposure_level,

        "criticality":
            criticality
    }