# =========================================================
# VULNGRAPH - RISK ENGINE
# =========================================================


def calculate_risk(
    vulnerabilities,
    trust_score,
    exposure_level="Medium",
    criticality="Medium",
    criticality_level=None
):
    """
    Calculate dependency risk score between 0 and 100.

    Inputs:
        vulnerabilities   -> list of vulnerability dictionaries
        trust_score       -> trust score between 0 and 100
        exposure_level    -> Low / Medium / High
        criticality       -> Low / Medium / High
        criticality_level -> Backward-compatible alias for
                             criticality

    Returns:
        Risk score between 0 and 100.
    """

    # -----------------------------------------------------
    # BACKWARD COMPATIBILITY
    # -----------------------------------------------------
    # app.py may send criticality_level instead of criticality.
    # If it is provided, use it.

    if criticality_level is not None:
        criticality = criticality_level

    # -----------------------------------------------------
    # SAFETY: Ensure vulnerabilities is a list
    # -----------------------------------------------------

    if vulnerabilities is None:
        vulnerabilities = []

    if not isinstance(vulnerabilities, list):
        vulnerabilities = []

    # =====================================================
    # 1. VULNERABILITY RISK
    # =====================================================

    vulnerability_score = 0

    for vuln in vulnerabilities:

        if not isinstance(vuln, dict):
            continue

        severity = str(
            vuln.get("severity", "")
        ).lower().strip()

        if severity == "critical":

            vulnerability_score += 20

        elif severity == "high":

            vulnerability_score += 12

        elif severity == "medium":

            vulnerability_score += 6

        elif severity == "low":

            vulnerability_score += 2

        else:

            vulnerability_score += 1

    # Maximum vulnerability contribution
    vulnerability_score = min(
        vulnerability_score,
        100
    )

    # =====================================================
    # 2. TRUST RISK
    # =====================================================

    try:

        trust_score = float(
            trust_score
        )

    except (
        TypeError,
        ValueError
    ):

        trust_score = 50

    # Keep trust score valid
    trust_score = max(
        0,
        min(trust_score, 100)
    )

    # Lower trust = higher risk
    trust_risk = (
        100 - trust_score
    )

    # =====================================================
    # 3. EXPOSURE RISK
    # =====================================================

    exposure_values = {

        "low": 20,

        "medium": 60,

        "high": 100

    }

    exposure_risk = exposure_values.get(

        str(
            exposure_level
        ).lower().strip(),

        60

    )

    # =====================================================
    # 4. CRITICALITY RISK
    # =====================================================

    criticality_values = {

        "low": 20,

        "medium": 60,

        "high": 100

    }

    criticality_risk = criticality_values.get(

        str(
            criticality
        ).lower().strip(),

        60

    )

    # =====================================================
    # 5. WEIGHTED RISK FORMULA
    # =====================================================
    #
    # Vulnerability : 55%
    # Trust         : 15%
    # Exposure      : 15%
    # Criticality   : 15%
    #
    # Total         : 100%
    #
    # =====================================================

    risk = (

        vulnerability_score * 0.55

        + trust_risk * 0.15

        + exposure_risk * 0.15

        + criticality_risk * 0.15

    )

    # =====================================================
    # 6. NORMALIZE
    # =====================================================

    risk = max(
        0,
        min(risk, 100)
    )

    return round(
        risk,
        2
    )


# =========================================================
# RISK LEVEL
# =========================================================

def get_risk_level(risk_score):
    """
    Convert numerical risk score into a security level.

    0 - 24.99   -> Low
    25 - 49.99  -> Medium
    50 - 74.99  -> High
    75 - 100    -> Critical
    """

    try:

        risk_score = float(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        risk_score = 0

    # Keep score inside valid range

    risk_score = max(
        0,
        min(risk_score, 100)
    )

    if risk_score < 25:

        return "Low"

    elif risk_score < 50:

        return "Medium"

    elif risk_score < 75:

        return "High"

    else:

        return "Critical"
