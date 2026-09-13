# =========================================================
# VULNGRAPH - EXPLAINABILITY ENGINE
# =========================================================


def generate_explanation(
    dependency_name,
    vulnerability_count,
    trust_score,
    risk_score,
    impact_level,
    priority=None,
    vulnerabilities=None
):
    """
    Generate a clear and explainable security assessment.

    Explains:
    - Vulnerability count
    - Severity distribution
    - Highest CVSS score
    - Malware / supply-chain findings
    - Trust score
    - Impact level
    - Overall risk score
    - Remediation priority
    """

    if vulnerabilities is None:
        vulnerabilities = []

    if not isinstance(vulnerabilities, list):
        vulnerabilities = []

    reasons = []

    # =====================================================
    # NORMALIZE VALUES
    # =====================================================

    try:
        vulnerability_count = int(
            vulnerability_count
        )

    except (
        TypeError,
        ValueError
    ):

        vulnerability_count = len(
            vulnerabilities
        )

    try:
        trust_score = float(
            trust_score
        )

    except (
        TypeError,
        ValueError
    ):

        trust_score = 0.0

    try:
        risk_score = float(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        risk_score = 0.0

    # Keep values inside sensible ranges

    trust_score = max(
        0,
        min(trust_score, 100)
    )

    risk_score = max(
        0,
        min(risk_score, 100)
    )

    if impact_level is None:
        impact_level = "Unknown"

    impact_level = str(
        impact_level
    )

    # =====================================================
    # VULNERABILITY ANALYSIS
    # =====================================================

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    unknown_count = 0
    malware_count = 0

    cvss_scores = []

    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):
            continue

        # -------------------------------------------------
        # Severity
        # -------------------------------------------------

        severity = str(
            vulnerability.get(
                "severity",
                "Unknown"
            )
        ).strip().lower()

        if severity == "critical":

            critical_count += 1

        elif severity == "high":

            high_count += 1

        elif severity == "medium":

            medium_count += 1

        elif severity == "low":

            low_count += 1

        else:

            unknown_count += 1

        # -------------------------------------------------
        # Malware / Supply-chain indicator
        # -------------------------------------------------

        if vulnerability.get(
            "malware_detected",
            False
        ):

            malware_count += 1

        # -------------------------------------------------
        # CVSS
        # -------------------------------------------------

        cvss_score = vulnerability.get(
            "cvss_score",
            "N/A"
        )

        try:

            cvss_scores.append(
                float(cvss_score)
            )

        except (
            TypeError,
            ValueError
        ):

            pass

    # =====================================================
    # VULNERABILITY EXPLANATION
    # =====================================================

    if vulnerability_count == 0:

        reasons.append(
            f"No known vulnerabilities were "
            f"detected in {dependency_name}."
        )

    else:

        reasons.append(
            f"{dependency_name} has "
            f"{vulnerability_count} known "
            f"vulnerability finding(s)."
        )

        severity_parts = []

        if critical_count > 0:

            severity_parts.append(
                f"{critical_count} Critical"
            )

        if high_count > 0:

            severity_parts.append(
                f"{high_count} High"
            )

        if medium_count > 0:

            severity_parts.append(
                f"{medium_count} Medium"
            )

        if low_count > 0:

            severity_parts.append(
                f"{low_count} Low"
            )

        if unknown_count > 0:

            severity_parts.append(
                f"{unknown_count} Unknown"
            )

        if severity_parts:

            reasons.append(
                "Severity distribution: "
                + ", ".join(
                    severity_parts
                )
                + "."
            )

    # =====================================================
    # HIGHEST CVSS
    # =====================================================

    if cvss_scores:

        highest_cvss = max(
            cvss_scores
        )

        reasons.append(
            f"The highest available CVSS "
            f"score is {highest_cvss:.1f}."
        )

    # =====================================================
    # MALWARE / SUPPLY-CHAIN
    # =====================================================

    if malware_count > 0:

        reasons.append(
            f"{malware_count} malware or "
            "supply-chain related finding(s) "
            "were detected, which increases "
            "the security risk."
        )

    else:

        reasons.append(
            "No malware or supply-chain "
            "indicator was detected in the "
            "available vulnerability evidence."
        )

    # =====================================================
    # TRUST ASSESSMENT
    # =====================================================

    if trust_score >= 80:

        reasons.append(
            f"The dependency has a high trust "
            f"score of {trust_score:.2f}%, indicating "
            "strong trust-related characteristics "
            "based on the available package metadata."
        )

    elif trust_score >= 50:

        reasons.append(
            f"The dependency has a moderate trust "
            f"score of {trust_score:.2f}%."
        )

    else:

        reasons.append(
            f"The dependency has a low trust "
            f"score of {trust_score:.2f}%, which "
            "increases trust-related risk."
        )

    # =====================================================
    # IMPACT
    # =====================================================

    reasons.append(
        f"The assessed impact level is "
        f"{impact_level}."
    )

    # =====================================================
    # OVERALL RISK
    # =====================================================

    risk_level = get_risk_level(
        risk_score
    )

    reasons.append(
        f"The calculated overall risk score "
        f"is {risk_score:.2f}%, classified as "
        f"{risk_level}."
    )

    # =====================================================
    # REMEDIATION PRIORITY
    # =====================================================

    # If app.py does not provide priority,
    # derive a reasonable priority from risk level.

    if priority is None:

        if risk_level == "Critical":

            priority = "Critical"

        elif risk_level == "High":

            priority = "High"

        elif risk_level == "Medium":

            priority = "Medium"

        elif risk_level == "Low":

            priority = "Low"

        else:

            priority = "Review"

    # -----------------------------------------------------
    # Priority may be a dictionary
    # -----------------------------------------------------

    if isinstance(
        priority,
        dict
    ):

        priority_value = (

            priority.get(
                "priority"
            )

            or priority.get(
                "level"
            )

            or priority.get(
                "severity"
            )

            or "Review"

        )

    else:

        priority_value = priority

    priority_value = str(
        priority_value
    )

    reasons.append(
        f"Based on the vulnerability, trust, "
        f"impact, and risk factors, the "
        f"recommended remediation priority is "
        f"{priority_value}."
    )

    # =====================================================
    # FINAL EXPLANATION
    # =====================================================

    explanation = " ".join(
        reasons
    )

    return {
        "dependency": dependency_name,
        "explanation": explanation
    }


# =========================================================
# RISK LEVEL HELPER
# =========================================================

def get_risk_level(risk_score):
    """
    Convert numerical risk score into
    a security risk level.
    """

    try:

        risk_score = float(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        return "Unknown"

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