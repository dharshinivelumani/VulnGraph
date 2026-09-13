def parse_version(version):
    """
    Convert a version string into a comparable tuple.

    Examples:
        4.2.30 -> (4, 2, 30)
        6.0.2  -> (6, 0, 2)
        v4.2.30 -> (4, 2, 30)
        ^4.2.30 -> (4, 2, 30)
    """

    if not version:
        return None

    version = str(version).strip()

    # Remove common prefixes
    while version.startswith(("v", "^", "~", "=", ">", "<")):
        version = version[1:].strip()

    parts = version.split(".")

    numbers = []

    for part in parts[:3]:

        number = ""

        for char in part:

            if char.isdigit():
                number += char

            else:
                break

        if number:
            numbers.append(int(number))

        else:
            numbers.append(0)

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)


def extract_fixed_versions(vulnerabilities):
    """
    Extract all advisory-listed fixed versions.

    Example:
        "6.0.2, 5.2.11, 4.2.28"

    becomes:
        ["6.0.2", "5.2.11", "4.2.28"]
    """

    fixed_versions = []

    if not isinstance(vulnerabilities, list):
        return fixed_versions

    for vulnerability in vulnerabilities:

        if not isinstance(vulnerability, dict):
            continue

        fixed = vulnerability.get(
            "fixed_version",
            ""
        )

        if not fixed:
            continue

        fixed = str(fixed)

        versions = fixed.split(",")

        for version in versions:

            version = version.strip()

            if not version:
                continue

            if version.lower() == "not available":
                continue

            if version not in fixed_versions:
                fixed_versions.append(version)

    return fixed_versions


def get_vulnerability_fixed_versions(vulnerability):
    """
    Get parsed fixed versions for one vulnerability.
    """

    if not isinstance(vulnerability, dict):
        return []

    fixed = vulnerability.get(
        "fixed_version",
        ""
    )

    if not fixed:
        return []

    versions = []

    for version in str(fixed).split(","):

        version = version.strip()

        parsed = parse_version(version)

        if parsed:

            versions.append(
                (parsed, version)
            )

    return versions


def find_common_safe_version(
    installed_version,
    vulnerabilities
):
    """
    Try to identify a version that satisfies all
    detected vulnerability fixed-version requirements.

    The method checks candidate versions from the
    advisory data and verifies them against every
    vulnerability.

    Returns:
        candidate version if one common candidate exists
        otherwise None
    """

    current = parse_version(
        installed_version
    )

    if not current:
        return None

    if not vulnerabilities:
        return None

    vulnerability_requirements = []

    for vulnerability in vulnerabilities:

        fixed_versions = (
            get_vulnerability_fixed_versions(
                vulnerability
            )
        )

        # Vulnerability has no fixed version.
        # Therefore we cannot prove that a candidate
        # version resolves this vulnerability.
        if not fixed_versions:
            return None

        vulnerability_requirements.append(
            fixed_versions
        )

    # Build candidate versions from advisory data.
    candidates = []

    for requirement in vulnerability_requirements:

        for parsed, original in requirement:

            if parsed > current:

                if original not in candidates:
                    candidates.append(original)

    # Sort candidates from lowest to highest.
    candidates.sort(
        key=lambda version: parse_version(version)
    )

    # -------------------------------------------------
    # Check every candidate against EVERY vulnerability
    # -------------------------------------------------

    for candidate in candidates:

        candidate_parsed = parse_version(
            candidate
        )

        if not candidate_parsed:
            continue

        all_fixed = True

        for requirement in vulnerability_requirements:

            # Candidate must be greater than or equal
            # to at least one fixed version for this
            # vulnerability.
            vulnerability_fixed = any(
                candidate_parsed >= fixed_parsed
                for fixed_parsed, _ in requirement
            )

            if not vulnerability_fixed:

                all_fixed = False
                break

        if all_fixed:

            return candidate

    return None


def find_best_branch_candidate(
    installed_version,
    vulnerabilities
):
    """
    Find the best branch-aware candidate when a single
    common fixed version cannot be proven.

    Preference:
        1. Same major + minor branch
        2. Same major branch
        3. Higher supported branch

    This candidate is NOT considered a guaranteed
    all-vulnerability fix.
    """

    current = parse_version(
        installed_version
    )

    if not current:
        return None

    fixed_versions = extract_fixed_versions(
        vulnerabilities
    )

    parsed_versions = []

    for version in fixed_versions:

        parsed = parse_version(version)

        if parsed and parsed > current:

            parsed_versions.append(
                (parsed, version)
            )

    if not parsed_versions:
        return None

    # Same major + minor
    same_branch = [
        item
        for item in parsed_versions
        if item[0][0] == current[0]
        and item[0][1] == current[1]
    ]

    if same_branch:

        same_branch.sort(
            key=lambda item: item[0]
        )

        return same_branch[-1][1]

    # Same major
    same_major = [
        item
        for item in parsed_versions
        if item[0][0] == current[0]
    ]

    if same_major:

        same_major.sort(
            key=lambda item: item[0]
        )

        return same_major[-1][1]

    # Highest available advisory version
    parsed_versions.sort(
        key=lambda item: item[0]
    )

    return parsed_versions[-1][1]


def select_recommended_version(
    installed_version,
    vulnerabilities
):
    """
    Select the safest recommendation strategy.

    First:
        Try to find one version that satisfies ALL
        detected vulnerability fixed-version requirements.

    If that cannot be proven:
        Return a branch-aware candidate, but mark it
        as requiring further validation.

    Returns:
        {
            "version": "...",
            "all_vulnerabilities_addressed": True/False
        }
    """

    # -------------------------------------------------
    # Try to find one common safe version
    # -------------------------------------------------

    common_version = find_common_safe_version(
        installed_version,
        vulnerabilities
    )

    if common_version:

        return {
            "version": common_version,
            "all_vulnerabilities_addressed": True
        }

    # -------------------------------------------------
    # No common version found
    # -------------------------------------------------

    branch_candidate = find_best_branch_candidate(
        installed_version,
        vulnerabilities
    )

    if branch_candidate:

        return {
            "version": branch_candidate,
            "all_vulnerabilities_addressed": False
        }

    return {
        "version": None,
        "all_vulnerabilities_addressed": False
    }


def determine_priority(risk_score):
    """
    Determine remediation priority from risk score.
    """

    if risk_score >= 75:

        return "Critical"

    elif risk_score >= 50:

        return "High"

    elif risk_score >= 25:

        return "Medium"

    else:

        return "Low"


def generate_recommendation(
    dependency_name,
    risk_score,
    impact_level,
    vulnerability_count,
    vulnerabilities=None,
    installed_version=None
):
    """
    Generate an actionable security recommendation.

    The recommendation engine:
        1. Determines remediation priority.
        2. Extracts advisory fixed versions.
        3. Checks whether one candidate can address
           all detected vulnerabilities.
        4. Avoids falsely claiming that one version
           fixes every vulnerability.
    """

    if vulnerabilities is None:
        vulnerabilities = []

    try:

        risk_score = float(risk_score)

    except (TypeError, ValueError):

        risk_score = 0

    try:

        vulnerability_count = int(
            vulnerability_count
        )

    except (TypeError, ValueError):

        vulnerability_count = 0

    # -------------------------------------------------
    # No vulnerabilities
    # -------------------------------------------------

    if vulnerability_count == 0:

        return {

            "priority": "Low",

            "message": (
                f"{dependency_name} has no known "
                "vulnerabilities in the current scan. "
                "Continue monitoring security advisories "
                "and maintain the dependency."
            ),

            "recommended_version": None,

            "fixed_versions": [],

            "all_vulnerabilities_addressed": True
        }

    # -------------------------------------------------
    # Priority
    # -------------------------------------------------

    priority = determine_priority(
        risk_score
    )

    # -------------------------------------------------
    # Extract fixed versions
    # -------------------------------------------------

    fixed_versions = extract_fixed_versions(
        vulnerabilities
    )

    # -------------------------------------------------
    # Select recommendation
    # -------------------------------------------------

    recommendation_result = (
        select_recommended_version(
            installed_version,
            vulnerabilities
        )
    )

    recommended_version = (
        recommendation_result["version"]
    )

    all_vulnerabilities_addressed = (
        recommendation_result[
            "all_vulnerabilities_addressed"
        ]
    )

    # -------------------------------------------------
    # Build message
    # -------------------------------------------------

    if recommended_version:

        if installed_version:

            version_text = (
                f"Upgrade from version "
                f"{installed_version} to "
                f"{recommended_version}."
            )

        else:

            version_text = (
                f"Consider upgrading to "
                f"version {recommended_version}."
            )

        # ---------------------------------------------
        # Proven common fixed version
        # ---------------------------------------------

        if all_vulnerabilities_addressed:

            message = (

                f"{dependency_name} requires "
                f"{priority.lower()}-priority remediation. "

                f"{vulnerability_count} known vulnerabilities "
                f"were detected with a risk score of "
                f"{risk_score}%. "

                f"{version_text} "

                "Based on the available advisory fixed-version "
                "data, this candidate satisfies the fixed-version "
                "requirements for all detected vulnerabilities. "

                "Application compatibility testing is still "
                "required before deployment."
            )

        # ---------------------------------------------
        # Candidate found but cannot prove all fixes
        # ---------------------------------------------

        else:

            message = (

                f"{dependency_name} requires "
                f"{priority.lower()}-priority remediation. "

                f"{vulnerability_count} known vulnerabilities "
                f"were detected with a risk score of "
                f"{risk_score}%. "

                f"{version_text} "

                "However, the available advisory data does "
                "not prove that this single version resolves "
                "all detected vulnerabilities. "

                "Review each advisory and validate the target "
                "version before deployment."
            )

    else:

        message = (

            f"{dependency_name} requires "
            f"{priority.lower()}-priority remediation. "

            f"{vulnerability_count} known vulnerabilities "
            f"were detected with a risk score of "
            f"{risk_score}%. "

            "No single suitable target version could be "
            "identified from the available advisory "
            "fixed-version data. "

            "Review the affected security advisories and "
            "upgrade to a supported security-fixed release "
            "after compatibility testing."
        )

    # -------------------------------------------------
    # Return result
    # -------------------------------------------------

    return {

        "priority": priority,

        "message": message,

        "recommended_version": (
            recommended_version
        ),

        "fixed_versions": fixed_versions,

        "all_vulnerabilities_addressed": (
            all_vulnerabilities_addressed
        )
    }