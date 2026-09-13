def parse_version(version):
    """
    Convert a version string into a comparable tuple.

    Examples:
        4.2.30      -> (4, 2, 30)
        6.0.2       -> (6, 0, 2)
        v4.2.30     -> (4, 2, 30)
        ^4.2.30     -> (4, 2, 30)
        4.20.0-beta -> (4, 20, 0)
    """

    if not version:
        return None

    version = str(version).strip()

    while version.startswith(
        ("v", "^", "~", "=", ">", "<")
    ):
        version = version[1:].strip()

    if version in ("", "*"):
        return None

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
            numbers.append(
                int(number)
            )
        else:
            numbers.append(0)

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)


# ---------------------------------------------------------
# FIXED VERSION EXTRACTION
# ---------------------------------------------------------

def extract_fixed_versions(vulnerabilities):
    """
    Extract all advisory-listed fixed versions.

    Example:
        "6.0.2, 5.2.11, 4.2.28"

    becomes:
        ["6.0.2", "5.2.11", "4.2.28"]
    """

    fixed_versions = []

    if not isinstance(
        vulnerabilities,
        list
    ):
        return fixed_versions

    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):
            continue

        # Prefer the new structured field.
        structured_fixed = vulnerability.get(
            "fixed_versions",
            []
        )

        if isinstance(
            structured_fixed,
            list
        ):

            for version in structured_fixed:

                if not version:
                    continue

                version = str(
                    version
                ).strip()

                if (
                    version
                    and version.lower()
                    != "not available"
                    and version not in fixed_versions
                ):
                    fixed_versions.append(
                        version
                    )

        # Backward compatibility with
        # existing processed results.
        fixed = vulnerability.get(
            "fixed_version",
            ""
        )

        if not fixed:
            continue

        for version in str(
            fixed
        ).split(","):

            version = version.strip()

            if not version:
                continue

            if version.lower() == "not available":
                continue

            if version not in fixed_versions:

                fixed_versions.append(
                    version
                )

    return fixed_versions


def get_vulnerability_fixed_versions(
    vulnerability
):
    """
    Get parsed fixed versions for one vulnerability.
    """

    if not isinstance(
        vulnerability,
        dict
    ):
        return []

    versions = []

    structured_fixed = vulnerability.get(
        "fixed_versions",
        []
    )

    if isinstance(
        structured_fixed,
        list
    ):

        raw_versions = structured_fixed

    else:

        fixed = vulnerability.get(
            "fixed_version",
            ""
        )

        if not fixed:
            return []

        raw_versions = str(
            fixed
        ).split(",")

    for version in raw_versions:

        version = str(
            version
        ).strip()

        if not version:
            continue

        if version.lower() == "not available":
            continue

        parsed = parse_version(
            version
        )

        if parsed:

            versions.append(
                (
                    parsed,
                    version
                )
            )

    return versions


# ---------------------------------------------------------
# ADVISORY RANGE HELPERS
# ---------------------------------------------------------

def get_affected_ranges(
    vulnerability
):
    """
    Return advisory affected range information.

    New scanner output stores this in:
        affected_ranges

    This function also safely handles older vulnerability
    records that do not contain the field.
    """

    if not isinstance(
        vulnerability,
        dict
    ):
        return []

    ranges = vulnerability.get(
        "affected_ranges",
        []
    )

    if not isinstance(
        ranges,
        list
    ):
        return []

    return ranges


def get_range_events(
    affected_range
):
    """
    Return cleaned advisory events.
    """

    if not isinstance(
        affected_range,
        dict
    ):
        return []

    events = affected_range.get(
        "events",
        []
    )

    if not isinstance(
        events,
        list
    ):
        return []

    return [
        event
        for event in events
        if isinstance(
            event,
            dict
        )
    ]


def version_meets_event(
    candidate_version,
    event_version
):
    """
    Compare a candidate version with an OSV event version.
    """

    candidate = parse_version(
        candidate_version
    )

    event = parse_version(
        event_version
    )

    if not candidate or not event:
        return False

    return candidate >= event


def candidate_is_after_fixed_event(
    candidate_version,
    affected_range
):
    """
    Determine whether a candidate is at or after a
    fixed event within one advisory range.

    Example:

        introduced: 0
        fixed: 4.20.0

    Candidate 4.20.0 -> True
    Candidate 4.19.2 -> False
    """

    events = get_range_events(
        affected_range
    )

    if not events:
        return False

    for event in events:

        fixed = event.get(
            "fixed"
        )

        if fixed:

            if version_meets_event(
                candidate_version,
                fixed
            ):
                return True

    return False


def candidate_is_affected_by_range(
    candidate_version,
    affected_range
):
    """
    Determine whether a candidate version is still
    inside an advisory's affected range.

    This is intentionally conservative.

    If the advisory gives a fixed version and the
    candidate is at or above that fixed version,
    the candidate is treated as outside that range.

    If no fixed event exists, the function does not
    claim that the vulnerability is resolved.
    """

    events = get_range_events(
        affected_range
    )

    if not events:
        return None

    has_introduction = False
    has_fixed = False

    for event in events:

        introduced = event.get(
            "introduced"
        )

        fixed = event.get(
            "fixed"
        )

        if introduced is not None:

            has_introduction = True

        if fixed is not None:

            has_fixed = True

            if version_meets_event(
                candidate_version,
                fixed
            ):
                return False

    # A range with an introduction but
    # without a fixed event cannot prove
    # that the vulnerability is resolved.
    if has_introduction and not has_fixed:

        return True

    # Unknown range information.
    return None


def advisory_proves_candidate_safe(
    candidate_version,
    vulnerability
):
    """
    Determine whether available OSV advisory data
    provides sufficient evidence that the candidate
    resolves this vulnerability.

    Returns:
        True  -> advisory data proves candidate is fixed
        False -> advisory data indicates candidate
                 is still affected
        None  -> insufficient advisory evidence
    """

    affected_ranges = get_affected_ranges(
        vulnerability
    )

    # No range data means we cannot make a strong
    # advisory-aware claim.
    if not affected_ranges:

        return None

    range_results = []

    for affected_range in affected_ranges:

        result = candidate_is_affected_by_range(
            candidate_version,
            affected_range
        )

        if result is not None:

            range_results.append(
                result
            )

    if not range_results:

        return None

    # Candidate is safe only when every known
    # affected range indicates it is outside
    # the affected range.
    if all(
        result is False
        for result in range_results
    ):
        return True

    # If any range still marks the candidate
    # as affected, it is not safe.
    if any(
        result is True
        for result in range_results
    ):
        return False

    return None


# ---------------------------------------------------------
# COMMON SAFE VERSION
# ---------------------------------------------------------

def find_common_safe_version(
    installed_version,
    vulnerabilities
):
    """
    Try to identify a version that satisfies all
    detected vulnerability requirements.

    Advisory-aware strategy:

        1. Build candidate versions from OSV fixed data.
        2. Ignore candidates that are not newer than
           the installed version.
        3. Validate every candidate against every
           vulnerability.
        4. Prefer candidates proven safe by affected-range
           information.
        5. Fall back to fixed-version evidence only when
           the advisory range data is unavailable.

    Returns:
        candidate version if a common safe version
        can be proven, otherwise None.
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

                    candidates.append(
                        original
                    )

    candidates.sort(
        key=lambda version: (
            parse_version(version)
            or (0, 0, 0)
        )
    )

    # -------------------------------------------------
    # Validate candidates
    # -------------------------------------------------

    for candidate in candidates:

        candidate_parsed = parse_version(
            candidate
        )

        if not candidate_parsed:
            continue

        all_fixed = True

        for vulnerability in vulnerabilities:

            advisory_result = (
                advisory_proves_candidate_safe(
                    candidate,
                    vulnerability
                )
            )

            # If advisory explicitly says candidate
            # is still affected -> reject.
            if advisory_result is False:

                all_fixed = False
                break

            # If advisory range exists but does not
            # provide enough evidence -> do not claim
            # a guaranteed fix.
            if advisory_result is None:

                fixed_versions = (
                    get_vulnerability_fixed_versions(
                        vulnerability
                    )
                )

                if not fixed_versions:

                    all_fixed = False
                    break

                fixed_by_version = any(
                    candidate_parsed >= fixed_parsed
                    for fixed_parsed, _ in fixed_versions
                )

                if not fixed_by_version:

                    all_fixed = False
                    break

        if all_fixed:

            return candidate

    return None


# ---------------------------------------------------------
# BRANCH CANDIDATE
# ---------------------------------------------------------

def find_best_branch_candidate(
    installed_version,
    vulnerabilities
):
    """
    Find a reasonable upgrade candidate when a fully
    verified common safe version cannot be proven.

    Preference:
        1. Same major + minor branch
        2. Same major branch
        3. Higher advisory branch

    IMPORTANT:
        This function never claims that the returned
        candidate fixes all vulnerabilities.
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

        parsed = parse_version(
            version
        )

        if parsed and parsed > current:

            parsed_versions.append(
                (
                    parsed,
                    version
                )
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


# ---------------------------------------------------------
# SELECT RECOMMENDED VERSION
# ---------------------------------------------------------

def select_recommended_version(
    installed_version,
    vulnerabilities
):
    """
    Select the safest recommendation strategy.

    First:
        Try to find a candidate that is supported by
        advisory affected-range/fixed-event evidence.

    If that cannot be proven:
        Return a branch-aware candidate and mark it
        as unverified.

    Returns:

        {
            "version": "...",
            "all_vulnerabilities_addressed": True/False
        }
    """

    common_version = (
        find_common_safe_version(
            installed_version,
            vulnerabilities
        )
    )

    if common_version:

        return {
            "version": common_version,
            "all_vulnerabilities_addressed": True
        }

    branch_candidate = (
        find_best_branch_candidate(
            installed_version,
            vulnerabilities
        )
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


# ---------------------------------------------------------
# PRIORITY
# ---------------------------------------------------------

def determine_priority(
    risk_score
):
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


# ---------------------------------------------------------
# MAIN RECOMMENDATION
# ---------------------------------------------------------

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
        3. Uses OSV affected-range information
           when available.
        4. Attempts to prove a common safe version.
        5. Avoids falsely claiming that a version fixes
           every vulnerability.
    """

    if vulnerabilities is None:

        vulnerabilities = []

    try:

        risk_score = float(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        risk_score = 0

    try:

        vulnerability_count = int(
            vulnerability_count
        )

    except (
        TypeError,
        ValueError
    ):

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
    # Fixed versions
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
        recommendation_result[
            "version"
        ]
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
        # Verified recommendation
        # ---------------------------------------------

        if all_vulnerabilities_addressed:

            message = (

                f"{dependency_name} requires "
                f"{priority.lower()}-priority remediation. "

                f"{vulnerability_count} known vulnerabilities "
                f"were detected with a risk score of "
                f"{risk_score}%. "

                f"{version_text} "

                "Available OSV advisory range and fixed-version "
                "data supports this candidate as a version "
                "outside the affected ranges for all detected "
                "vulnerabilities. "

                "Application compatibility testing is still "
                "required before deployment."
            )

        # ---------------------------------------------
        # Candidate but not proven
        # ---------------------------------------------

        else:

            message = (

                f"{dependency_name} requires "
                f"{priority.lower()}-priority remediation. "

                f"{vulnerability_count} known vulnerabilities "
                f"were detected with a risk score of "
                f"{risk_score}%. "

                f"{version_text} "

                "However, the available OSV advisory data "
                "does not provide sufficient evidence to prove "
                "that this single version resolves all detected "
                "vulnerabilities. "

                "Review each advisory, verify the affected "
                "version range, and perform compatibility "
                "testing before deployment."
            )

    else:

        message = (

            f"{dependency_name} requires "
            f"{priority.lower()}-priority remediation. "

            f"{vulnerability_count} known vulnerabilities "
            f"were detected with a risk score of "
            f"{risk_score}%. "

            "No single suitable target version could be "
            "proven safe from the available advisory data. "

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

        "recommended_version":
            recommended_version,

        "fixed_versions":
            fixed_versions,

        "all_vulnerabilities_addressed":
            all_vulnerabilities_addressed
    }