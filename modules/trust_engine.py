import requests
from datetime import datetime, timezone


# =========================================================
# PACKAGE AGE
# =========================================================

def calculate_package_age(created_date):
    """
    Calculate package age in days.
    """

    if not created_date:
        return 0

    try:

        created = datetime.fromisoformat(
            created_date.replace("Z", "+00:00")
        )

        age_days = (
            datetime.now(timezone.utc) - created
        ).days

        return max(age_days, 0)

    except Exception:

        return 0


# =========================================================
# MAINTENANCE SCORE
# =========================================================

def get_maintenance_score(data):
    """
    Estimate maintenance quality.
    """

    score = 0

    time_data = data.get("time", {})

    created_date = time_data.get("created")
    modified_date = time_data.get("modified")

    age_days = calculate_package_age(
        created_date
    )

    # Package age
    if age_days > 365:
        score += 10

    elif age_days > 180:
        score += 7

    elif age_days > 30:
        score += 4

    # Recent modification
    if modified_date:

        try:

            modified = datetime.fromisoformat(
                modified_date.replace("Z", "+00:00")
            )

            days_since_modified = (
                datetime.now(timezone.utc) - modified
            ).days

            if days_since_modified <= 90:
                score += 10

            elif days_since_modified <= 180:
                score += 7

            elif days_since_modified <= 365:
                score += 4

        except Exception:
            pass

    return min(score, 20)


# =========================================================
# REPOSITORY SCORE
# =========================================================

def get_repository_score(data):
    """
    Check repository availability.
    """

    repository = data.get("repository")

    if repository:
        return 15

    return 0


# =========================================================
# VERSION HISTORY SCORE
# =========================================================

def get_version_history_score(data):
    """
    Estimate package maturity using
    published version count.
    """

    versions = data.get(
        "versions",
        {}
    )

    version_count = len(versions)

    if version_count > 50:
        return 15

    elif version_count > 20:
        return 12

    elif version_count > 10:
        return 8

    elif version_count > 5:
        return 5

    return 0


# =========================================================
# LATEST VERSION SCORE
# =========================================================

def get_latest_version_score(data):
    """
    Check whether latest release information
    is available.
    """

    dist_tags = data.get(
        "dist-tags",
        {}
    )

    if dist_tags.get("latest"):
        return 10

    return 0


# =========================================================
# METADATA SCORE
# =========================================================

def get_metadata_score(data):
    """
    Check availability of package metadata.
    """

    score = 0

    if data.get("name"):
        score += 2

    if data.get("description"):
        score += 2

    if data.get("maintainers"):
        score += 2

    if data.get("license"):
        score += 2

    return min(score, 8)


# =========================================================
# NPM TRUST DATA
# =========================================================

def get_npm_data(package_name):

    url = (
        f"https://registry.npmjs.org/"
        f"{package_name}"
    )

    response = requests.get(
        url,
        timeout=10
    )

    response.raise_for_status()

    return response.json()


# =========================================================
# PYPI TRUST DATA
# =========================================================

def get_pypi_data(package_name):

    url = (
        f"https://pypi.org/pypi/"
        f"{package_name}/json"
    )

    response = requests.get(
        url,
        timeout=10
    )

    response.raise_for_status()

    raw_data = response.json()

    info = raw_data.get(
        "info",
        {}
    )

    releases = raw_data.get(
        "releases",
        {}
    )

    # Convert PyPI data into a common format
    data = {

        "name":
            info.get(
                "name",
                package_name
            ),

        "description":
            info.get(
                "summary",
                ""
            ),

        "license":
            info.get(
                "license"
            ),

        "repository":
            info.get(
                "project_urls"
            ),

        "maintainers":
            info.get(
                "maintainer"
            ),

        "versions":
            releases,

        "latest":
            info.get(
                "version"
            ),

        "release_time":
            None

    }

    # Find first release date
    release_dates = []

    for version_files in releases.values():

        for file_data in version_files:

            upload_time = file_data.get(
                "upload_time_iso_8601"
            )

            if upload_time:
                release_dates.append(
                    upload_time
                )

    if release_dates:

        try:

            created_date = min(
                release_dates
            )

            data["created"] = (
                created_date
            )

        except Exception:

            data["created"] = None

    else:

        data["created"] = None

    return data


# =========================================================
# MAVEN TRUST DATA
# =========================================================

def get_maven_data(package_name):

    if ":" not in package_name:

        raise ValueError(
            "Maven dependency must use "
            "groupId:artifactId format."
        )

    group_id, artifact_id = (
        package_name.split(
            ":",
            1
        )
    )

    url = (
        "https://search.maven.org/solrsearch/select"
    )

    params = {

        "q":
            f'g:"{group_id}" AND a:"{artifact_id}"',

        "rows":
            200,

        "wt":
            "json"

    }

    response = requests.get(
        url,
        params=params,
        timeout=10
    )

    response.raise_for_status()

    raw_data = response.json()

    response_data = raw_data.get(
        "response",
        {}
    )

    docs = response_data.get(
        "docs",
        []
    )

    latest_version = None

    version_count = 0

    repository_available = False

    if docs:

        first_doc = docs[0]

        latest_version = (
            first_doc.get(
                "latestVersion"
            )
        )

        version_count = (
            first_doc.get(
                "versionCount",
                0
            )
        )

        repository_available = True

    data = {

        "name":
            package_name,

        "description":
            "Maven Central dependency",

        "license":
            None,

        "repository":
            repository_available,

        "maintainers":
            None,

        "versions":
            version_count,

        "latest":
            latest_version,

        "created":
            None

    }

    return data


# =========================================================
# COMMON TRUST CALCULATION
# =========================================================

def calculate_trust(
    package_name,
    ecosystem="npm"
):
    """
    Calculate heuristic trust score.

    Supported ecosystems:
        npm
        python / PyPI
        maven
    """

    ecosystem = ecosystem.lower()

    try:

        # -----------------------------------------
        # GET PACKAGE DATA
        # -----------------------------------------

        if ecosystem == "npm":

            data = get_npm_data(
                package_name
            )

            return calculate_npm_trust(
                data
            )

        elif ecosystem in [
            "python",
            "pypi"
        ]:

            data = get_pypi_data(
                package_name
            )

            return calculate_python_trust(
                data
            )

        elif ecosystem in [
            "maven",
            "java"
        ]:

            data = get_maven_data(
                package_name
            )

            return calculate_maven_trust(
                data
            )

        else:

            return 50

    except Exception:

        return 50


# =========================================================
# NPM TRUST SCORE
# =========================================================

def calculate_npm_trust(data):

    score = 17

    # Repository
    score += get_repository_score(
        data
    )

    # Package age
    time_data = data.get(
        "time",
        {}
    )

    created_date = time_data.get(
        "created"
    )

    age_days = calculate_package_age(
        created_date
    )

    if age_days > 365:
        score += 15

    elif age_days > 180:
        score += 10

    elif age_days > 30:
        score += 5

    # Maintenance
    score += get_maintenance_score(
        data
    )

    # Version history
    score += get_version_history_score(
        data
    )

    # Latest release
    score += get_latest_version_score(
        data
    )

    # Metadata
    score += get_metadata_score(
        data
    )

    return min(
        score,
        100
    )


# =========================================================
# PYTHON TRUST SCORE
# =========================================================

def calculate_python_trust(data):

    score = 17

    # Repository / project URLs
    if data.get("repository"):

        score += 15

    # Package age
    created_date = data.get(
        "created"
    )

    age_days = calculate_package_age(
        created_date
    )

    if age_days > 365:
        score += 15

    elif age_days > 180:
        score += 10

    elif age_days > 30:
        score += 5

    # Version history
    versions = data.get(
        "versions",
        {}
    )

    if isinstance(
        versions,
        dict
    ):

        version_count = len(
            versions
        )

    else:

        version_count = 0

    if version_count > 50:
        score += 15

    elif version_count > 20:
        score += 12

    elif version_count > 10:
        score += 8

    elif version_count > 5:
        score += 5

    # Latest version
    if data.get("latest"):

        score += 10

    # Metadata
    if data.get("name"):
        score += 2

    if data.get("description"):
        score += 2

    if data.get("maintainers"):
        score += 2

    if data.get("license"):
        score += 2

    return min(
        score,
        100
    )


# =========================================================
# MAVEN TRUST SCORE
# =========================================================

def calculate_maven_trust(data):

    score = 17

    # Repository / Maven Central availability
    if data.get("repository"):

        score += 15

    # Version history
    version_count = data.get(
        "versions",
        0
    )

    if isinstance(
        version_count,
        int
    ):

        if version_count > 50:
            score += 15

        elif version_count > 20:
            score += 12

        elif version_count > 10:
            score += 8

        elif version_count > 5:
            score += 5

    # Latest release
    if data.get("latest"):

        score += 10

    # Metadata
    if data.get("name"):
        score += 2

    if data.get("description"):
        score += 2

    if data.get("maintainers"):
        score += 2

    if data.get("license"):
        score += 2

    return min(
        score,
        100
    )


# =========================================================
# TRUST LEVEL
# =========================================================

def get_trust_level(trust_score):

    if trust_score >= 80:

        return "High"

    elif trust_score >= 50:

        return "Moderate"

    else:

        return "Low"


# =========================================================
# TRUST DETAILS
# =========================================================

def get_trust_details(
    package_name,
    ecosystem="npm"
):
    """
    Return detailed trust assessment.
    """

    ecosystem = ecosystem.lower()

    try:

        # =========================================
        # NPM
        # =========================================

        if ecosystem == "npm":

            data = get_npm_data(
                package_name
            )

            trust_score = (
                calculate_npm_trust(
                    data
                )
            )

            time_data = data.get(
                "time",
                {}
            )

            created_date = time_data.get(
                "created"
            )

            age_days = calculate_package_age(
                created_date
            )

            versions = data.get(
                "versions",
                {}
            )

            repository = bool(
                data.get(
                    "repository"
                )
            )

            latest_version = (
                data.get(
                    "dist-tags",
                    {}
                ).get(
                    "latest"
                )
            )

            return {

                "package":
                    package_name,

                "trust_score":
                    trust_score,

                "trust_level":
                    get_trust_level(
                        trust_score
                    ),

                "package_age_days":
                    age_days,

                "version_count":
                    len(
                        versions
                    ),

                "repository_available":
                    repository,

                "latest_version":
                    latest_version

            }

        # =========================================
        # PYTHON / PYPI
        # =========================================

        elif ecosystem in [
            "python",
            "pypi"
        ]:

            data = get_pypi_data(
                package_name
            )

            trust_score = (
                calculate_python_trust(
                    data
                )
            )

            created_date = data.get(
                "created"
            )

            age_days = calculate_package_age(
                created_date
            )

            versions = data.get(
                "versions",
                {}
            )

            if isinstance(
                versions,
                dict
            ):

                version_count = len(
                    versions
                )

            else:

                version_count = 0

            repository = bool(
                data.get(
                    "repository"
                )
            )

            latest_version = data.get(
                "latest"
            )

            return {

                "package":
                    package_name,

                "trust_score":
                    trust_score,

                "trust_level":
                    get_trust_level(
                        trust_score
                    ),

                "package_age_days":
                    age_days,

                "version_count":
                    version_count,

                "repository_available":
                    repository,

                "latest_version":
                    latest_version

            }

        # =========================================
        # MAVEN
        # =========================================

        elif ecosystem in [
            "maven",
            "java"
        ]:

            data = get_maven_data(
                package_name
            )

            trust_score = (
                calculate_maven_trust(
                    data
                )
            )

            version_count = data.get(
                "versions",
                0
            )

            repository = bool(
                data.get(
                    "repository"
                )
            )

            latest_version = data.get(
                "latest"
            )

            return {

                "package":
                    package_name,

                "trust_score":
                    trust_score,

                "trust_level":
                    get_trust_level(
                        trust_score
                    ),

                "package_age_days":
                    0,

                "version_count":
                    version_count,

                "repository_available":
                    repository,

                "latest_version":
                    latest_version

            }

        return {

            "package":
                package_name,

            "trust_score":
                50,

            "trust_level":
                "Moderate",

            "package_age_days":
                0,

            "version_count":
                0,

            "repository_available":
                False,

            "latest_version":
                None

        }

    except Exception:

        return {

            "package":
                package_name,

            "trust_score":
                50,

            "trust_level":
                "Moderate",

            "package_age_days":
                0,

            "version_count":
                0,

            "repository_available":
                False,

            "latest_version":
                None

        }