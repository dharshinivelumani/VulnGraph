import json
import os
import xml.etree.ElementTree as ET


# =========================================================
# CONTENT VALIDATION
# =========================================================

def validate_dependency_file(file_path):
    """
    Validates the actual content of a dependency file.

    Supported:
    - package-lock.json
    - package.json
    - requirements.txt
    - pom.xml
    """

    filename = os.path.basename(file_path).lower()

    # -----------------------------------------------------
    # PACKAGE-LOCK.JSON
    # -----------------------------------------------------

    if filename == "package-lock.json":

        try:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

        except json.JSONDecodeError as error:

            raise ValueError(
                "Invalid package-lock.json content. "
                "The file is not valid JSON."
            ) from error

        except UnicodeDecodeError as error:

            raise ValueError(
                "Invalid package-lock.json encoding."
            ) from error

        if not isinstance(data, dict):

            raise ValueError(
                "Invalid package-lock.json structure."
            )

        lockfile_version = data.get(
            "lockfileVersion"
        )

        dependencies = data.get(
            "dependencies"
        )

        packages = data.get(
            "packages"
        )

        if (
            lockfile_version is None
            and dependencies is None
            and packages is None
        ):

            raise ValueError(
                "Invalid package-lock.json structure. "
                "Expected lockfileVersion, dependencies, "
                "or packages."
            )

        return True

    # -----------------------------------------------------
    # PACKAGE.JSON
    # -----------------------------------------------------

    elif filename == "package.json":

        try:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

        except json.JSONDecodeError as error:

            raise ValueError(
                "Invalid package.json content. "
                "The file is not valid JSON."
            ) from error

        except UnicodeDecodeError as error:

            raise ValueError(
                "Invalid package.json encoding."
            ) from error

        if not isinstance(data, dict):

            raise ValueError(
                "Invalid package.json structure."
            )

        return True

    # -----------------------------------------------------
    # REQUIREMENTS.TXT
    # -----------------------------------------------------

    elif filename == "requirements.txt":

        try:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                file.read()

        except UnicodeDecodeError as error:

            raise ValueError(
                "Invalid requirements.txt encoding."
            ) from error

        return True

    # -----------------------------------------------------
    # POM.XML
    # -----------------------------------------------------

    elif filename == "pom.xml":

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

        except ET.ParseError as error:

            raise ValueError(
                "Invalid pom.xml content. "
                "The file is not valid XML."
            ) from error

        if root is None:

            raise ValueError(
                "Invalid pom.xml structure."
            )

        return True

    # -----------------------------------------------------
    # UNSUPPORTED FILE
    # -----------------------------------------------------

    raise ValueError(
        "Unsupported dependency file."
    )


# =========================================================
# MAIN DEPENDENCY EXTRACTION
# =========================================================

def extract_dependency_graph(file_path, ecosystem=None):
    """
    Automatically detects and extracts dependencies from:

    - package-lock.json
    - package.json
    - requirements.txt
    - pom.xml

    ecosystem is accepted for compatibility with app.py.
    The parser automatically detects the ecosystem from
    the uploaded filename.

    Returns:
        dependencies
        relationships
        dependency_versions
    """

    filename = os.path.basename(
        file_path
    ).lower()

    # -----------------------------------------------------
    # Validate actual file content first
    # -----------------------------------------------------

    validate_dependency_file(
        file_path
    )

    # -----------------------------------------------------
    # Detect file type
    # -----------------------------------------------------

    if filename == "package-lock.json":

        return extract_package_lock(
            file_path
        )

    elif filename == "package.json":

        return extract_package_json(
            file_path
        )

    elif filename == "requirements.txt":

        return extract_requirements_txt(
            file_path
        )

    elif filename == "pom.xml":

        return extract_pom_xml(
            file_path
        )

    else:

        raise ValueError(
            "Unsupported dependency file. "
            "Please upload package-lock.json, package.json, "
            "requirements.txt, or pom.xml."
        )


# =========================================================
# PACKAGE-LOCK.JSON
# =========================================================

def extract_package_lock(file_path):

    dependencies = []
    relationships = []
    dependency_versions = {}

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    lockfile_version = data.get(
        "lockfileVersion",
        1
    )

    # -----------------------------------------------------
    # PACKAGE-LOCK.JSON V2 / V3
    # -----------------------------------------------------

    if lockfile_version >= 2:

        packages = data.get(
            "packages",
            {}
        )

        root_package = packages.get(
            "",
            {}
        )

        root_dependencies = {}

        root_dependencies.update(
            root_package.get(
                "dependencies",
                {}
            )
        )

        root_dependencies.update(
            root_package.get(
                "devDependencies",
                {}
            )
        )

        root_dependencies.update(
            root_package.get(
                "optionalDependencies",
                {}
            )
        )

        # -------------------------------------------------
        # DIRECT DEPENDENCIES
        # -------------------------------------------------

        for dependency_name in root_dependencies:

            dependencies.append(
                dependency_name
            )

            relationships.append({
                "parent": "project",
                "child": dependency_name,
                "type": "direct"
            })

        # -------------------------------------------------
        # ALL INSTALLED PACKAGES
        # -------------------------------------------------

        for package_path, package_data in packages.items():

            if package_path == "":
                continue

            if "node_modules/" not in package_path:
                continue

            package_name = package_path.split(
                "node_modules/"
            )[-1]

            if not package_name:
                continue

            dependencies.append(
                package_name
            )

            installed_version = package_data.get(
                "version"
            )

            if installed_version:

                dependency_versions[
                    package_name
                ] = installed_version

            # -------------------------------------------------
            # CHILD DEPENDENCIES
            # -------------------------------------------------

            child_dependencies = {}

            child_dependencies.update(
                package_data.get(
                    "dependencies",
                    {}
                )
            )

            child_dependencies.update(
                package_data.get(
                    "optionalDependencies",
                    {}
                )
            )

            for child_name in child_dependencies:

                dependencies.append(
                    child_name
                )

                relationships.append({
                    "parent": package_name,
                    "child": child_name,
                    "type": "transitive"
                })

    # -----------------------------------------------------
    # PACKAGE-LOCK.JSON V1
    # -----------------------------------------------------

    else:

        package_dependencies = data.get(
            "dependencies",
            {}
        )

        def process_dependencies(
            dependency_data,
            parent="project"
        ):

            for (
                package_name,
                package_info
            ) in dependency_data.items():

                dependencies.append(
                    package_name
                )

                dependency_type = (
                    "direct"
                    if parent == "project"
                    else "transitive"
                )

                relationships.append({
                    "parent": parent,
                    "child": package_name,
                    "type": dependency_type
                })

                installed_version = package_info.get(
                    "version"
                )

                if installed_version:

                    dependency_versions[
                        package_name
                    ] = installed_version

                nested_dependencies = (
                    package_info.get(
                        "dependencies",
                        {}
                    )
                )

                if nested_dependencies:

                    process_dependencies(
                        nested_dependencies,
                        package_name
                    )

        process_dependencies(
            package_dependencies
        )

    return clean_results(
        dependencies,
        relationships,
        dependency_versions
    )


# =========================================================
# PACKAGE.JSON
# =========================================================

def extract_package_json(file_path):

    dependencies = []
    relationships = []
    dependency_versions = {}

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    root_dependencies = {}

    root_dependencies.update(
        data.get(
            "dependencies",
            {}
        )
    )

    root_dependencies.update(
        data.get(
            "devDependencies",
            {}
        )
    )

    root_dependencies.update(
        data.get(
            "optionalDependencies",
            {}
        )
    )

    for (
        package_name,
        version
    ) in root_dependencies.items():

        dependencies.append(
            package_name
        )

        relationships.append({
            "parent": "project",
            "child": package_name,
            "type": "direct"
        })

        # package.json normally contains
        # a version range rather than exact
        # installed version.

        if version:

            dependency_versions[
                package_name
            ] = version

    return clean_results(
        dependencies,
        relationships,
        dependency_versions
    )


# =========================================================
# REQUIREMENTS.TXT
# =========================================================

def extract_requirements_txt(file_path):

    dependencies = []
    relationships = []
    dependency_versions = {}

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if line.startswith("-r"):
                continue

            if line.startswith("--"):
                continue

            package_name = line
            version = None

            operators = [
                "==",
                ">=",
                "<=",
                "~=",
                "!=",
                ">",
                "<"
            ]

            for operator in operators:

                if operator in line:

                    parts = line.split(
                        operator,
                        1
                    )

                    package_name = (
                        parts[0].strip()
                    )

                    version = (
                        parts[1].strip()
                    )

                    break

            package_name = (
                package_name
                .split("[")[0]
                .strip()
            )

            if not package_name:
                continue

            dependencies.append(
                package_name
            )

            relationships.append({
                "parent": "project",
                "child": package_name,
                "type": "direct"
            })

            if version:

                dependency_versions[
                    package_name
                ] = version

    return clean_results(
        dependencies,
        relationships,
        dependency_versions
    )


# =========================================================
# POM.XML
# =========================================================

def extract_pom_xml(file_path):

    dependencies = []
    relationships = []
    dependency_versions = {}

    tree = ET.parse(
        file_path
    )

    root = tree.getroot()

    namespace = ""

    if root.tag.startswith("{"):

        namespace = (
            root.tag.split("}")[0]
            + "}"
        )

    dependency_nodes = root.findall(
        ".//"
        + namespace
        + "dependency"
    )

    for dependency in dependency_nodes:

        group_id = dependency.find(
            namespace + "groupId"
        )

        artifact_id = dependency.find(
            namespace + "artifactId"
        )

        version = dependency.find(
            namespace + "version"
        )

        if artifact_id is None:
            continue

        if not artifact_id.text:
            continue

        artifact_name = (
            artifact_id.text.strip()
        )

        if (
            group_id is not None
            and group_id.text
        ):

            package_name = (
                group_id.text.strip()
                + ":"
                + artifact_name
            )

        else:

            package_name = artifact_name

        dependencies.append(
            package_name
        )

        relationships.append({
            "parent": "project",
            "child": package_name,
            "type": "direct"
        })

        if (
            version is not None
            and version.text
        ):

            dependency_versions[
                package_name
            ] = version.text.strip()

    return clean_results(
        dependencies,
        relationships,
        dependency_versions
    )


# =========================================================
# REMOVE DUPLICATES
# =========================================================

def clean_results(
    dependencies,
    relationships,
    dependency_versions
):

    # -----------------------------------------------------
    # Remove duplicate dependency names
    # -----------------------------------------------------

    unique_dependencies = list(
        dict.fromkeys(
            dependencies
        )
    )

    # -----------------------------------------------------
    # Remove duplicate relationships
    # -----------------------------------------------------

    unique_relationships = []

    seen_relationships = set()

    for relationship in relationships:

        key = (
            relationship["parent"],
            relationship["child"],
            relationship["type"]
        )

        if key not in seen_relationships:

            seen_relationships.add(
                key
            )

            unique_relationships.append(
                relationship
            )

    return (
        unique_dependencies,
        unique_relationships,
        dependency_versions
    )


# =========================================================
# BACKWARD COMPATIBILITY
# =========================================================

def extract_dependencies(file_path):

    dependencies, _, _ = (
        extract_dependency_graph(
            file_path
        )
    )

    return dependencies
