import json


def extract_dependencies(file_path):
    """
    Extract direct and transitive dependencies
    from an npm package-lock.json file.

    Returns a list of unique dependency names.
    """

    dependencies = []

    # =========================
    # Read package-lock.json
    # =========================

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    # =========================
    # Check npm lockfile version
    # =========================

    lockfile_version = data.get(
        "lockfileVersion",
        1
    )

    # =========================
    # npm lockfileVersion 2 / 3
    # =========================

    if lockfile_version >= 2:

        packages = data.get(
            "packages",
            {}
        )

        for package_path, package_data in packages.items():

            # Root project itself skip pannuvom
            if package_path == "":
                continue

            # node_modules/<package-name>
            if "node_modules/" in package_path:

                package_name = package_path.split(
                    "node_modules/"
                )[-1]

                # Scoped package support:
                # @scope/package
                if package_name:

                    dependencies.append(
                        package_name
                    )

    # =========================
    # npm lockfileVersion 1
    # =========================

    else:

        package_dependencies = data.get(
            "dependencies",
            {}
        )

        def extract_nested_dependencies(
            dependency_data
        ):

            for package_name, package_info in dependency_data.items():

                dependencies.append(
                    package_name
                )

                nested_dependencies = package_info.get(
                    "dependencies",
                    {}
                )

                if nested_dependencies:

                    extract_nested_dependencies(
                        nested_dependencies
                    )

        extract_nested_dependencies(
            package_dependencies
        )

    # =========================
    # Remove duplicates
    # =========================

    unique_dependencies = list(
        dict.fromkeys(
            dependencies
        )
    )

    return unique_dependencies