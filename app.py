import os
import secrets
import json
import shutil
import time
import xml.etree.ElementTree as ET

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

from werkzeug.utils import secure_filename

from modules.dependency_parser import extract_dependency_graph
from modules.vulnerability_scanner import scan_dependencies
from modules.risk_engine import calculate_risk, get_risk_level

from modules.trust_engine import (
    calculate_trust,
    get_trust_details,
    get_trust_level
)

from modules.graph_engine import build_dependency_graph
from modules.recommendation import generate_recommendation
from modules.simulator import simulate_version_change
from modules.explainability import generate_explanation
from modules.report_generator import generate_security_report


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)


# =========================================================
# SECRET KEY
# =========================================================

app.secret_key = os.environ.get(
    "VULNGRAPH_SECRET_KEY",
    secrets.token_hex(32)
)


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_DOMAIN"] = None


# =========================================================
# LOGIN CREDENTIALS
# =========================================================

VULNGRAPH_USERNAME = os.environ.get(
    "VULNGRAPH_USERNAME",
    "admin"
)

VULNGRAPH_PASSWORD = os.environ.get(
    "VULNGRAPH_PASSWORD",
    "admin123"
)


# =========================================================
# LOGIN RATE LIMITING
# =========================================================

MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = 5 * 60

login_attempts = {}


# =========================================================
# REPORT STORAGE
# =========================================================

REPORT_CACHE = {}

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

REPORT_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)

os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)


# =========================================================
# UPLOAD CONFIGURATION
# =========================================================
# Store temporary uploads outside OneDrive.
# This helps avoid Windows/OneDrive file-lock issues.

UPLOAD_FOLDER = os.path.join(
    os.environ.get(
        "TEMP",
        os.path.expanduser("~")
    ),
    "VulnGraphUploads"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# =========================================================
# ALLOWED FILES
# =========================================================

ALLOWED_FILENAMES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pom.xml"
}


# =========================================================
# LOGIN HELPER
# =========================================================

def is_logged_in():

    return session.get(
        "logged_in",
        False
    )


# =========================================================
# CLIENT IDENTIFIER
# =========================================================

def get_client_identifier():

    return request.remote_addr or "unknown"


# =========================================================
# CHECK LOGIN RATE LIMIT
# =========================================================

def is_login_rate_limited():

    client_id = get_client_identifier()

    current_time = time.time()

    attempts = login_attempts.get(
        client_id,
        []
    )

    valid_attempts = [
        timestamp
        for timestamp in attempts
        if current_time - timestamp
        < LOGIN_ATTEMPT_WINDOW
    ]

    login_attempts[client_id] = valid_attempts

    return len(valid_attempts) >= MAX_LOGIN_ATTEMPTS


# =========================================================
# RECORD FAILED LOGIN
# =========================================================

def record_failed_login():

    client_id = get_client_identifier()

    current_time = time.time()

    attempts = login_attempts.get(
        client_id,
        []
    )

    attempts = [
        timestamp
        for timestamp in attempts
        if current_time - timestamp
        < LOGIN_ATTEMPT_WINDOW
    ]

    attempts.append(
        current_time
    )

    login_attempts[client_id] = attempts


# =========================================================
# CLEAR FAILED LOGINS
# =========================================================

def clear_failed_logins():

    client_id = get_client_identifier()

    login_attempts.pop(
        client_id,
        None
    )


# =========================================================
# GET ECOSYSTEM FROM FILENAME
# =========================================================

def get_ecosystem_from_filename(filename):

    filename = filename.lower()

    if filename in {
        "package.json",
        "package-lock.json"
    }:

        return "npm"

    if filename == "requirements.txt":

        return "pypi"

    if filename == "pom.xml":

        return "maven"

    return None


# =========================================================
# VALIDATE UPLOADED CONTENT
# =========================================================

def validate_uploaded_content(
    file_path,
    filename
):

    try:

        file_size = os.path.getsize(
            file_path
        )

        if file_size == 0:

            return False, (
                "Uploaded file is empty."
            )

        # -------------------------------------------------
        # JSON VALIDATION
        # -------------------------------------------------

        if filename in {
            "package.json",
            "package-lock.json"
        }:

            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if not isinstance(
                data,
                dict
            ):

                return False, (
                    "Invalid JSON structure."
                )

        # -------------------------------------------------
        # XML VALIDATION
        # -------------------------------------------------

        elif filename == "pom.xml":

            ET.parse(
                file_path
            )

        # -------------------------------------------------
        # REQUIREMENTS VALIDATION
        # -------------------------------------------------

        elif filename == "requirements.txt":

            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                content = file.read().strip()

            if not content:

                return False, (
                    "requirements.txt is empty."
                )

        else:

            return False, (
                "Unsupported file type."
            )

        return True, None

    except json.JSONDecodeError:

        return False, (
            "Invalid JSON file."
        )

    except ET.ParseError:

        return False, (
            "Invalid XML file."
        )

    except UnicodeDecodeError:

        return False, (
            "File encoding is not supported."
        )

    except Exception as error:

        print(
            "Content validation error:",
            error
        )

        return False, (
            "Unable to validate uploaded file."
        )


# =========================================================
# GET DEPENDENCY VULNERABILITIES
# =========================================================

def get_dependency_vulnerabilities(
    scan_results,
    dependency
):

    if isinstance(
        scan_results,
        dict
    ):

        result = scan_results.get(
            dependency,
            {}
        )

        if isinstance(
            result,
            dict
        ):

            vulnerabilities = result.get(
                "vulnerabilities",
                []
            )

            if isinstance(
                vulnerabilities,
                list
            ):

                return vulnerabilities

    elif isinstance(
        scan_results,
        list
    ):

        for result in scan_results:

            if not isinstance(
                result,
                dict
            ):

                continue

            if result.get(
                "name"
            ) == dependency:

                vulnerabilities = result.get(
                    "vulnerabilities",
                    []
                )

                if isinstance(
                    vulnerabilities,
                    list
                ):

                    return vulnerabilities

    return []


# =========================================================
# NORMALIZE EXPLANATION
# =========================================================

def normalize_explanation(
    explanation
):

    if isinstance(
        explanation,
        str
    ):

        return explanation

    if isinstance(
        explanation,
        dict
    ):

        for key in [
            "explanation",
            "summary",
            "message",
            "text"
        ]:

            value = explanation.get(
                key
            )

            if value:

                return str(
                    value
                )

    return (
        "Security analysis explanation "
        "is not available."
    )


# =========================================================
# NORMALIZE RECOMMENDATION
# =========================================================

def normalize_recommendation(
    recommendation
):

    if isinstance(
        recommendation,
        str
    ):

        return recommendation

    if isinstance(
        recommendation,
        dict
    ):

        for key in [
            "recommendation",
            "action",
            "message",
            "summary"
        ]:

            value = recommendation.get(
                key
            )

            if value:

                return str(
                    value
                )

    return (
        "Review the affected dependency "
        "and consider upgrading to a "
        "secure supported version."
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        # -------------------------------------------------
        # RATE LIMIT CHECK
        # -------------------------------------------------

        if is_login_rate_limited():

            flash(
                "Too many failed login attempts. "
                "Please try again after a few minutes.",
                "error"
            )

            return render_template(
                "login.html"
            )

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        # -------------------------------------------------
        # VALID LOGIN
        # -------------------------------------------------

        if (
            username == VULNGRAPH_USERNAME
            and password == VULNGRAPH_PASSWORD
        ):

            session.clear()

            session["logged_in"] = True

            clear_failed_logins()

            return redirect(
                url_for("index")
            )

        # -------------------------------------------------
        # FAILED LOGIN
        # -------------------------------------------------

        record_failed_login()

        if is_login_rate_limited():

            flash(
                "Too many failed login attempts. "
                "Please try again after a few minutes.",
                "error"
            )

        else:

            flash(
                "Invalid username or password.",
                "error"
            )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    if not is_logged_in():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# =========================================================
# TEMPORARY FOLDER CLEANUP
# =========================================================

def cleanup_temp_folder(
    path,
    retries=5
):

    if not path:
        return True

    for attempt in range(
        retries
    ):

        try:

            if not os.path.exists(
                path
            ):

                return True

            shutil.rmtree(
                path,
                ignore_errors=False
            )

            print(
                f"Temporary folder cleaned: {path}"
            )

            return True

        except PermissionError as error:

            print(
                f"Cleanup attempt "
                f"{attempt + 1}/{retries} failed: "
                f"{error}"
            )

            time.sleep(
                0.5 * (
                    attempt + 1
                )
            )

        except FileNotFoundError:

            return True

        except Exception as error:

            print(
                "Temporary cleanup error:",
                error
            )

            return False

    print(
        "WARNING: Temporary folder could not "
        "be removed after multiple attempts:",
        path
    )

    return False


# =========================================================
# UPLOAD + SECURITY ANALYSIS
# =========================================================

@app.route(
    "/upload",
    methods=["POST"]
)
def upload():

    # -----------------------------------------------------
    # LOGIN CHECK
    # -----------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("login")
        )

    uploaded_file = request.files.get(
        "file"
    )

    if not uploaded_file:

        flash(
            "Please select a dependency file.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # ORIGINAL FILENAME
    # -----------------------------------------------------

    original_filename = (
        uploaded_file.filename or ""
    ).strip()

    if not original_filename:

        flash(
            "Invalid filename.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # SECURE FILENAME
    # -----------------------------------------------------

    safe_filename = secure_filename(
        original_filename
    )

    if not safe_filename:

        flash(
            "Invalid filename.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # ALLOWLIST
    # -----------------------------------------------------

    if safe_filename not in ALLOWED_FILENAMES:

        flash(
            "Unsupported file. "
            "Allowed files: package.json, "
            "package-lock.json, requirements.txt, pom.xml",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # ECOSYSTEM
    # -----------------------------------------------------

    ecosystem = get_ecosystem_from_filename(
        safe_filename
    )

    if not ecosystem:

        flash(
            "Unable to determine dependency ecosystem.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    temporary_folder = None

    try:

        # -------------------------------------------------
        # TEMPORARY DIRECTORY
        # -------------------------------------------------

        temporary_folder = os.path.join(
            UPLOAD_FOLDER,
            secrets.token_hex(16)
        )

        os.makedirs(
            temporary_folder,
            exist_ok=True
        )

        temporary_root = os.path.realpath(
            temporary_folder
        )

        temporary_path = os.path.realpath(
            os.path.join(
                temporary_root,
                safe_filename
            )
        )

        # -------------------------------------------------
        # PATH SECURITY
        # -------------------------------------------------

        if not temporary_path.startswith(
            temporary_root + os.sep
        ):

            raise ValueError(
                "Unsafe temporary upload path."
            )

        # -------------------------------------------------
        # SAVE UPLOAD
        # -------------------------------------------------

        uploaded_file.save(
            temporary_path
        )

        # -------------------------------------------------
        # FILE SIZE CHECK
        # -------------------------------------------------

        actual_size = os.path.getsize(
            temporary_path
        )

        if actual_size > app.config[
            "MAX_CONTENT_LENGTH"
        ]:

            flash(
                "File is too large. "
                "Maximum allowed size is 5 MB.",
                "error"
            )

            return redirect(
                url_for("index")
            )

        # -------------------------------------------------
        # CONTENT VALIDATION
        # -------------------------------------------------

        valid, error_message = (
            validate_uploaded_content(
                temporary_path,
                safe_filename
            )
        )

        if not valid:

            flash(
                error_message,
                "error"
            )

            return redirect(
                url_for("index")
            )

        # -------------------------------------------------
        # DEPENDENCY EXTRACTION
        # -------------------------------------------------

        extracted = extract_dependency_graph(
            temporary_path,
            ecosystem=ecosystem
        )

        # -------------------------------------------------
        # NORMALIZE EXTRACTION RESULT
        # -------------------------------------------------

        if isinstance(
            extracted,
            tuple
        ):

            if len(extracted) == 3:

                (
                    dependencies,
                    relationships,
                    dependency_versions
                ) = extracted

            elif len(extracted) == 2:

                (
                    dependencies,
                    relationships
                ) = extracted

                dependency_versions = {}

            else:

                dependencies = []
                relationships = []
                dependency_versions = {}

        elif isinstance(
            extracted,
            dict
        ):

            dependencies = extracted.get(
                "dependencies",
                []
            )

            relationships = extracted.get(
                "relationships",
                []
            )

            dependency_versions = extracted.get(
                "dependency_versions",
                {}
            )

        else:

            dependencies = []
            relationships = []
            dependency_versions = {}

        # -------------------------------------------------
        # CHECK DEPENDENCIES
        # -------------------------------------------------

        if not dependencies:

            flash(
                "No dependencies were found in the uploaded file.",
                "error"
            )

            return redirect(
                url_for("index")
            )

        # -------------------------------------------------
        # VULNERABILITY SCANNING
        # -------------------------------------------------

        scan_results = scan_dependencies(
            dependencies,
            dependency_versions,
            ecosystem=ecosystem
        )

        # -------------------------------------------------
        # NORMALIZE SCAN RESULTS
        # -------------------------------------------------

        if isinstance(
            scan_results,
            dict
        ):

            normalized_scan_results = []

            for dependency in dependencies:

                result = scan_results.get(
                    dependency,
                    {}
                )

                if not isinstance(
                    result,
                    dict
                ):

                    result = {}

                result = dict(
                    result
                )

                result.setdefault(
                    "name",
                    dependency
                )

                normalized_scan_results.append(
                    result
                )

            scan_results = normalized_scan_results

        elif not isinstance(
            scan_results,
            list
        ):

            scan_results = []

        # =================================================
        # PROCESS EACH DEPENDENCY
        # =================================================

        processed_results = []

        for dependency in dependencies:

            result = {}

            # ---------------------------------------------
            # FIND SCAN RESULT
            # ---------------------------------------------

            for item in scan_results:

                if not isinstance(
                    item,
                    dict
                ):

                    continue

                if item.get(
                    "name"
                ) == dependency:

                    result = item

                    break

            # ---------------------------------------------
            # VULNERABILITIES
            # ---------------------------------------------

            vulnerabilities = result.get(
                "vulnerabilities",
                []
            )

            if not isinstance(
                vulnerabilities,
                list
            ):

                vulnerabilities = []

            vulnerability_count = len(
                vulnerabilities
            )

            # ---------------------------------------------
            # VERSION
            # ---------------------------------------------

            declared_version = (
                dependency_versions.get(
                    dependency
                )
                if isinstance(
                    dependency_versions,
                    dict
                )
                else None
            )

            installed_version = (
                result.get(
                    "installed_version"
                )
                or result.get(
                    "version"
                )
                or result.get(
                    "resolved_version"
                )
                or declared_version
            )

            # ---------------------------------------------
            # DEPENDENCY TYPE
            # ---------------------------------------------

            dependency_type = "transitive"

            if relationships:

                for relationship in relationships:

                    if not isinstance(
                        relationship,
                        dict
                    ):

                        continue

                    if (
                        relationship.get(
                            "child"
                        ) == dependency
                        and
                        relationship.get(
                            "parent"
                        ) == "project"
                    ):

                        dependency_type = "direct"

                        break

            # ---------------------------------------------
            # TRUST SCORE
            # ---------------------------------------------

            try:

                trust_score = calculate_trust(
                    dependency
                )

            except Exception as error:

                print(
                    "Trust calculation error:",
                    error
                )

                trust_score = (
                    result.get(
                        "trust_score"
                    )
                    if result.get(
                        "trust_score"
                    ) is not None
                    else result.get(
                        "trust",
                        100
                    )
                )

            # ---------------------------------------------
            # NORMALIZE TRUST SCORE
            # ---------------------------------------------

            try:

                trust_score = float(
                    trust_score
                )

            except (
                TypeError,
                ValueError
            ):

                trust_score = 100.0

            trust_score = max(
                0,
                min(
                    trust_score,
                    100
                )
            )

            # ---------------------------------------------
            # TRUST LEVEL
            # ---------------------------------------------

            try:

                trust_level = get_trust_level(
                    trust_score
                )

            except Exception:

                trust_level = (
                    "High"
                    if trust_score >= 80
                    else "Medium"
                    if trust_score >= 50
                    else "Low"
                )

            # ---------------------------------------------
            # TRUST DETAILS
            # ---------------------------------------------

            try:

                trust_details = get_trust_details(
                    dependency
                )

            except Exception:

                trust_details = {}

            # ---------------------------------------------
            # EXPOSURE
            # ---------------------------------------------

            exposure_level = (
                result.get(
                    "exposure"
                )
                or "High"
            )

            # ---------------------------------------------
            # CRITICALITY
            # ---------------------------------------------

            criticality_level = (
                result.get(
                    "criticality"
                )
                or "High"
            )

            # ---------------------------------------------
            # IMPACT
            # ---------------------------------------------

            if vulnerability_count >= 5:

                impact_level = "High"

            elif vulnerability_count >= 2:

                impact_level = "Medium"

            else:

                impact_level = "Low"

            # ---------------------------------------------
            # RISK SCORE
            # ---------------------------------------------

            try:

                risk_score = calculate_risk(
                    vulnerabilities,
                    trust_score,
                    exposure_level=exposure_level,
                    criticality=criticality_level
                )

            except Exception as error:

                print(
                    "Risk calculation error:",
                    error
                )

                risk_score = (
                    result.get(
                        "risk_score"
                    )
                    if result.get(
                        "risk_score"
                    ) is not None
                    else result.get(
                        "risk",
                        0
                    )
                )

            # ---------------------------------------------
            # NORMALIZE RISK
            # ---------------------------------------------

            try:

                risk_score = float(
                    risk_score
                )

            except (
                TypeError,
                ValueError
            ):

                risk_score = 0.0

            risk_score = max(
                0,
                min(
                    risk_score,
                    100
                )
            )

            # ---------------------------------------------
            # RISK LEVEL
            # ---------------------------------------------

            try:

                risk_level = get_risk_level(
                    risk_score
                )

            except Exception:

                risk_level = (
                    "Critical"
                    if risk_score >= 75
                    else "High"
                    if risk_score >= 50
                    else "Medium"
                    if risk_score >= 25
                    else "Low"
                )

            # ---------------------------------------------
            # PRIORITY
            # ---------------------------------------------

            if risk_level == "Critical":

                priority = "Critical"

            elif risk_level == "High":

                priority = "High"

            elif risk_level == "Medium":

                priority = "Medium"

            else:

                priority = "Low"

            # ---------------------------------------------
            # RECOMMENDATION
            # ---------------------------------------------

            try:

                recommendation = generate_recommendation(
                    dependency_name=dependency,
                    risk_score=risk_score,
                    impact_level=impact_level,
                    vulnerability_count=vulnerability_count,
                    vulnerabilities=vulnerabilities,
                    installed_version=installed_version
                )

            except Exception as error:

                print(
                    "Recommendation error:",
                    error
                )

                recommendation = (
                    "Review the dependency "
                    "and upgrade to a secure version."
                )

            recommendation = normalize_recommendation(
                recommendation
            )

            # ---------------------------------------------
            # EXPLANATION
            # ---------------------------------------------

            try:

                explanation = generate_explanation(
                    dependency,
                    vulnerability_count,
                    trust_score,
                    risk_score,
                    impact_level,
                    priority,
                    vulnerabilities
                )

            except Exception as error:

                print(
                    "Explanation error:",
                    error
                )

                explanation = (
                    "The dependency was analyzed "
                    "using vulnerability, risk, "
                    "trust and impact indicators."
                )

            explanation = normalize_explanation(
                explanation
            )

            # ---------------------------------------------
            # FINAL RESULT
            # ---------------------------------------------

            processed_results.append({

                "name":
                    dependency,

                "version":
                    installed_version,

                "declared_version":
                    declared_version,

                "installed_version":
                    installed_version,

                "dependency_type":
                    dependency_type,

                "vulnerabilities":
                    vulnerabilities,

                "vulnerability_count":
                    vulnerability_count,

                "risk_score":
                    risk_score,

                "risk":
                    risk_score,

                "risk_level":
                    risk_level,

                "priority":
                    priority,

                "trust_score":
                    trust_score,

                "trust":
                    trust_score,

                "trust_level":
                    trust_level,

                "trust_details":
                    trust_details,

                "exposure":
                    exposure_level,

                "criticality":
                    criticality_level,

                "impact":
                    impact_level,

                "impact_level":
                    impact_level,

                "recommendation":
                    recommendation,

                "explanation":
                    explanation
            })

        # =================================================
        # BUILD DEPENDENCY GRAPH
        # =================================================

        graph_data = build_dependency_graph(
            dependencies,
            relationships,
            processed_results
        )

        # =================================================
        # STORE ANALYSIS FOR PDF
        # =================================================

        analysis_id = secrets.token_hex(
            16
        )

        REPORT_CACHE[
            analysis_id
        ] = {

            "dependencies":
                dependencies,

            "scan_results":
                processed_results,

            "filename":
                safe_filename,

            "ecosystem":
                ecosystem,

            "project_name":
                "VulnGraph Project",

            "simulation":
                None
        }

        session[
            "analysis_id"
        ] = analysis_id

        # =================================================
        # SUMMARY
        # =================================================

        total_dependencies = len(
            processed_results
        )

        vulnerable_dependencies = sum(
            1
            for result in processed_results
            if result.get(
                "vulnerability_count",
                0
            ) > 0
        )

        total_vulnerabilities = sum(
            result.get(
                "vulnerability_count",
                0
            )
            for result in processed_results
        )

        if processed_results:

            average_risk = round(

                sum(

                    float(
                        result.get(
                            "risk_score",
                            0
                        ) or 0
                    )

                    for result in processed_results

                )
                /
                len(
                    processed_results
                ),

                2
            )

        else:

            average_risk = 0

        # =================================================
        # DASHBOARD
        # =================================================

        return render_template(

            "dashboard.html",

            results=
                processed_results,

            graph_data=
                graph_data,

            total_dependencies=
                total_dependencies,

            vulnerable_dependencies=
                vulnerable_dependencies,

            total_vulnerabilities=
                total_vulnerabilities,

            average_risk=
                average_risk,

            ecosystem=
                ecosystem,

            filename=
                safe_filename
        )

    except Exception as error:

        print(
            "Upload analysis error:",
            error
        )

        flash(
            "Unable to analyze the uploaded dependency file.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    finally:

        # -------------------------------------------------
        # TEMPORARY FILE CLEANUP
        # -------------------------------------------------

        cleanup_temp_folder(
            temporary_folder
        )


# =========================================================
# WHAT-IF SIMULATION
# =========================================================

@app.route(
    "/simulate",
    methods=["POST"]
)
def simulate():

    # -----------------------------------------------------
    # LOGIN CHECK
    # -----------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("login")
        )

    dependency = request.form.get(
        "dependency",
        ""
    ).strip()

    target_version = request.form.get(
        "target_version",
        ""
    ).strip()

    current_version = request.form.get(
        "current_version",
        ""
    ).strip()

    ecosystem = request.form.get(
        "ecosystem",
        "npm"
    ).strip()

    # -----------------------------------------------------
    # VALIDATE DEPENDENCY
    # -----------------------------------------------------

    if not dependency:

        flash(
            "Dependency name is required.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # VALIDATE TARGET VERSION
    # -----------------------------------------------------

    if not target_version:

        flash(
            "Target version is required.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    try:

        # -------------------------------------------------
        # CURRENT VERSION SCAN
        # -------------------------------------------------

        current_scan = scan_dependencies(

            [dependency],

            {
                dependency:
                    current_version
            },

            ecosystem=
                ecosystem
        )

        # -------------------------------------------------
        # TARGET VERSION SCAN
        # -------------------------------------------------

        target_scan = scan_dependencies(

            [dependency],

            {
                dependency:
                    target_version
            },

            ecosystem=
                ecosystem
        )

        # -------------------------------------------------
        # CURRENT VULNERABILITIES
        # -------------------------------------------------

        current_vulnerabilities = (
            get_dependency_vulnerabilities(
                current_scan,
                dependency
            )
        )

        # -------------------------------------------------
        # TARGET VULNERABILITIES
        # -------------------------------------------------

        target_vulnerabilities = (
            get_dependency_vulnerabilities(
                target_scan,
                dependency
            )
        )

        # -------------------------------------------------
        # TRUST SCORE
        # -------------------------------------------------

        try:

            trust_score = calculate_trust(
                dependency
            )

        except Exception:

            trust_score = 100

        # -------------------------------------------------
        # SIMULATION
        # -------------------------------------------------

        simulation = simulate_version_change(

            current_vulnerabilities,

            target_vulnerabilities,

            trust_score,

            "High",

            "High"
        )

        # -------------------------------------------------
        # STORE SIMULATION
        # -------------------------------------------------

        analysis_id = session.get(
            "analysis_id"
        )

        if analysis_id in REPORT_CACHE:

            REPORT_CACHE[
                analysis_id
            ][
                "simulation"
            ] = simulation

            REPORT_CACHE[
                analysis_id
            ][
                "simulation_dependency"
            ] = dependency

            REPORT_CACHE[
                analysis_id
            ][
                "simulation_current_version"
            ] = current_version

            REPORT_CACHE[
                analysis_id
            ][
                "simulation_target_version"
            ] = target_version

        # -------------------------------------------------
        # SIMULATION PAGE
        # -------------------------------------------------

        return render_template(

            "simulation.html",

            dependency=
                dependency,

            current_version=
                current_version,

            target_version=
                target_version,

            current_vulnerabilities=
                current_vulnerabilities,

            target_vulnerabilities=
                target_vulnerabilities,

            trust_score=
                trust_score,

            simulation=
                simulation
        )

    except Exception as error:

        print(
            "Simulation error:",
            error
        )

        flash(
            "Unable to perform What-If simulation.",
            "error"
        )

        return redirect(
            url_for("index")
        )


# =========================================================
# GENERATE PDF SECURITY REPORT
# =========================================================

@app.route(
    "/generate-report",
    methods=["GET"]
)
def generate_report():

    # -----------------------------------------------------
    # LOGIN CHECK
    # -----------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("login")
        )

    # -----------------------------------------------------
    # ANALYSIS ID
    # -----------------------------------------------------

    analysis_id = session.get(
        "analysis_id"
    )

    if not analysis_id:

        flash(
            "No security analysis is available "
            "for PDF report generation.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # GET ANALYSIS
    # -----------------------------------------------------

    analysis = REPORT_CACHE.get(
        analysis_id
    )

    if not analysis:

        flash(
            "Security analysis session has expired. "
            "Please upload the dependency file again.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------
    # PDF FILENAME
    # -----------------------------------------------------

    pdf_filename = (
        "VulnGraph_Security_Report.pdf"
    )

    pdf_path = os.path.join(

        REPORT_FOLDER,

        f"{analysis_id}_{pdf_filename}"
    )

    try:

        # -------------------------------------------------
        # GENERATE PDF
        # -------------------------------------------------

        generate_security_report(

            output_path=
                pdf_path,

            dependencies=
                analysis.get(
                    "dependencies",
                    []
                ),

            scan_results=
                analysis.get(
                    "scan_results",
                    []
                ),

            project_name=
                analysis.get(
                    "project_name",
                    "VulnGraph Project"
                ),

            simulation_result=
                analysis.get(
                    "simulation"
                )
        )

        # -------------------------------------------------
        # VERIFY PDF
        # -------------------------------------------------

        if not os.path.isfile(
            pdf_path
        ):

            raise FileNotFoundError(
                "PDF file was not created."
            )

        # -------------------------------------------------
        # SEND PDF
        # -------------------------------------------------

        return send_file(

            pdf_path,

            as_attachment=True,

            download_name=
                pdf_filename,

            mimetype=
                "application/pdf"
        )

    except Exception as error:

        print(
            "PDF generation error:",
            error
        )

        flash(
            "Unable to generate the security report.",
            "error"
        )

        return redirect(
            url_for("index")
        )


# =========================================================
# FILE SIZE ERROR
# =========================================================

@app.errorhandler(
    413
)
def request_entity_too_large(
    error
):

    flash(
        "File is too large. "
        "Maximum allowed size is 5 MB.",
        "error"
    )

    return redirect(
        url_for("index")
    )


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False
    )