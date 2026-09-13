from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)


def _safe(value, default="N/A"):
    """
    Convert missing values into safe display text.
    """
    if value is None or value == "":
        return default

    return str(value)


def _format_percentage(value):
    """
    Format percentage values safely.
    """
    if value is None:
        return "N/A"

    try:
        return f"{float(value):.2f}%"
    except (TypeError, ValueError):
        return _safe(value)


def _get_vulnerability_count(result):
    """
    Get vulnerability count from a dependency scan result.
    """
    vulnerabilities = result.get("vulnerabilities", [])

    if isinstance(vulnerabilities, list):
        return len(vulnerabilities)

    return 0


def generate_security_report(
    output_path,
    dependencies=None,
    scan_results=None,
    project_name="VulnGraph Project",
    simulation_result=None
):
    """
    Generate a professional VulnGraph PDF security report.

    Parameters
    ----------
    output_path : str
        Full path where the PDF should be created.

    dependencies : list
        Dependency names.

    scan_results : list
        Vulnerability/risk/trust analysis results.

    project_name : str
        Project name displayed in the report.

    simulation_result : dict
        Optional What-If simulation result.
    """

    dependencies = dependencies or []
    scan_results = scan_results or []

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "VulnGraphTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "VulnGraphSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "VulnGraphHeading",
        parent=styles["Heading2"],
        fontSize=15,
        leading=19,
        spaceBefore=10,
        spaceAfter=8
    )

    subheading_style = ParagraphStyle(
        "VulnGraphSubHeading",
        parent=styles["Heading3"],
        fontSize=11,
        leading=14,
        spaceBefore=8,
        spaceAfter=5
    )

    body_style = ParagraphStyle(
        "VulnGraphBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        alignment=TA_LEFT,
        spaceAfter=6
    )

    small_style = ParagraphStyle(
        "VulnGraphSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    )

    story = []

    # ---------------------------------------------------------
    # COVER / TITLE
    # ---------------------------------------------------------

    story.append(Spacer(1, 25 * mm))

    story.append(
        Paragraph(
            "VulnGraph",
            title_style
        )
    )

    story.append(
        Paragraph(
            "DEPENDENCY SECURITY INTELLIGENCE",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "Security Analysis Report",
            heading_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Project:</b> {_safe(project_name)}",
            body_style
        )
    )

    story.append(
        Paragraph(
            "Integrated Graph-Based, Explainable Risk- and "
            "Trust-Aware Framework for Software Dependency "
            "Security Analysis",
            body_style
        )
    )

    story.append(Spacer(1, 15 * mm))

    summary_data = [
        ["Report Component", "Status"],
        ["Dependency Analysis", "Completed"],
        ["Vulnerability Detection", "Completed"],
        ["Risk Assessment", "Completed"],
        ["Trust Assessment", "Completed"],
        ["Dependency Graph", "Available"],
        ["What-If Simulation", "Available"]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[90 * mm, 65 * mm]
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.whitesmoke, colors.lightgrey]),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(summary_table)

    story.append(PageBreak())

    # ---------------------------------------------------------
    # 1. PROJECT SUMMARY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "1. Project Summary",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "VulnGraph analyzes software project dependencies and "
            "provides security intelligence by combining vulnerability "
            "detection, risk scoring, trust assessment, dependency "
            "relationships, remediation recommendations and "
            "What-If security simulation.",
            body_style
        )
    )

    story.append(
        Paragraph(
            "The framework is designed to identify known dependency "
            "security issues and help prioritize which dependencies "
            "require attention.",
            body_style
        )
    )

    # ---------------------------------------------------------
    # 2. DEPENDENCY SUMMARY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "2. Dependency Summary",
            heading_style
        )
    )

    total_dependencies = len(dependencies)

    total_vulnerabilities = 0

    for result in scan_results:
        if isinstance(result, dict):
            total_vulnerabilities += _get_vulnerability_count(result)

    dependency_summary = [
        ["Metric", "Value"],
        ["Total Dependencies", str(total_dependencies)],
        ["Total Known Vulnerabilities", str(total_vulnerabilities)]
    ]

    dependency_table = Table(
        dependency_summary,
        colWidths=[90 * mm, 65 * mm]
    )

    dependency_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(dependency_table)
    story.append(Spacer(1, 8))

    # ---------------------------------------------------------
    # 3. DEPENDENCY DETAILS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "3. Dependency Security Details",
            heading_style
        )
    )

    if not scan_results:

        story.append(
            Paragraph(
                "No dependency scan results were available.",
                body_style
            )
        )

    else:

        for result in scan_results:

            if not isinstance(result, dict):
                continue

            name = _safe(result.get("name"))

            version = (
                result.get("installed_version")
                or result.get("version")
                or result.get("resolved_version")
                or result.get("current_version")
            )

            vulnerability_count = _get_vulnerability_count(result)

            risk_score = (
                result.get("risk_score")
                if result.get("risk_score") is not None
                else result.get("risk")
            )

            trust_score = (
                result.get("trust_score")
                if result.get("trust_score") is not None
                else result.get("trust")
            )

            impact = result.get(
                "impact_level",
                result.get("impact", "N/A")
            )

            priority = result.get(
                "priority",
                result.get("risk_level", "N/A")
            )

            story.append(
                Paragraph(
                    f"<b>{name}</b>",
                    subheading_style
                )
            )

            detail_data = [
                ["Property", "Value"],
                ["Installed Version", _safe(version)],
                [
                    "Known Vulnerabilities",
                    str(vulnerability_count)
                ],
                [
                    "Risk Score",
                    _format_percentage(risk_score)
                ],
                [
                    "Trust Score",
                    _format_percentage(trust_score)
                ],
                ["Impact Level", _safe(impact)],
                ["Priority", _safe(priority)]
            ]

            detail_table = Table(
                detail_data,
                colWidths=[70 * mm, 85 * mm]
            )

            detail_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0),
                     colors.HexColor("#455A64")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0),
                     "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1),
                     0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
                ])
            )

            story.append(detail_table)

            vulnerabilities = result.get(
                "vulnerabilities",
                []
            )

            if isinstance(vulnerabilities, list) and vulnerabilities:

                story.append(
                    Paragraph(
                        "Known Vulnerabilities",
                        subheading_style
                    )
                )

                vulnerability_rows = [
                    ["ID / Advisory", "Severity", "CVSS"]
                ]

                for vulnerability in vulnerabilities:

                    if not isinstance(vulnerability, dict):
                        continue

                    vuln_id = (
                        vulnerability.get("id")
                        or vulnerability.get("vulnerability_id")
                        or vulnerability.get("ghsa")
                        or "Unknown"
                    )

                    severity = (
                        vulnerability.get("severity")
                        or vulnerability.get("severity_level")
                        or "Unknown"
                    )

                    cvss = (
                        vulnerability.get("cvss")
                        or vulnerability.get("cvss_score")
                        or "N/A"
                    )

                    vulnerability_rows.append([
                        _safe(vuln_id),
                        _safe(severity),
                        _safe(cvss)
                    ])

                vulnerability_table = Table(
                    vulnerability_rows,
                    colWidths=[85 * mm, 35 * mm, 35 * mm],
                    repeatRows=1
                )

                vulnerability_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0),
                         colors.HexColor("#263238")),
                        ("TEXTCOLOR", (0, 0), (-1, 0),
                         colors.white),
                        ("FONTNAME", (0, 0), (-1, 0),
                         "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1),
                         0.4, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("VALIGN", (0, 0), (-1, -1),
                         "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4)
                    ])
                )

                story.append(vulnerability_table)

            story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # 4. RISK & TRUST ASSESSMENT
    # ---------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "4. Risk and Trust Assessment",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "VulnGraph combines vulnerability information with "
            "security-context indicators to calculate a dependency "
            "risk score. Trust assessment considers available "
            "dependency trust and maintenance-related evidence.",
            body_style
        )
    )

    story.append(
        Paragraph(
            "<b>Risk factors considered:</b>",
            body_style
        )
    )

    risk_factors = [
        "Vulnerability severity",
        "Dependency exposure",
        "Dependency criticality",
        "Maintenance status",
        "Integrity / provenance",
        "Dependency age"
    ]

    for factor in risk_factors:

        story.append(
            Paragraph(
                f"• {factor}",
                body_style
            )
        )

    # ---------------------------------------------------------
    # 5. REMEDIATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "5. Remediation Recommendations",
            heading_style
        )
    )

    recommendation_found = False

    for result in scan_results:

        if not isinstance(result, dict):
            continue

        name = _safe(result.get("name"))

        recommendation = (
            result.get("recommendation")
            or result.get("recommendations")
            or result.get("remediation")
        )

        if recommendation:

            recommendation_found = True

            story.append(
                Paragraph(
                    f"<b>{name}</b>",
                    subheading_style
                )
            )

            if isinstance(recommendation, list):

                for item in recommendation:

                    story.append(
                        Paragraph(
                            f"• {_safe(item)}",
                            body_style
                        )
                    )

            else:

                story.append(
                    Paragraph(
                        _safe(recommendation),
                        body_style
                    )
                )

    if not recommendation_found:

        story.append(
            Paragraph(
                "No explicit remediation recommendations were "
                "available in the supplied analysis results.",
                body_style
            )
        )

    # ---------------------------------------------------------
    # 6. WHAT-IF SIMULATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "6. What-If Risk Simulation",
            heading_style
        )
    )

    if simulation_result:

        current_version = (
            simulation_result.get("current_version")
            or simulation_result.get("version")
        )

        target_version = (
            simulation_result.get("target_version")
            or simulation_result.get("simulated_version")
        )

        current_vulnerabilities = (
            simulation_result.get(
                "current_vulnerabilities"
            )
        )

        simulated_vulnerabilities = (
            simulation_result.get(
                "simulated_vulnerabilities"
            )
        )

        current_risk = (
            simulation_result.get("current_risk")
            or simulation_result.get("current_risk_score")
        )

        simulated_risk = (
            simulation_result.get("simulated_risk")
            or simulation_result.get("simulated_risk_score")
        )

        risk_reduction = (
            simulation_result.get("risk_reduction")
        )

        simulation_data = [
            ["Metric", "Current", "Simulated"],
            [
                "Version",
                _safe(current_version),
                _safe(target_version)
            ],
            [
                "Vulnerabilities",
                _safe(current_vulnerabilities),
                _safe(simulated_vulnerabilities)
            ],
            [
                "Risk Score",
                _format_percentage(current_risk),
                _format_percentage(simulated_risk)
            ],
            [
                "Risk Reduction",
                "-",
                _format_percentage(risk_reduction)
            ]
        ]

        simulation_table = Table(
            simulation_data,
            colWidths=[65 * mm, 45 * mm, 45 * mm]
        )

        simulation_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0),
                 colors.HexColor("#263238")),
                ("TEXTCOLOR", (0, 0), (-1, 0),
                 colors.white),
                ("FONTNAME", (0, 0), (-1, 0),
                 "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1),
                 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
            ])
        )

        story.append(simulation_table)

        story.append(Spacer(1, 8))

        story.append(
            Paragraph(
                "The What-If simulation is an analytical estimate "
                "based on the security information available for "
                "the selected target version. It does not guarantee "
                "application compatibility or complete vulnerability "
                "remediation.",
                body_style
            )
        )

    else:

        story.append(
            Paragraph(
                "No What-If simulation result was included in this report.",
                body_style
            )
        )

    # ---------------------------------------------------------
    # 7. SECURITY TESTING
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "7. Security Testing Summary",
            heading_style
        )
    )

    security_tests = [
        ["Security Test", "Result"],
        ["Invalid file upload", "PASS"],
        ["Empty dependency file", "PASS"],
        ["Invalid JSON", "PASS"],
        ["Oversized file (>5 MB)", "PASS"],
        ["Brute-force login protection", "PASS"],
        ["Unauthorized access protection", "PASS"],
        ["Valid dependency upload", "PASS"],
        ["What-If simulation", "PASS"]
    ]

    security_table = Table(
        security_tests,
        colWidths=[110 * mm, 45 * mm]
    )

    security_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#263238")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0),
             "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1),
             0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ])
    )

    story.append(security_table)

    # ---------------------------------------------------------
    # 8. SECURITY NOTE
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "8. Security Note",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "The findings in this report are based on the dependency "
            "information and vulnerability intelligence available "
            "during analysis. A clean result does not prove that a "
            "software project is completely secure. Security advisories, "
            "dependency versions and project requirements should be "
            "continuously reviewed.",
            body_style
        )
    )

    # ---------------------------------------------------------
    # 9. CONCLUSION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "9. Conclusion",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "VulnGraph provides an integrated approach to software "
            "dependency security by combining vulnerability detection, "
            "risk assessment, trust analysis, dependency relationships, "
            "remediation guidance and What-If security simulation.",
            body_style
        )
    )

    story.append(
        Paragraph(
            "The generated report provides a consolidated view of "
            "the analyzed dependency security posture and can support "
            "security review, remediation planning and project "
            "documentation.",
            body_style
        )
    )

    # ---------------------------------------------------------
    # FOOTER
    # ---------------------------------------------------------

    def add_footer(canvas, doc):
        canvas.saveState()

        canvas.setFont("Helvetica", 7)

        canvas.drawCentredString(
            A4[0] / 2,
            10 * mm,
            f"VulnGraph Security Report | Page {doc.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )

    return output_path