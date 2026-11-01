
import os
import logging
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

logger = logging.getLogger("threatlens.report_generator")


def safe_text(value, default="N/A"):
    """Safely convert dynamic values into PDF-compatible text."""

    if value is None or value == "":
        value = default

    return escape(str(value))


def safe_percentage(value):
    """Convert a probability into a percentage safely."""

    try:
        number = float(value)

        if not 0 <= number <= 1:
            return 0.0

        return number * 100

    except (TypeError, ValueError):
        return 0.0


def generate_pdf_report(
    scan_data: dict,
    scan_result_data: dict,
    output_path: str,
) -> str:
    """
    Generate a professional cybersecurity audit PDF report.
    """

    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom brand styles.
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=colors.HexColor("#0C1423"),
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=colors.HexColor("#38D6C5"),
        spaceAfter=12,
    )

    h2_style = ParagraphStyle(
        "Heading2Custom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#111C2E"),
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#25354B"),
        leading=12,
        wordWrap="CJK",
    )

    mono_style = ParagraphStyle(
        "MonoCustom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#162338"),
        leading=10,
        wordWrap="CJK",
    )

    badge_style = ParagraphStyle(
        "BadgeCustom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        alignment=1,
    )

    story = []

    # 1. Header Banner.
    story.append(
        Paragraph(
            "THREATLENS AI &bull; SECURITY AUDIT REPORT",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Malware Classification &amp; Static Threat Intelligence Engine",
            subtitle_style,
        )
    )

    story.append(
        HRFlowable(
            width="100%",
            thickness=1.5,
            color=colors.HexColor("#38D6C5"),
            spaceAfter=12,
        )
    )

    # 2. Executive Summary & Risk Badge.
    risk_level = str(
        scan_data.get("risk_level") or "Unknown"
    ).capitalize()

    try:
        risk_score = max(
            0,
            min(100, int(scan_data.get("risk_score", 0))),
        )
    except (TypeError, ValueError):
        risk_score = 0

    classification = str(
        scan_data.get("classification") or "Unclassified"
    )

    risk_colors = {
        "Critical": "#D94C63",
        "High": "#F16B75",
        "Medium": "#F5B84B",
        "Low": "#35C98A",
        "Unknown": "#64748B",
    }

    risk_bg = risk_colors.get(
        risk_level,
        "#64748B",
    )

    risk_badge = Paragraph(
        (
            "<font color='white'><b>"
            f"RISK LEVEL: {safe_text(risk_level).upper()} "
            f"({risk_score}/100) &bull; "
            f"{safe_text(classification).upper()}"
            "</b></font>"
        ),
        badge_style,
    )

    badge_table = Table(
        [[risk_badge]],
        colWidths=[540],
    )

    badge_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor(risk_bg),
            ),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )

    story.append(badge_table)
    story.append(Spacer(1, 12))

    # 3. File & Scan Overview.
    story.append(
        Paragraph(
            "1. Scan &amp; File Overview",
            h2_style,
        )
    )

    created_at = scan_data.get("created_at")

    if isinstance(created_at, datetime):
        date_str = created_at.strftime("%Y-%m-%d %H:%M:%S")
    else:
        date_str = str(created_at or "N/A")

    static_info = scan_result_data.get("static_analysis") or {}

    file_size = scan_data.get("file_size", 0)

    try:
        file_size = f"{int(file_size):,} bytes"
    except (TypeError, ValueError):
        file_size = "N/A"

    file_hash = (
        scan_data.get("file_hash")
        or static_info.get("sha256")
        or "N/A"
    )

    overview_data = [
        [
            Paragraph("<b>File Name:</b>", body_style),
            Paragraph(safe_text(scan_data.get("file_name")), body_style),
            Paragraph("<b>Scan ID:</b>", body_style),
            Paragraph(safe_text(scan_data.get("scan_id")), body_style),
        ],
        [
            Paragraph("<b>File Size:</b>", body_style),
            Paragraph(file_size, body_style),
            Paragraph("<b>Scan Mode:</b>", body_style),
            Paragraph(
                safe_text(
                    scan_data.get("scan_mode", "standard")
                ).upper(),
                body_style,
            ),
        ],
        [
            Paragraph("<b>File Type:</b>", body_style),
            Paragraph(
                safe_text(scan_data.get("file_type", "Unknown")),
                body_style,
            ),
            Paragraph("<b>Scan Timestamp:</b>", body_style),
            Paragraph(safe_text(date_str), body_style),
        ],
        [
            Paragraph("<b>SHA-256:</b>", body_style),
            Paragraph(safe_text(file_hash), mono_style),
            "",
            "",
        ],
        [
            Paragraph("<b>MD5:</b>", body_style),
            Paragraph(
                safe_text(static_info.get("md5")),
                mono_style,
            ),
            "",
            "",
        ],
    ]

    overview_table = Table(
        overview_data,
        colWidths=[90, 200, 90, 160],
    )

    overview_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F4F7FB"),
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#D1D9E4"),
            ),
            ("SPAN", (1, 3), (3, 3)),
            ("SPAN", (1, 4), (3, 4)),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )

    story.append(overview_table)
    story.append(Spacer(1, 10))

    # 4. Machine Learning Classification.
    story.append(
        Paragraph(
            "2. Machine Learning Threat Classification",
            h2_style,
        )
    )

    ml_pred = scan_result_data.get("ml_prediction") or {}

    if not isinstance(ml_pred, dict):
        ml_pred = {}

    probs = ml_pred.get("class_probabilities") or {}

    if not isinstance(probs, dict):
        probs = {}

    p_mal = safe_percentage(probs.get("Malicious", 0))
    p_ben = safe_percentage(probs.get("Benign", 0))

    ml_available = bool(ml_pred)

    model_name = (
        ml_pred.get("model_name", "N/A")
        if ml_available
        else "Not used"
    )

    model_version = (
        ml_pred.get("model_version", "N/A")
        if ml_available
        else "N/A"
    )

    try:
        confidence = safe_percentage(
            ml_pred.get("confidence", 0)
        )
    except (TypeError, ValueError):
        confidence = 0.0

    ml_table_data = [
        [
            Paragraph("<b>Primary Engine:</b>", body_style),
            Paragraph(
                "Locally Trained Machine Learning (No Cloud API)",
                body_style,
            ),
        ],
        [
            Paragraph("<b>Active Model:</b>", body_style),
            Paragraph(
                (
                    f"{safe_text(str(model_name).replace('_', ' '))} "
                    f"(v{safe_text(model_version)})"
                ),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Predicted Label:</b>", body_style),
            Paragraph(
                (
                    f"<b>{safe_text(classification)}</b> "
                    f"(Confidence: "
                    f"{confidence:.2f}%)"
                    if ml_available
                    else f"<b>{safe_text(classification)}</b> "
                    "(ML prediction unavailable or not used)"
                ),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Malware Family:</b>", body_style),
            Paragraph(
                safe_text(scan_data.get("malware_family")),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Class Probabilities:</b>", body_style),
            Paragraph(
                (
                    f"Malicious: {p_mal:.2f}% | "
                    f"Benign: {p_ben:.2f}%"
                    if ml_available
                    else "Not available"
                ),
                body_style,
            ),
        ],
    ]

    ml_table = Table(
        ml_table_data,
        colWidths=[130, 410],
    )

    ml_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F4F7FB"),
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#D1D9E4"),
            ),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )

    story.append(ml_table)
    story.append(Spacer(1, 10))

    # 5. YARA Signature Detections.
    story.append(
        Paragraph(
            "3. YARA Signature Detection Engine",
            h2_style,
        )
    )

    yara_list = scan_result_data.get("yara_results") or []

    if yara_list:
        yara_rows = [[
            Paragraph("<b>Rule Name</b>", body_style),
            Paragraph("<b>Category</b>", body_style),
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>Description</b>", body_style),
        ]]

        for yr in yara_list:
            yara_rows.append([
                Paragraph(
                    safe_text(yr.get("rule_name")),
                    mono_style,
                ),
                Paragraph(
                    safe_text(yr.get("category")),
                    body_style,
                ),
                Paragraph(
                    safe_text(yr.get("severity")),
                    body_style,
                ),
                Paragraph(
                    safe_text(yr.get("description")),
                    body_style,
                ),
            ])

        yara_table = Table(
            yara_rows,
            colWidths=[150, 80, 70, 240],
            repeatRows=1,
        )

        yara_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#E2E8F0"),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1"),
                ),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )

        story.append(yara_table)

    else:
        story.append(
            Paragraph(
                "<i>No matching YARA signatures were reported. "
                "This does not guarantee that the file is safe.</i>",
                body_style,
            )
        )

    story.append(Spacer(1, 10))

    # 6. Static Analysis & Indicators.
    story.append(
        Paragraph(
            "4. Static Analysis Findings &amp; PE Structure",
            h2_style,
        )
    )

    entropy_val = static_info.get("entropy", 0.0)

    try:
        entropy_val = max(
            0.0,
            min(8.0, float(entropy_val)),
        )
    except (TypeError, ValueError):
        entropy_val = 0.0

    sections = static_info.get("sections") or []
    obfuscation = static_info.get("obfuscation_indicators") or []
    imported_apis = static_info.get("imported_apis") or []

    static_summary = [
        [
            Paragraph("<b>Shannon Entropy:</b>", body_style),
            Paragraph(
                (
                    f"{entropy_val:.4f}/8.0 "
                    f"({'High' if entropy_val > 7.2 else 'Standard'})"
                ),
                body_style,
            ),
        ],
        [
            Paragraph("<b>PE Sections:</b>", body_style),
            Paragraph(
                (
                    f"{len(sections)} sections parsed "
                    f"({sum(1 for section in sections if section.get('is_suspicious'))} suspicious)"
                    if static_info.get("is_pe")
                    else "Not applicable - non-PE file"
                ),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Sensitive APIs:</b>", body_style),
            Paragraph(
                safe_text(", ".join(imported_apis[:10]), "None detected"),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Structural Anomalies:</b>", body_style),
            Paragraph(
                (
                    "; ".join(
                        safe_text(item)
                        for item in obfuscation
                    )
                    if obfuscation
                    else "None identified"
                ),
                body_style,
            ),
        ],
    ]

    static_table = Table(
        static_summary,
        colWidths=[130, 410],
    )

    static_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F4F7FB"),
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#D1D9E4"),
            ),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )

    story.append(static_table)
    story.append(Spacer(1, 10))

    # 7. Risk Assessment & Recommended Actions.
    risk_info = scan_result_data.get("risk_assessment") or {}

    reasons = risk_info.get("reasons") or []
    recommendations = risk_info.get("recommended_actions") or []

    story.append(
        Paragraph(
            "5. Risk Scoring &amp; Recommended Actions",
            h2_style,
        )
    )

    reasons_text = (
        "<br/>&bull; ".join(
            safe_text(reason)
            for reason in reasons
        )
        if reasons
        else "No risk indicators flagged."
    )

    recommendations_text = (
        "<br/>&bull; ".join(
            safe_text(action)
            for action in recommendations
        )
        if recommendations
        else "Standard procedures."
    )

    actions_table_data = [
        [
            Paragraph("<b>Scoring Breakdown:</b>", body_style),
            Paragraph(
                f"&bull; {reasons_text}",
                body_style,
            ),
        ],
        [
            Paragraph("<b>Action Protocol:</b>", body_style),
            Paragraph(
                f"&bull; {recommendations_text}",
                body_style,
            ),
        ],
    ]

    actions_table = Table(
        actions_table_data,
        colWidths=[130, 410],
    )

    actions_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F4F7FB"),
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#D1D9E4"),
            ),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.append(actions_table)
    story.append(Spacer(1, 15))

    # Footer.
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        alignment=1,
    )

    footer_text = Paragraph(
        (
            "<font color='#64748B'><i>"
            "ThreatLens AI Security Engine &bull; "
            "Generated automatically via static analysis, "
            "local ML classification, and signature matching. "
            "Never executes uploaded binaries."
            "</i></font>"
        ),
        footer_style,
    )

    story.append(footer_text)

    doc.build(story)

    logger.info(
        "Generated PDF report at %s",
        output_path,
    )

    return output_path
