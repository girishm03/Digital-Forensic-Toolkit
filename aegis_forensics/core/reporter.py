import os
import json
import datetime
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(case_data: Dict[str, Any], output_path: str, findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Generate an official, court-admissible Digital Forensics & Incident Response (DFIR) Report.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )

    sub_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=12
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )

    bold_cell_style = ParagraphStyle(
        'TableBoldCell',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # Title & Header Banner
    story.append(Paragraph("DIGITAL FORENSICS INVESTIGATION REPORT", title_style))
    story.append(Paragraph(f"CONFIDENTIAL // LAW ENFORCEMENT & DFIR INCIDENT RESPONSE // AEGIS SUITE", sub_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # Case Metadata Table
    meta_data = [
        [Paragraph("Case ID:", bold_cell_style), Paragraph(case_data.get("case_id", "N/A"), cell_style),
         Paragraph("Date of Report:", bold_cell_style), Paragraph(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), cell_style)],
        [Paragraph("Case Title:", bold_cell_style), Paragraph(case_data.get("title", "Untitled Investigation"), cell_style),
         Paragraph("Lead Investigator:", bold_cell_style), Paragraph(case_data.get("investigator", "Unknown"), cell_style)],
        [Paragraph("Organization:", bold_cell_style), Paragraph(case_data.get("organization", "DFIR Unit"), cell_style),
         Paragraph("Target System:", bold_cell_style), Paragraph(case_data.get("target_system", "Unknown Host"), cell_style)],
    ]

    t_meta = Table(meta_data, colWidths=[1.3*inch, 2.3*inch, 1.4*inch, 2.3*inch])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 14))

    # Case Summary
    story.append(Paragraph("1. EXECUTIVE SUMMARY", section_heading))
    desc = case_data.get("description") or "Digital forensic triage and artifact examination conducted in accordance with ISO/IEC 27037 standards for digital evidence handling."
    story.append(Paragraph(desc, body_style))
    story.append(Spacer(1, 12))

    # Evidence Inventory & Cryptographic Baseline
    story.append(Paragraph("2. EVIDENCE INVENTORY & CHAIN OF CUSTODY BASELINE", section_heading))
    evidence_items = case_data.get("evidence_items", [])
    if not evidence_items:
        story.append(Paragraph("No physical or logical evidence items registered to this case file.", body_style))
    else:
        headers = [Paragraph("Evidence ID", bold_cell_style), Paragraph("Label / File", bold_cell_style), Paragraph("Size", bold_cell_style), Paragraph("SHA-256 Hash", bold_cell_style), Paragraph("Status", bold_cell_style)]
        rows = [headers]
        for item in evidence_items:
            rows.append([
                Paragraph(item.get("evidence_id", ""), cell_style),
                Paragraph(f"{item.get('label', '')}<br/><i>{item.get('original_filename', '')}</i>", cell_style),
                Paragraph(item.get("size_human", ""), cell_style),
                Paragraph(f"<font size=6>{item.get('sha256', '')}</font>", cell_style),
                Paragraph(f"<font color='green'><b>{item.get('status', 'SECURED')}</b></font>", cell_style)
            ])
        t_ev = Table(rows, colWidths=[1.1*inch, 2.0*inch, 0.7*inch, 2.6*inch, 0.9*inch])
        t_ev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0284c7")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_ev)

    story.append(Spacer(1, 14))

    # Chain of Custody Audit Trail
    story.append(Paragraph("3. CHAIN OF CUSTODY AUDIT LOG", section_heading))
    coc_events = case_data.get("chain_of_custody", [])
    if coc_events:
        coc_headers = [Paragraph("Timestamp (UTC)", bold_cell_style), Paragraph("Investigator", bold_cell_style), Paragraph("Action", bold_cell_style), Paragraph("Details", bold_cell_style)]
        coc_rows = [coc_headers]
        for coc in coc_events:
            coc_rows.append([
                Paragraph(coc.get("timestamp", "")[:19].replace("T", " "), cell_style),
                Paragraph(coc.get("investigator", ""), cell_style),
                Paragraph(f"<b>{coc.get('action', '')}</b>", cell_style),
                Paragraph(coc.get("details", ""), cell_style)
            ])
        t_coc = Table(coc_rows, colWidths=[1.4*inch, 1.3*inch, 1.8*inch, 2.8*inch])
        t_coc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_coc)

    story.append(Spacer(1, 14))

    # Findings & Anomalies
    if findings:
        story.append(Paragraph("4. FORENSIC FINDINGS & ANOMALY DETECTIONS", section_heading))
        for f in findings:
            sev = f.get("severity", "Medium")
            color = "#dc2626" if sev in ["High", "Critical"] else "#d97706" if sev == "Medium" else "#2563eb"
            finding_text = f"<b><font color='{color}'>[{sev.upper()}] {f.get('threat_type', f.get('title', 'Forensic Artifact'))}</font></b><br/>" \
                           f"Timestamp: {f.get('timestamp', 'N/A')}<br/>" \
                           f"Details: {f.get('details', f.get('description', ''))}"
            story.append(Paragraph(finding_text, body_style))
            story.append(Spacer(1, 6))

    # Investigator Certification / Sign-off
    story.append(Spacer(1, 20))
    story.append(Paragraph("5. INVESTIGATOR DECLARATION & INTEGRITY CERTIFICATION", section_heading))
    declaration = "I hereby certify that the forensic examination of the digital items documented herein was conducted " \
                  "in strict adherence to sound forensic principles. Evidence integrity was safeguarded through cryptographic " \
                  "hashing baselines, and no unauthorized alteration occurred during examination."
    story.append(Paragraph(declaration, body_style))
    story.append(Spacer(1, 24))

    sign_data = [
        [Paragraph(f"<b>Examiner Signature:</b> ___________________________", cell_style),
         Paragraph(f"<b>Date:</b> {datetime.datetime.now().strftime('%Y-%m-%d')}", cell_style)],
        [Paragraph(f"<b>Name:</b> {case_data.get('investigator', 'Examiner')}", cell_style),
         Paragraph(f"<b>Badge/ID:</b> AGY-DFIR-{case_data.get('case_id', '001')}", cell_style)]
    ]
    t_sign = Table(sign_data, colWidths=[4.5*inch, 2.8*inch])
    t_sign.setStyle(TableStyle([('PADDING', (0,0), (-1,-1), 4)]))
    story.append(t_sign)

    doc.build(story)
    return output_path

def generate_html_report(case_data: Dict[str, Any], output_path: str, findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """Generate self-contained HTML forensic case report."""
    evidence_rows = "".join([
        f"""<tr>
            <td><code>{item.get('evidence_id')}</code></td>
            <td><strong>{item.get('label')}</strong><br><small>{item.get('original_filename')}</small></td>
            <td>{item.get('size_human')}</td>
            <td><code class="hash-text">{item.get('sha256')}</code></td>
            <td><span class="badge badge-success">{item.get('status', 'SECURED')}</span></td>
        </tr>""" for item in case_data.get("evidence_items", [])
    ])

    coc_rows = "".join([
        f"""<tr>
            <td>{coc.get('timestamp', '')[:19].replace('T', ' ')}</td>
            <td><strong>{coc.get('investigator')}</strong></td>
            <td><span class="badge badge-info">{coc.get('action')}</span></td>
            <td>{coc.get('details')}</td>
        </tr>""" for coc in case_data.get("chain_of_custody", [])
    ])

    findings_html = ""
    if findings:
        for f in findings:
            sev = f.get("severity", "Medium").lower()
            findings_html += f"""
            <div class="finding-card finding-{sev}">
                <div class="finding-header">
                    <span class="badge badge-{sev}">{f.get('severity', 'INFO')}</span>
                    <strong>{f.get('threat_type', f.get('title', 'Finding'))}</strong>
                    <span class="finding-time">{f.get('timestamp', '')}</span>
                </div>
                <p class="finding-body">{f.get('details', f.get('description', ''))}</p>
            </div>
            """
    else:
        findings_html = "<p class='text-muted'>No anomalies detected in automated analysis.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Case Report: {case_data.get('case_id')}</title>
<style>
    :root {{
        --bg: #0b0f19;
        --card: #151d2e;
        --border: #23314d;
        --text: #e2e8f0;
        --text-dim: #94a3b8;
        --accent: #00ffc8;
        --primary: #38bdf8;
        --danger: #ef4444;
        --warning: #f59e0b;
        --success: #10b981;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        background: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 40px 20px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 1000px;
        margin: 0 auto;
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 40px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }}
    .header {{
        border-bottom: 2px solid var(--border);
        padding-bottom: 20px;
        margin-bottom: 30px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
    }}
    .header h1 {{
        margin: 0 0 5px 0;
        font-size: 26px;
        color: var(--accent);
        letter-spacing: 0.5px;
    }}
    .meta-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 15px;
        background: rgba(0,0,0,0.2);
        padding: 20px;
        border-radius: 8px;
        border: 1px solid var(--border);
        margin-bottom: 30px;
    }}
    .meta-item strong {{
        display: block;
        font-size: 11px;
        color: var(--text-dim);
        text-transform: uppercase;
    }}
    .meta-item span {{
        font-size: 15px;
        color: var(--text);
    }}
    h2 {{
        font-size: 18px;
        color: var(--primary);
        border-bottom: 1px solid var(--border);
        padding-bottom: 8px;
        margin-top: 30px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0 25px 0;
        font-size: 13px;
    }}
    th, td {{
        padding: 10px 12px;
        text-align: left;
        border-bottom: 1px solid var(--border);
    }}
    th {{
        background: rgba(255,255,255,0.03);
        color: var(--text-dim);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
    }}
    .hash-text {{
        font-family: monospace;
        font-size: 11px;
        color: #38bdf8;
        word-break: break-all;
    }}
    .badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }}
    .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--success); }}
    .badge-info {{ background: rgba(56, 189, 248, 0.2); color: var(--primary); }}
    .badge-critical, .badge-high {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); }}
    .finding-card {{
        border: 1px solid var(--border);
        border-left: 4px solid var(--primary);
        background: rgba(0,0,0,0.25);
        padding: 15px;
        border-radius: 6px;
        margin-bottom: 15px;
    }}
    .finding-critical, .finding-high {{ border-left-color: var(--danger); }}
    .finding-medium {{ border-left-color: var(--warning); }}
    .finding-header {{
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 8px;
    }}
    .finding-time {{
        margin-left: auto;
        font-size: 12px;
        color: var(--text-dim);
    }}
    .finding-body {{
        margin: 0;
        font-size: 14px;
        color: var(--text);
    }}
    .print-btn {{
        background: var(--accent);
        color: #0b0f19;
        font-weight: 700;
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        cursor: pointer;
    }}
    @media print {{
        .print-btn {{ display: none; }}
        body {{ background: white; color: black; }}
        .container {{ border: none; box-shadow: none; padding: 0; }}
        th, td {{ border-color: #ddd; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>DIGITAL FORENSICS CASE REPORT</h1>
            <p style="margin: 0; color: var(--text-dim);">Aegis Forensics Suite &bull; Defensive Investigation Record</p>
        </div>
        <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
    </div>

    <div class="meta-grid">
        <div class="meta-item"><strong>Case ID</strong><span>{case_data.get('case_id')}</span></div>
        <div class="meta-item"><strong>Case Title</strong><span>{case_data.get('title')}</span></div>
        <div class="meta-item"><strong>Lead Investigator</strong><span>{case_data.get('investigator')}</span></div>
        <div class="meta-item"><strong>Agency / Org</strong><span>{case_data.get('organization')}</span></div>
        <div class="meta-item"><strong>Target System</strong><span>{case_data.get('target_system')}</span></div>
        <div class="meta-item"><strong>Report Generated</strong><span>{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</span></div>
    </div>

    <h2>1. Executive Summary</h2>
    <p>{case_data.get('description') or 'Digital forensic acquisition and triage report compiled under standard incident response protocols.'}</p>

    <h2>2. Registered Evidence Items &amp; Integrity Baseline</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Evidence Label</th>
                <th>Size</th>
                <th>Cryptographic SHA-256 Hash</th>
                <th>Vault Status</th>
            </tr>
        </thead>
        <tbody>
            {evidence_rows or '<tr><td colspan="5">No evidence items registered.</td></tr>'}
        </tbody>
    </table>

    <h2>3. Chain of Custody Audit Trail</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp (UTC)</th>
                <th>Investigator</th>
                <th>Action</th>
                <th>Custody Notes</th>
            </tr>
        </thead>
        <tbody>
            {coc_rows or '<tr><td colspan="4">No custody records available.</td></tr>'}
        </tbody>
    </table>

    <h2>4. Correlated Findings &amp; Threat Detections</h2>
    {findings_html}

    <h2>5. Investigator Certification</h2>
    <p>I verify that this report accurately reflects the analysis of the preserved digital evidence items.</p>
    <div style="margin-top: 30px; display: flex; justify-content: space-between;">
        <div>______________________________________<br><small>Investigator Signature: {case_data.get('investigator')}</small></div>
        <div>Date: {datetime.datetime.now().strftime('%Y-%m-%d')}</div>
    </div>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
