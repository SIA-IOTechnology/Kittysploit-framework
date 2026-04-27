#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from core.framework.analysis import Analysis
from core.framework.option import OptString
from core.models.models import Host, Service, Vulnerability, Credential, Note, Loot
import os
from datetime import datetime

# ReportLab imports
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, HRFlowable
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class Module(Analysis):
    """KittyReport Generator - Professional PDF reporting engine."""
    
    __info__ = {
        'name': 'KittyReport Generator',
        'description': 'Generates a professional, high-design PDF report of all findings (Hosts, Vulns, Creds, Loot).',
        'author': ['KittySploit Team'],
        'license': 'MIT',
        'type': 'analysis',
        'dependencies': ['reportlab']
    }

    FILENAME = OptString("penetration_test_report.pdf", description="Output filename", required=True)
    WORKSPACE = OptString("default", description="Workspace to report", required=True)
    TITLE = OptString("Penetration Test Report", description="Report title", required=True)
    SUBTITLE = OptString("Security Assessment Findings", description="Report subtitle", required=True)
    AUTHOR = OptString("KittySploit Offensive Team", description="Report author", required=True)

    def run(self):
        if not REPORTLAB_AVAILABLE:
            print_error("ReportLab is not installed. Please install it with 'pip install reportlab'.")
            return False

        workspace_name = self.WORKSPACE
        filename = self.FILENAME
        
        if not filename.endswith('.pdf'):
            filename += '.pdf'
        
        output_dir = os.path.join(os.getcwd(), "output", "reports")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        full_path = os.path.join(output_dir, filename)
        
        print_status(f"Generating professional report for workspace: {workspace_name}")
        
        try:
            with self.framework.db_manager.get_db_session(workspace_name) as s:
                # Query data
                hosts = s.query(Host).all()
                creds = s.query(Credential).all()
                vulns = s.query(Vulnerability).all()
                loots = s.query(Loot).all()
                notes = s.query(Note).all()

                # Start PDF Generation
                doc = SimpleDocTemplate(full_path, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
                styles = getSampleStyleSheet()
                
                # Custom Styles
                title_style = ParagraphStyle('TitleStyle', parent=styles['Title'], fontSize=28, textColor=colors.HexColor('#2c3e50'), spaceAfter=10, alignment=TA_CENTER)
                subtitle_style = ParagraphStyle('SubtitleStyle', parent=styles['Normal'], fontSize=16, textColor=colors.HexColor('#7f8c8d'), spaceAfter=30, alignment=TA_CENTER)
                heading1_style = ParagraphStyle('Heading1Style', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#2980b9'), spaceBefore=20, spaceAfter=15, borderPadding=10)
                heading2_style = ParagraphStyle('Heading2Style', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#2c3e50'), spaceBefore=15, spaceAfter=10)
                normal_style = styles['Normal']
                
                elements = []

                # --- Cover Page ---
                logo_path = os.path.join(os.getcwd(), 'static', 'logo.jpg')
                if os.path.exists(logo_path):
                    elements.append(Image(logo_path, width=2*inch, height=2*inch))
                
                elements.append(Spacer(1, 1.5*inch))
                elements.append(Paragraph(self.TITLE, title_style))
                elements.append(Paragraph(self.SUBTITLE, subtitle_style))
                elements.append(Spacer(1, 1*inch))
                
                # Info Box
                info_data = [
                    ["Workspace:", workspace_name],
                    ["Date:", datetime.now().strftime('%B %d, %Y')],
                    ["Time:", datetime.now().strftime('%H:%M:%S')],
                    ["Assessed by:", self.AUTHOR]
                ]
                it = Table(info_data, colWidths=[1.5*inch, 3*inch])
                it.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2980b9')),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#ecf0f1')),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                ]))
                elements.append(it)
                elements.append(PageBreak())

                # --- Executive Summary ---
                elements.append(Paragraph("Executive Summary", heading1_style))
                elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#2980b9'), spaceAfter=20))
                
                summary_text = f"This report outlines the security assessment findings for the <b>{workspace_name}</b> environment. " \
                               f"During the assessment, a total of <b>{len(hosts)}</b> hosts were identified, with <b>{len(vulns)}</b> security vulnerabilities discovered."
                elements.append(Paragraph(summary_text, normal_style))
                elements.append(Spacer(1, 0.3*inch))

                # Risk Distribution Table
                if vulns:
                    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
                    for v in vulns:
                        level = v.risk_level.lower() if v.risk_level else 'unknown'
                        risk_counts[level] = risk_counts.get(level, 0) + 1
                    
                    risk_data = [
                        ["Critical", "High", "Medium", "Low"],
                        [str(risk_counts['critical']), str(risk_counts['high']), str(risk_counts['medium']), str(risk_counts['low'])]
                    ]
                    rt = Table(risk_data, colWidths=[1.2*inch]*4)
                    rt.setStyle(TableStyle([
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 14),
                        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#c0392b')), # Critical
                        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#e67e22')), # High
                        ('BACKGROUND', (2, 0), (2, 0), colors.HexColor('#f1c40f')), # Medium
                        ('BACKGROUND', (3, 0), (3, 0), colors.HexColor('#3498db')), # Low
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('GRID', (0, 0), (-1, -1), 1, colors.white),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                        ('TOPPADDING', (0, 0), (-1, -1), 10),
                    ]))
                    elements.append(rt)
                
                elements.append(Spacer(1, 0.5*inch))

                # --- Section 1: Asset Inventory ---
                elements.append(Paragraph("1. Asset Inventory", heading1_style))
                if not hosts:
                    elements.append(Paragraph("No assets discovered in this workspace.", normal_style))
                else:
                    host_data = [["IP Address", "Hostname", "Operating System", "Status"]]
                    for h in hosts:
                        host_data.append([h.address, h.hostname or "-", h.os or "N/A", h.status.upper()])
                    
                    ht = Table(host_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1*inch], repeatRows=1)
                    ht.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7'))
                    ]))
                    elements.append(ht)
                
                elements.append(PageBreak())

                # --- Section 2: Security Findings ---
                elements.append(Paragraph("2. Security Findings", heading1_style))
                if not vulns:
                    elements.append(Paragraph("Great! No security vulnerabilities were recorded for this assessment.", normal_style))
                else:
                    for i, v in enumerate(vulns):
                        # Severity Badge
                        sev = v.risk_level.lower() if v.risk_level else 'unknown'
                        sev_color = colors.HexColor('#95a5a6')
                        if sev == 'critical': sev_color = colors.HexColor('#c0392b')
                        elif sev == 'high': sev_color = colors.HexColor('#e67e22')
                        elif sev == 'medium': sev_color = colors.HexColor('#f1c40f')
                        elif sev == 'low': sev_color = colors.HexColor('#3498db')

                        elements.append(Paragraph(f"Finding #{i+1}: {v.name}", heading2_style))
                        
                        # Info Table for the finding
                        finding_info = [
                            ["Severity:", Paragraph(f"<font color='{sev_color}'><b>{sev.upper()}</b></font>", normal_style)],
                            ["CVE:", v.cve or "N/A"],
                            ["CVSS:", v.cvss_score or "N/A"]
                        ]
                        fit = Table(finding_info, colWidths=[1.5*inch, 4*inch])
                        fit.setStyle(TableStyle([
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ecf0f1')),
                        ]))
                        elements.append(fit)
                        elements.append(Spacer(1, 0.1*inch))
                        
                        elements.append(Paragraph("<b>Description:</b>", normal_style))
                        elements.append(Paragraph(v.description or "No description provided.", normal_style))
                        elements.append(Spacer(1, 0.1*inch))
                        
                        if v.remediation:
                            elements.append(Paragraph("<b>Recommendation:</b>", normal_style))
                            elements.append(Paragraph(v.remediation, normal_style))
                        
                        elements.append(Spacer(1, 0.3*inch))
                        if (i + 1) % 2 == 0: elements.append(PageBreak()) # Break every 2 findings to keep it clean

                # --- Section 3: Compromised Credentials ---
                if elements[-1] != PageBreak(): elements.append(PageBreak())
                elements.append(Paragraph("3. Compromised Credentials", heading1_style))
                if not creds:
                    elements.append(Paragraph("No credentials were recovered during this assessment.", normal_style))
                else:
                    cred_data = [["Username", "Secret (Password/Hash)", "Type", "Source"]]
                    for c in creds:
                        pwd = c.password or c.password_hash or "********"
                        cred_data.append([c.username or "Unknown", pwd, c.hash_type or "plain", c.source or "N/A"])
                    
                    ct = Table(cred_data, colWidths=[1.5*inch, 2*inch, 1*inch, 1.5*inch], repeatRows=1)
                    ct.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ]))
                    elements.append(ct)

                # --- Section 4: Exfiltrated Data (Loot) ---
                elements.append(Spacer(1, 0.5*inch))
                elements.append(Paragraph("4. Exfiltrated Data (Loot)", heading1_style))
                if not loots:
                    elements.append(Paragraph("No loot items were collected.", normal_style))
                else:
                    loot_data = [["Item Name", "Loot Type", "Size", "Acquired Date"]]
                    for l in loots:
                        size = l.get_file_size_human() if hasattr(l, 'get_file_size_human') else "N/A"
                        loot_data.append([l.name, l.loot_type, size, l.created_at.strftime('%Y-%m-%d')])
                    
                    lt = Table(loot_data, colWidths=[1.8*inch, 1.4*inch, 0.8*inch, 2*inch], repeatRows=1)
                    lt.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7'))
                    ]))
                    elements.append(lt)

                # Finalize
                doc.build(elements)
                print_success(f"High-design PDF report successfully generated: {full_path}")
                return True

        except Exception as e:
            print_error(f"Error during report generation: {str(e)}")
            import traceback
            print_debug(traceback.format_exc())
            return False
