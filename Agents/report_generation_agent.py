import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image, KeepTogether
from reportlab.pdfgen import canvas
import pandas as pd
import tempfile
from PIL import Image as PILImage, ImageEnhance

class ReportGenerationAgent:
    """
    Agent that generates PDF reports from risk assessment and mitigation data.
    """
    
    def __init__(self):
        """Initialize the Report Generation Agent."""
        # Find the logo path
        self.logo_path = None
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        possible_logo_paths = [
            os.path.join(project_root, 'Patch-path-logo.png'),
            os.path.join(project_root, 'Patch-path-logo.PNG'),
            'Patch-path-logo.png',
            'Patch-path-logo.PNG'
        ]
        
        for path in possible_logo_paths:
            if os.path.exists(path):
                self.logo_path = path
                print(f"[INFO] Logo found at: {path}")
                break
        
        if not self.logo_path:
            print("[WARNING] Logo file not found. Watermark will not be added.")
    
    def _create_transparent_logo(self, opacity=0.15):
        """Create a semi-transparent version of the logo using PIL."""
        if not self.logo_path or not os.path.exists(self.logo_path):
            return None
        
        try:
            img = PILImage.open(self.logo_path)
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            alpha = img.split()[3]
            alpha = alpha.point(lambda p: int(p * opacity))
            
            transparent_img = PILImage.new('RGBA', img.size)
            transparent_img.paste(img, (0, 0))
            transparent_img.putalpha(alpha)
            
            temp_logo = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            transparent_img.save(temp_logo.name, 'PNG')
            temp_logo.close()
            
            return temp_logo.name
        except Exception as e:
            print(f"[WARNING] Could not create transparent logo: {e}")
            return None
    
    def _add_logo_to_canvas(self, canvas_obj, doc):
        """Add logo as a translucent background watermark on each page."""
        if not self.logo_path or not os.path.exists(self.logo_path):
            return
        
        try:
            transparent_logo_path = self._create_transparent_logo(opacity=0.15)
            if not transparent_logo_path:
                return
            
            page_width = doc.pagesize[0]
            page_height = doc.pagesize[1]
            
            logo_width = page_width * 0.6
            try:
                img = PILImage.open(self.logo_path)
                img_width, img_height = img.size
                aspect_ratio = img_height / img_width
                logo_height = logo_width * aspect_ratio
            except:
                logo_height = logo_width * 0.3
            
            logo_x = (page_width - logo_width) / 2
            logo_y = (page_height - logo_height) / 2
            
            canvas_obj.drawImage(
                transparent_logo_path,
                logo_x,
                logo_y,
                width=logo_width,
                height=logo_height,
                preserveAspectRatio=True,
                mask='auto'
            )
        except Exception as e:
            print(f"[WARNING] Could not add logo watermark to PDF: {e}")
    
    def _parse_risk_metrics_table(self, table_text):
        """Parse the risk metrics table text into structured data.
        Handles markdown table format and skips header/separator rows.
        """
        if not table_text:
            return None
        
        lines = [line.strip() for line in table_text.split('\n') if line.strip()]
        if not lines:
            return None
        
        data = []
        
        # Check if it's a markdown table (starts with |)
        is_markdown = any(line.startswith('|') for line in lines)
        
        if is_markdown:
            # Parse markdown table format
            # Skip header row (first line) and separator row (second line with ---)
            data_lines = []
            for i, line in enumerate(lines):
                if line.startswith('|'):
                    # Skip header row (index 0)
                    if i == 0:
                        continue
                    # Skip separator row (contains ---)
                    if '---' in line:
                        continue
                    # This is a data row
                    data_lines.append(line)
            
            # Parse data rows by splitting on | (not spaces!)
            for line in data_lines:
                # Split by | and clean up
                parts = [p.strip() for p in line.split('|')]
                # Remove empty strings from beginning/end (from leading/trailing |)
                parts = [p for p in parts if p]
                
                if len(parts) >= 7:
                    tech_name = parts[0]  # "Google Cloud" stays together!
                    risk_score = parts[1]  # "5.22/10"
                    critical = parts[2]   # "0"
                    high = parts[3]       # "0"
                    medium = parts[4]     # "1"
                    low = parts[5]        # "0"
                    total = parts[6]      # "1"
                    data.append([tech_name, risk_score, critical, high, medium, low, total])
        else:
            # Fallback: Parse plain text format (space-separated)
            # Skip header row by checking for header keywords
            header_keywords = ['tech', 'stack', 'overall', 'risk', 'score', 'critical', 'high', 'medium', 'low', 'total', 'cves']
            
            for line in lines:
                line_lower = line.lower()
                # Skip if line contains multiple header keywords (it's the header row)
                header_word_count = sum(1 for keyword in header_keywords if keyword in line_lower)
                if header_word_count >= 4:
                    continue
                
                # Parse data row
                parts = line.split()
                if len(parts) >= 7:
                    tech_name = parts[0]
                    risk_score = parts[1] if len(parts) > 1 else 'N/A'
                    critical = parts[2] if len(parts) > 2 else '0'
                    high = parts[3] if len(parts) > 3 else '0'
                    medium = parts[4] if len(parts) > 4 else '0'
                    low = parts[5] if len(parts) > 5 else '0'
                    total = parts[6] if len(parts) > 6 else '0'
                    data.append([tech_name, risk_score, critical, high, medium, low, total])
        
        return data if data else None
    
    def generate_report(self, risk_assessment_data, mitigation_data, tech_stack=None, cves_data=None):
        """
        Generate a professional PDF report from risk assessment and/or mitigation data.
        """
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        pdf_path = temp_file.name
        temp_file.close()
        
        # Professional margins
        doc = SimpleDocTemplate(
            pdf_path, 
            pagesize=letter,
            rightMargin=72, 
            leftMargin=72,
            topMargin=100,  # Extra space for header
            bottomMargin=72
        )
        
        elements = []
        
        # Define professional styles
        styles = getSampleStyleSheet()
        
        # Title style
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=12,
            spaceBefore=0,
            alignment=1,  # Center
            fontName='Helvetica-Bold'
        )
        
        # Subtitle style
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=24,
            alignment=1,  # Center
            fontName='Helvetica'
        )
        
        # Section heading style
        section_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=12,
            spaceBefore=24,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderPadding=0
        )
        
        # Subsection style
        subsection_style = ParagraphStyle(
            'SubsectionHeading',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#3b82f6'),
            spaceAfter=8,
            spaceBefore=16,
            fontName='Helvetica-Bold'
        )
        
        # Body text style
        body_style = ParagraphStyle(
            'BodyText',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=10,
            leading=14,
            fontName='Helvetica'
        )
        
        # Bullet style
        bullet_style = ParagraphStyle(
            'BulletText',
            parent=body_style,
            leftIndent=20,
            bulletIndent=10,
            spaceAfter=6
        )
        
        # ========== COVER PAGE / HEADER ==========
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph("Patch Path Security Report", title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", subtitle_style))
        elements.append(Spacer(1, 0.4*inch))
        
        # ========== EXECUTIVE SUMMARY ==========
        elements.append(Paragraph("Executive Summary", section_style))
        
        summary_text = "This security assessment report provides a comprehensive analysis of vulnerabilities "
        summary_text += "identified in the technology stack, including risk assessment and recommended mitigation strategies."
        
        if tech_stack:
            summary_text += f" The assessment covers {len(tech_stack) if isinstance(tech_stack, list) else 1} technology/technologies."
        
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # ========== DETECTED TECHNOLOGIES ==========
        if tech_stack:
            elements.append(Paragraph("1. Detected Technologies", section_style))
            tech_list = tech_stack if isinstance(tech_stack, list) else [tech_stack]
            tech_text = ", ".join(tech_list)
            elements.append(Paragraph(tech_text, body_style))
            elements.append(Spacer(1, 0.3*inch))
        
        # ========== RISK ASSESSMENT SECTION ==========
        if risk_assessment_data:
            section_num = "2" if tech_stack else "1"
            elements.append(Paragraph(f"{section_num}. Risk Assessment", section_style))
            
            # Summary subsection
            if risk_assessment_data.get('summary'):
                elements.append(Paragraph("2.1 Overview", subsection_style))
                summary = risk_assessment_data['summary']
                # Clean up summary text
                summary = summary.replace('\n', ' ').strip()
                elements.append(Paragraph(summary, body_style))
                elements.append(Spacer(1, 0.15*inch))
            
            # Risk Metrics Table - Convert to proper table format
            if risk_assessment_data.get('clean_table'):
                elements.append(Paragraph("2.2 Risk Metrics by Technology", subsection_style))
                
                # Parse and create proper table
                table_data = self._parse_risk_metrics_table(risk_assessment_data.get('clean_table'))
                
                if table_data:
                    # Create professional table
                    header = [['Technology', 'Risk Score', 'Critical', 'High', 'Medium', 'Low', 'Total CVEs']]
                    table_data_formatted = header + table_data
                    
                    risk_table = Table(table_data_formatted, colWidths=[1.5*inch, 1.2*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.9*inch])
                    risk_table.setStyle(TableStyle([
                        # Header row
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('TOPPADDING', (0, 0), (-1, 0), 12),
                        # Data rows
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ]))
                    elements.append(risk_table)
                else:
                    # Fallback to text if parsing fails
                    elements.append(Paragraph(risk_assessment_data['clean_table'], body_style))
                
                elements.append(Spacer(1, 0.2*inch))
            
            # Top Risk CVEs Table
            if risk_assessment_data.get('ranked_cves') is not None:
                ranked_cves = risk_assessment_data['ranked_cves']
                if isinstance(ranked_cves, pd.DataFrame) and len(ranked_cves) > 0:
                    elements.append(Paragraph("2.3 Top Risk CVEs", subsection_style))
                    elements.append(Spacer(1, 0.1*inch))
                    
                    top_cves = ranked_cves.head(20)  # Show top 20
                    table_data = []
                    
                    for idx, row in top_cves.iterrows():
                        cve_id = str(row.get('cve_id', 'N/A'))
                        risk_score = f"{row.get('overall_risk_score', 0):.2f}"
                        risk_level = str(row.get('risk_level', 'N/A'))
                        title = str(row.get('title', row.get('description', 'N/A')))
                        # Truncate very long titles but keep more characters
                        if len(title) > 100:
                            title = title[:97] + "..."
                        table_data.append([cve_id, risk_score, risk_level, title])
                    
                    # Create professional CVE table
                    header = [['CVE ID', 'Risk Score', 'Risk Level', 'Description']]
                    cve_table_data = header + table_data
                    
                    cve_table = Table(cve_table_data, colWidths=[1.3*inch, 1*inch, 1*inch, 3.2*inch])
                    
                    # Color code risk levels
                    def get_risk_color(level):
                        level_lower = str(level).lower()
                        if 'critical' in level_lower:
                            return colors.HexColor('#dc2626')
                        elif 'high' in level_lower:
                            return colors.HexColor('#ea580c')
                        elif 'medium' in level_lower:
                            return colors.HexColor('#f59e0b')
                        else:
                            return colors.HexColor('#10b981')
                    
                    # Build table style
                    table_style = [
                        # Header
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('TOPPADDING', (0, 0), (-1, 0), 12),
                        # Data rows
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 1), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                    ]
                    
                    # Add risk level color coding
                    for i, row in enumerate(table_data, start=1):
                        risk_level = row[2]
                        color = get_risk_color(risk_level)
                        table_style.append(('TEXTCOLOR', (2, i), (2, i), color))
                        table_style.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))
                    
                    cve_table.setStyle(TableStyle(table_style))
                    elements.append(cve_table)
                    elements.append(Spacer(1, 0.3*inch))
        
        # ========== MITIGATION SECTION ==========
        if mitigation_data:
            section_num = "3" if (tech_stack and risk_assessment_data) else ("2" if risk_assessment_data or tech_stack else "1")
            elements.append(PageBreak())
            elements.append(Paragraph(f"{section_num}. Mitigation Roadmap", section_style))
            
            # Remove overview section - go directly to mitigation steps
            
            # Mitigation steps - format with CVE IDs and numbered points
            if mitigation_data.get('steps'):
                steps = mitigation_data['steps']
                cve_ids = mitigation_data.get('cve_ids', [])
                
                # Create CVE heading style
                cve_heading_style = ParagraphStyle(
                    'CVEHeading',
                    parent=subsection_style,
                    fontSize=12,
                    textColor=colors.HexColor('#1e40af'),
                    spaceAfter=8,
                    spaceBefore=12,
                    fontName='Helvetica-Bold'
                )
                
                # Handle dict format (multiple CVEs organized by CVE-ID)
                if isinstance(steps, dict) and cve_ids and len(cve_ids) > 1:
                    for cve_id in cve_ids:
                        # CVE ID on its own line (bold, as heading)
                        elements.append(Paragraph(f"<b>{cve_id}</b>", cve_heading_style))
                        
                        if cve_id in steps and len(steps[cve_id]) > 0:
                            # Each step on a new line with proper numbering
                            for idx, step in enumerate(steps[cve_id], start=1):
                                action = step.get('action', 'N/A')
                                priority = step.get('priority', 'Medium')
                                
                                # Format: "1. Priority: Action text" (no brackets)
                                step_text = f"{idx}. {priority}: {action}"
                                step_para = Paragraph(step_text, body_style)
                                elements.append(step_para)
                                elements.append(Spacer(1, 0.08*inch))
                        else:
                            # No steps for this CVE
                            elements.append(Paragraph("No specific steps found for this CVE.", body_style))
                            elements.append(Spacer(1, 0.08*inch))
                        
                        elements.append(Spacer(1, 0.15*inch))  # Space between CVEs
                
                # Handle list format (single CVE or unified steps)
                elif isinstance(steps, list):
                    # If we have CVE IDs, show them
                    if cve_ids and len(cve_ids) == 1:
                        elements.append(Paragraph(f"<b>{cve_ids[0]}</b>", cve_heading_style))
                    
                    # Each step on a new line
                    for idx, step in enumerate(steps, start=1):
                        action = step.get('action', 'N/A') if isinstance(step, dict) else str(step)
                        priority = step.get('priority', 'Medium') if isinstance(step, dict) else 'Medium'
                        
                        # Format: "1. Priority: Action text" (no brackets)
                        step_text = f"{idx}. {priority}: {action}"
                        step_para = Paragraph(step_text, body_style)
                        elements.append(step_para)
                        elements.append(Spacer(1, 0.08*inch))
        
        # ========== FOOTER / APPENDIX ==========
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("─" * 60, subtitle_style))
        elements.append(Spacer(1, 0.1*inch))
        footer_text = "This report was generated by Patch Path Security Assessment System. "
        footer_text += "For questions or additional information, please contact your security team."
        elements.append(Paragraph(footer_text, subtitle_style))
        
        # Build PDF with logo watermark
        def on_first_page(canvas_obj, doc):
            self._add_logo_to_canvas(canvas_obj, doc)
        
        def on_later_pages(canvas_obj, doc):
            self._add_logo_to_canvas(canvas_obj, doc)
        
        doc.build(elements, onFirstPage=on_first_page, onLaterPages=on_later_pages)
        
        return pdf_path
    
    def generate_report_from_context(self, conversation_context):
        """Generate PDF report from Planner's conversation context."""
        risk_assessment = conversation_context.get('risk_assessment')
        mitigation = conversation_context.get('mitigation')
        tech_stack = conversation_context.get('tech_stack')
        cves = conversation_context.get('cves')
        
        return self.generate_report(
            risk_assessment_data=risk_assessment,
            mitigation_data=mitigation,
            tech_stack=tech_stack,
            cves_data=cves
        )
