import os, json, datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.enums import TA_CENTER

NAVY  = colors.HexColor('#1B3A5C')
TEAL  = colors.HexColor('#0E6655')
RED   = colors.HexColor('#A32D2D')
GREEN = colors.HexColor('#27500A')
AMBER = colors.HexColor('#B7770D')
LTBLUE= colors.HexColor('#E6F1FB')
LTGRN = colors.HexColor('#EAF3DE')
LTRED = colors.HexColor('#FCEBEB')
WHITE = colors.white
GRAY  = colors.HexColor('#F5F5F5')

def generate_report(state, output_dir='/tmp/poc-reports'):
    try:
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(output_dir, f'poc_report_{ts}.pdf')

        doc = SimpleDocTemplate(
            filename, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
            title='DevSecOps AI POC Report',
            author='Infosys Limited'
        )

        styles = getSampleStyleSheet()
        h1 = ParagraphStyle('H1', parent=styles['Normal'], fontSize=20, textColor=NAVY, spaceAfter=6, fontName='Helvetica-Bold')
        h2 = ParagraphStyle('H2', parent=styles['Normal'], fontSize=14, textColor=TEAL, spaceBefore=12, spaceAfter=4, fontName='Helvetica-Bold')
        body = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, spaceAfter=4, leading=14)
        small = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8, textColor=colors.gray)
        log_style = ParagraphStyle('Log', parent=styles['Normal'], fontSize=7.5, fontName='Courier', spaceAfter=1, leading=11)

        story = []

        # ── Cover ─────────────────────────────────────────────────────────
        story.append(Spacer(1, 1*cm))
        header_data = [['INFOSYS LIMITED  |  MICROSOFT / NUANCE PROGRAMME']]
        ht = Table(header_data, colWidths=[17*cm])
        ht.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), NAVY),
            ('TEXTCOLOR', (0,0), (-1,-1), WHITE),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(ht)
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph('DevSecOps AI POC', ParagraphStyle('Cover', parent=styles['Normal'], fontSize=32, textColor=NAVY, fontName='Helvetica-Bold', alignment=TA_CENTER)))
        story.append(Paragraph('Automated Vulnerability Scan & AI Remediation Report', ParagraphStyle('Sub', parent=styles['Normal'], fontSize=14, textColor=TEAL, alignment=TA_CENTER)))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(width='100%', thickness=2, color=TEAL))
        story.append(Spacer(1, 0.3*cm))

        initial = state.get('initial_findings', [])
        rescan  = state.get('rescan_findings', [])
        fixed   = len(initial) - len(rescan)
        pct     = round(fixed / len(initial) * 100) if initial else 0

        def sev(findings):
            s = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
            for f in findings:
                sv = f.get('extra', {}).get('severity', 'INFO').upper()
                s[sv] = s.get(sv, 0) + 1
            return s

        b_sev = sev(initial)
        a_sev = sev(rescan)

        # KPI table
        kpi_data = [
            ['Metric', 'Before (Initial)', 'After (Rescan)', 'Change'],
            ['Total Vulnerabilities', str(len(initial)), str(len(rescan)), f'-{fixed} ({pct}% reduction)'],
            ['Critical (ERROR)', str(b_sev.get('ERROR',0)), str(a_sev.get('ERROR',0)), f'-{b_sev.get("ERROR",0)-a_sev.get("ERROR",0)}'],
            ['Warning', str(b_sev.get('WARNING',0)), str(a_sev.get('WARNING',0)), f'-{b_sev.get("WARNING",0)-a_sev.get("WARNING",0)}'],
        ]
        kt = Table(kpi_data, colWidths=[5*cm, 3.5*cm, 3.5*cm, 5*cm])
        kt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('BACKGROUND', (0,1), (-1,1), LTRED),
            ('BACKGROUND', (0,2), (-1,-1), GRAY),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TEXTCOLOR', (3,1), (3,1), GREEN),
            ('FONTNAME', (3,1), (3,1), 'Helvetica-Bold'),
        ]))
        story.append(kt)
        story.append(Spacer(1, 0.3*cm))

        meta = [
            ['Report Generated', datetime.datetime.now().strftime('%d %B %Y %H:%M:%S')],
            ['Target Application', 'OWASP WebGoat (GitHub: harikrishnadevsecops-arch/WebGoat)'],
            ['SAST Scanner', 'Semgrep OSS (p/java + p/owasp-top-ten)'],
            ['AI Remediation', 'GitHub Models API (gpt-4o-mini)'],
            ['CI/CD Platform', 'GitHub Actions'],
            ['Dashboard', 'Azure Container Apps'],
        ]
        mt = Table(meta, colWidths=[5*cm, 12*cm])
        mt.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (0,-1), NAVY),
            ('GRID', (0,0), (-1,-1), 0.3, colors.lightgrey),
            ('BACKGROUND', (0,0), (-1,-1), GRAY),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(mt)
        story.append(PageBreak())

        # ── Initial findings ───────────────────────────────────────────────
        story.append(Paragraph('1. Initial Scan Findings', h1))
        story.append(HRFlowable(width='100%', thickness=1, color=TEAL))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(f'Semgrep SAST identified <b>{len(initial)} vulnerabilities</b> in OWASP WebGoat source code.', body))
        story.append(Spacer(1, 0.2*cm))

        if initial:
            vd = [['#', 'File', 'Rule', 'Severity', 'Line', 'Message']]
            for i, f in enumerate(initial[:50], 1):
                sv = f.get('extra', {}).get('severity', 'INFO').upper()
                vd.append([
                    str(i),
                    os.path.basename(f.get('path', '')),
                    f.get('check_id', '').split('.')[-1][:30],
                    sv,
                    str(f.get('start', {}).get('line', '')),
                    f.get('extra', {}).get('message', '')[:60],
                ])
            vt = Table(vd, colWidths=[0.8*cm, 3.5*cm, 3.5*cm, 1.8*cm, 1*cm, 6.4*cm], repeatRows=1)
            vt.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), NAVY),
                ('TEXTCOLOR', (0,0), (-1,0), WHITE),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 7.5),
                ('GRID', (0,0), (-1,-1), 0.3, colors.lightgrey),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, GRAY]),
            ]))
            story.append(vt)
        story.append(PageBreak())

        # ── AI Remediation ─────────────────────────────────────────────────
        story.append(Paragraph('2. AI Remediation Details', h1))
        story.append(HRFlowable(width='100%', thickness=1, color=TEAL))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph('The AI agent processed vulnerability findings and applied automated code fixes.', body))
        story.append(Spacer(1, 0.2*cm))

        log_entries = state.get('log', [])
        fixed_files = [e['msg'].replace('Fixed: ', '') for e in log_entries if e['msg'].startswith('Fixed: ')]

        ai_data = [['Status', 'File', 'Details']]
        for f in fixed_files:
            ai_data.append(['FIXED', f, 'AI successfully rewrote vulnerable code'])

        if len(ai_data) > 1:
            at = Table(ai_data, colWidths=[2*cm, 5*cm, 10*cm])
            at.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), NAVY),
                ('TEXTCOLOR', (0,0), (-1,0), WHITE),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.3, colors.lightgrey),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('BACKGROUND', (0,1), (0,-1), LTGRN),
                ('TEXTCOLOR', (0,1), (0,-1), GREEN),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('ROWBACKGROUNDS', (1,1), (-1,-1), [WHITE, GRAY]),
            ]))
            story.append(at)
        story.append(PageBreak())

        # ── Rescan results ─────────────────────────────────────────────────
        story.append(Paragraph('3. Rescan Results — After AI Remediation', h1))
        story.append(HRFlowable(width='100%', thickness=1, color=TEAL))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(f'After AI remediation and PR merge, rescan found <b>{len(rescan)} remaining vulnerabilities</b> — a <b>{pct}% reduction</b>.', body))
        story.append(Spacer(1, 0.2*cm))

        comp = [
            ['Severity', 'Before', 'After', 'Fixed'],
            ['CRITICAL (ERROR)', str(b_sev.get('ERROR',0)), str(a_sev.get('ERROR',0)), str(b_sev.get('ERROR',0)-a_sev.get('ERROR',0))],
            ['WARNING', str(b_sev.get('WARNING',0)), str(a_sev.get('WARNING',0)), str(b_sev.get('WARNING',0)-a_sev.get('WARNING',0))],
            ['TOTAL', str(len(initial)), str(len(rescan)), str(fixed) + f' ({pct}% reduction)'],
        ]
        ct = Table(comp, colWidths=[4*cm, 3*cm, 3*cm, 7*cm])
        ct.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BACKGROUND', (0,-1), (-1,-1), LTGRN),
            ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,-1), (-1,-1), GREEN),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('ROWBACKGROUNDS', (0,1), (-1,-2), [WHITE, GRAY]),
        ]))
        story.append(ct)
        story.append(PageBreak())

        # ── Activity log ───────────────────────────────────────────────────
        story.append(Paragraph('4. Audit Trail — Activity Log', h1))
        story.append(HRFlowable(width='100%', thickness=1, color=TEAL))
        story.append(Spacer(1, 0.2*cm))
        for entry in log_entries:
            ts_str = entry.get('ts', '')
            msg = entry.get('msg', '')
            level = entry.get('level', 'info')
            color = '#27500A' if level == 'success' else '#A32D2D' if level == 'error' else '#B7770D' if level == 'warning' else '#000000'
            story.append(Paragraph(f'<font color="grey">{ts_str}</font>  <font color="{color}">{msg}</font>', log_style))

        # Footer
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width='100%', thickness=0.5, color=colors.lightgrey))
        story.append(Paragraph(
            f'Infosys Limited  |  DevSecOps AI POC  |  Generated: {datetime.datetime.now().strftime("%d %B %Y %H:%M")}',
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7, textColor=colors.grey, alignment=TA_CENTER)
        ))

        doc.build(story)
        return filename

    except Exception as e:
        print(f'PDF generation error: {e}')
        import traceback
        traceback.print_exc()
        return None
