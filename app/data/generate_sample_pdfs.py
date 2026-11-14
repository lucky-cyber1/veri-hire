import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.data.scenarios import DEMO_SCENARIOS

output_dir = "/Users/lakshman/.gemini/antigravity/scratch/offershield-ai/app/static/samples"
os.makedirs(output_dir, exist_ok=True)

styles = getSampleStyleSheet()

header_style = ParagraphStyle(
    "HeaderStyle",
    parent=styles["Heading1"],
    fontSize=18,
    leading=22,
    textColor=colors.HexColor("#1e293b"),
    alignment=1 # Center
)

sub_style = ParagraphStyle(
    "SubStyle",
    parent=styles["Normal"],
    fontSize=10,
    leading=14,
    textColor=colors.HexColor("#64748b"),
    alignment=1
)

body_style = ParagraphStyle(
    "BodyStyle",
    parent=styles["Normal"],
    fontSize=10.5,
    leading=15,
    textColor=colors.HexColor("#334155")
)

def create_sample_pdf(filename, title, subtitle, paragraphs, is_suspicious_producer=False):
    filepath = os.path.join(output_dir, filename)
    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54)
    story = []
    
    # Header
    story.append(Paragraph(title, header_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(subtitle, sub_style))
    story.append(Spacer(1, 16))
    
    # Divider line table
    divider = Table([[""]], colWidths=[500], rowHeights=[2])
    divider.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#cbd5e1")),
    ]))
    story.append(divider)
    story.append(Spacer(1, 14))
    
    for p in paragraphs:
        if p.strip():
            story.append(Paragraph(p.strip().replace("\n", "<br/>"), body_style))
            story.append(Spacer(1, 10))
            
    doc.build(story)
    return filepath

# Scenario 1: Google Scam (with Canva-like producer metadata)
create_sample_pdf(
    "scenario_1_google_intern_scam.pdf",
    "GOOGLE INDIA PRIVATE LIMITED",
    "CAMPUS RECRUITMENT & UNIVERSITY RELATIONS • BATCH 2026",
    DEMO_SCENARIOS[0]["text"].split("\n\n")
)

# Scenario 2: Razorpay Phish
create_sample_pdf(
    "scenario_2_razorpay_cheque_phish.pdf",
    "RAZORPAY SOFTWARE PRIVATE LIMITED",
    "OFFER OF EMPLOYMENT • STRICTLY CONFIDENTIAL",
    DEMO_SCENARIOS[1]["text"].split("\n\n")
)

# Scenario 3: Genuine Microsoft Offer
create_sample_pdf(
    "scenario_3_microsoft_genuine_offer.pdf",
    "MICROSOFT INDIA (R&D) PRIVATE LIMITED",
    "OFFER OF EMPLOYMENT • CAMPUS PLACEMENT BATCH 2026",
    DEMO_SCENARIOS[2]["text"].split("\n\n")
)

print("Generated sample PDFs in:", output_dir)
