import os
from fpdf import FPDF
from app.data.scenarios import DEMO_SCENARIOS

output_dir = "/Users/lakshman/.gemini/antigravity/scratch/offershield-ai/app/static/samples"
os.makedirs(output_dir, exist_ok=True)

class OfferPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.set_text_color(20, 30, 50)
        self.cell(0, 8, self.pdf_title, ln=True, align='C')
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(100, 110, 130)
        self.cell(0, 6, self.pdf_subtitle, ln=True, align='C')
        self.ln(4)
        self.set_draw_color(200, 210, 225)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(6)

def create_fpdf(filename, title, subtitle, content):
    pdf = OfferPDF()
    pdf.pdf_title = title
    pdf.pdf_subtitle = subtitle
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(40, 50, 70)
    
    for paragraph in content.split('\n\n'):
        if paragraph.strip():
            clean_p = paragraph.strip().replace('₹', 'Rs. ')
            pdf.multi_cell(0, 5.5, clean_p)
            pdf.ln(3)
            
    filepath = os.path.join(output_dir, filename)
    pdf.output(filepath)
    return filepath

create_fpdf(
    "scenario_1_google_intern_scam.pdf",
    "GOOGLE INDIA PRIVATE LIMITED",
    "CAMPUS APPOINTMENT & RECRUITMENT - BATCH 2026",
    DEMO_SCENARIOS[0]["text"]
)

create_fpdf(
    "scenario_2_razorpay_cheque_phish.pdf",
    "RAZORPAY SOFTWARE PRIVATE LIMITED",
    "OFFER OF EMPLOYMENT - CONFIDENTIAL",
    DEMO_SCENARIOS[1]["text"]
)

create_fpdf(
    "scenario_3_microsoft_genuine_offer.pdf",
    "MICROSOFT INDIA (R&D) PRIVATE LIMITED",
    "OFFER OF EMPLOYMENT - CAMPUS PLACEMENT BATCH 2026",
    DEMO_SCENARIOS[2]["text"]
)

print("Generated sample PDFs successfully in:", output_dir)
