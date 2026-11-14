"""
Pre-configured realistic live demo scenarios for the judges.
Includes 2 synthetic attacks + 1 genuine bona fide offer.
"""

DEMO_SCENARIOS = [
    {
        "id": "scenario_google_scam",
        "name": "Scenario 1: High-Risk Advance-Fee Scam (Google Impersonation)",
        "badge": "Synthetic Attack",
        "badge_color": "red",
        "description": "Scammer impersonates Google University Recruiting, demanding ₹3,500 laptop insurance deposit and immediate Aadhaar/PAN scans.",
        "sender_email": "careers@google-hr-campus.xyz",
        "claimed_company": "Google",
        "text": """GOOGLE INDIA PRIVATE LIMITED
CAMPUS APPOINTMENT & INTERNSHIP LETTER
Reference: GOOG-IN/2026/SDE-INTERN

Dear Candidate,

We are delighted to offer you an internship position as Software Engineer Intern with Google India.
Your monthly stipend will be ₹85,000 INR along with standard corporate perks.

REMOTE HARDWARE DISPATCH & ONBOARDING PROTOCOL:
Due to our hybrid workplace policy, Google IT Operations will dispatch an Apple MacBook Pro M3, security yubi-keys, and 4K external display directly to your residential address.

To initiate priority courier insurance and customs clearing clearance, you are required to submit a refundable equipment security deposit of ₹3,500 via UPI to google-dispatch@icici within 24 hours of receiving this letter. This amount is 100% refundable and will be reimbursed with your first month stipend.

MANDATORY IDENTITY DOCUMENTS:
You must immediately reply to this email with clear, high-resolution front and back copies of your Aadhaar Card, PAN Card, and cancelled bank cheque. Failure to upload documents and complete the equipment deposit within 24 hours will result in automatic forfeiture of this offer.

Warm Regards,
Recruitment Team | Google India
careers@google-hr-campus.xyz
"""
    },
    {
        "id": "scenario_razorpay_phish",
        "name": "Scenario 2: Subtle Identity & Cheque Phishing (Razorpay Impersonation)",
        "badge": "Subtle Attack",
        "badge_color": "amber",
        "description": "Sophisticated lookalike domain targeting banking credentials and KYC documents under guise of automated direct-deposit payroll setup.",
        "sender_email": "talent@hiring-razorpay.tech",
        "claimed_company": "Razorpay",
        "text": """RAZORPAY SOFTWARE PRIVATE LIMITED
OFFER OF EMPLOYMENT
Role: Associate Product Analyst (Campus 2026 Batch)
Location: Bangalore, Karnataka

Dear Candidate,

Following your assessment and profile screening, we are excited to offer you the position of Associate Product Analyst at Razorpay.
Your annual Cost to Company (CTC) will be ₹14,50,000 INR.

PRE-JOINING PAYROLL DIRECT-DEPOSIT SETUP:
In accordance with Razorpay's instant payroll automated system, your salary account must be pre-authorized prior to contract countersignature.
Please upload the following confidential verification artifacts to our talent desk within 4 hours:
1. Front and back colored scan of your PAN Card and Aadhaar Card.
2. Scanned copy of a signed blank cheque (or net banking customer ID screenshot) for direct-debit clearing verification.

Kindly maintain absolute secrecy regarding this offer. Failure to submit within 4 hours will lead to cancellation.

Sincerely,
People Operations
Razorpay Software Private Limited
talent@hiring-razorpay.tech
"""
    },
    {
        "id": "scenario_microsoft_genuine",
        "name": "Scenario 3: Genuine Verified Placement Offer (Microsoft India)",
        "badge": "Genuine Case",
        "badge_color": "emerald",
        "description": "Bona fide enterprise offer letter with standard corporate terms, official enterprise domain, 14-day acceptance window, and zero fees.",
        "sender_email": "university-recruiting@microsoft.com",
        "claimed_company": "Microsoft",
        "text": """MICROSOFT INDIA (R&D) PRIVATE LIMITED
OFFER OF EMPLOYMENT
Campus Placement Batch 2026

Dear Candidate,

On behalf of Microsoft India (R&D) Private Limited, we are pleased to offer you employment for the position of Software Engineer - Azure Cloud Infrastructure.

COMPENSATION & BENEFITS:
- Base Annual Salary: ₹16,00,000 INR
- Performance Bonus Target: Up to 20%
- Stock Award (RSUs): $35,000 USD vested over 4 years
- Relocation & Home Office Support: Covered in full by Microsoft

ACCEPTANCE TIMELINE:
You have fourteen (14) calendar days from the date of this letter to review and accept the offer. Please log in to your candidate account at careers.microsoft.com to sign electronically.

BACKGROUND SCREENING & VERIFICATION:
Microsoft partners with HireRight to conduct standard educational transcript and reference verifications. You will receive an official portal link from HireRight on your scheduled start date. 

NOTE ON ETHICAL RECRUITMENT:
Microsoft does not collect any registration fee, security deposit, or equipment charges at any stage of hiring.

We look forward to welcoming you to Microsoft!

Warm regards,
University Relations & Talent Acquisition
Microsoft India (R&D) Pvt. Ltd.
university-recruiting@microsoft.com
"""
    }
]
