"""
Labelled synthetic test dataset for OfferShield AI effectiveness evaluation.
Contains 50 diverse cases:
- 25 Synthetic Scams & Identity Theft Attacks
- 25 Genuine Verified Job Offers across IT, Startups, and Consulting
"""

BENCHMARK_CASES = [
    # ==================== MALICIOUS ATTACKS (25 Cases) ====================
    {
        "id": "SCAM_001",
        "title": "Google Campus Internship Laptop Deposit Scam",
        "sender_email": "careers@google-hr-campus.xyz",
        "claimed_company": "Google",
        "expected_label": "MALICIOUS",
        "text": """
        Congratulations! We are pleased to offer you the position of Software Engineering Intern at Google India.
        Your stipend will be ₹85,000 per month.
        Due to remote policy, Google will ship an Apple MacBook Pro M3 and testing hardware to your residence.
        To initiate customs clearance and courier insurance, you must transfer a refundable security deposit of ₹3,500
        via UPI to equipment-logistics@upi within 24 hours. This amount will be fully reimbursed in your first month stipend.
        Please reply with your Aadhaar card and PAN card photocopy immediately.
        """
    },
    {
        "id": "SCAM_002",
        "title": "TCS Off-Campus Drive Telegram KYC Harvest",
        "sender_email": "tcs.hiring.team@gmail.com",
        "claimed_company": "TCS",
        "expected_label": "MALICIOUS",
        "text": """
        Tata Consultancy Services (TCS) Direct Campus Selection.
        Dear Candidate, Based on your GitHub and LinkedIn profile, you have been shortlisted for Associate System Engineer (Package ₹7.2 LPA).
        No technical interview required due to exceptional academic credentials.
        To confirm your seat, connect with Senior HR Manager Priya Sharma on Telegram: @tcs_campus_hr_onboarding.
        You must submit high-resolution front and back copy of your Aadhaar Card, PAN Card, and cancelled cheque within 12 hours
        or your candidate ID will be cancelled and blacklisted from future drives.
        """
    },
    {
        "id": "SCAM_003",
        "title": "Infosys Lookalike Domain Advance Training Fee",
        "sender_email": "hr@infosys-careers-portal.live",
        "claimed_company": "Infosys",
        "expected_label": "MALICIOUS",
        "text": """
        Infosys Technologies Limited - Letter of Intent.
        We are thrilled to extend an offer for Systems Engineer Specialist.
        Before joining the Mysore training academy, mandatory pre-onboarding certification fees of ₹4,999 must be remitted
        for online LMS access credentials. Pay using Google Pay / PhonePe to our verified vendor account.
        Failure to deposit within 2 days will forfeit your offer. Submit your Aadhaar card copy to proceed.
        """
    },
    {
        "id": "SCAM_004",
        "title": "Razorpay Impersonation Bank Cheque Phish",
        "sender_email": "talent@hiring-razorpay.tech",
        "claimed_company": "Razorpay",
        "expected_label": "MALICIOUS",
        "text": """
        Offer of Employment - Razorpay Software Private Limited.
        Role: Product Intern. Compensation: ₹60,000 / month.
        To set up direct payroll deposit, please attach a scan of your signed blank cheque, net banking customer ID,
        and colored scan of PAN card. Urgent: respond within 4 hours to reserve your batch slot.
        """
    },
    {
        "id": "SCAM_005",
        "title": "Amazon AWS Work-From-Home Equipment Bond Scam",
        "sender_email": "recruitment@amazon-cloud-india.icu",
        "claimed_company": "Amazon",
        "expected_label": "MALICIOUS",
        "text": """
        Amazon Development Centre India.
        Offer for Cloud Support Associate. CTC: 12 LPA.
        Candidates will receive an ergonomic home workstation. A refundable equipment dispatch fee of ₹5,500 must be paid
        prior to courier dispatch. Attach copy of PAN card and Aadhaar card immediately.
        """
    },
    {
        "id": "SCAM_006",
        "title": "Wipro Fast-Track WhatsApp Selection",
        "sender_email": "wipro.careers.desk@yahoo.com",
        "claimed_company": "Wipro",
        "expected_label": "MALICIOUS",
        "text": """
        Wipro Elite National Talent Hunt.
        You have been selected for Project Engineer role. No formal interview needed.
        Join the WhatsApp onboarding room at wa.me/919876543210 to receive onboarding docs.
        Submit your Aadhaar number and bank passbook photocopy within 24 hours to generate offer letter.
        """
    },
    {
        "id": "SCAM_007",
        "title": "Microsoft India Research Fellowship Fake Bond",
        "sender_email": "careers@microsoft-fellowship.cc",
        "claimed_company": "Microsoft",
        "expected_label": "MALICIOUS",
        "text": """
        Microsoft Research India Fellowship Award.
        Stipend: ₹1,20,000 per month.
        Candidates are required to pay a registration fee of ₹2,500 for the secure research cloud sandbox.
        This amount is refundable with your 1st month salary. Send Aadhaar front and back copy within 6 hours.
        """
    },
    {
        "id": "SCAM_008",
        "title": "Swiggy Delivery Ops Management Trainee Scam",
        "sender_email": "hr-swiggy@careers-portal.buzz",
        "claimed_company": "Swiggy",
        "expected_label": "MALICIOUS",
        "text": """
        Swiggy Corporate Careers.
        Designation: Operations Lead Trainee. CTC: 8 LPA.
        Mandatory background verification fee of ₹1,800 is required via Paytm/UPI before issuing the formal joining letter.
        Submit Aadhaar card and PAN card immediately.
        """
    },
    {
        "id": "SCAM_009",
        "title": "Zomato Growth Hacker High Pressure Phish",
        "sender_email": "zomato.hiring.team@outlook.com",
        "claimed_company": "Zomato",
        "expected_label": "MALICIOUS",
        "text": """
        Zomato Media Private Limited.
        Role: Growth Marketing Specialist. Stipend: ₹45,000/month.
        We require immediate submission of your PAN card, Aadhaar card, and cancelled cheque within 3 hours.
        Failure to upload will result in immediate forfeiture of the position.
        """
    },
    {
        "id": "SCAM_010",
        "title": "Flipkart Supply Chain Coordinator Deposit Scam",
        "sender_email": "hr@flipkart-logistics-jobs.xyz",
        "claimed_company": "Flipkart",
        "expected_label": "MALICIOUS",
        "text": """
        Flipkart Internet Private Limited.
        Job Offer: Logistics Trainee.
        Refundable asset security deposit of ₹3,000 required for inventory barcode scanner and ID card printing.
        Remit to UPI ID flipkart.onboard@icici. Submit colored scan of Aadhaar card.
        """
    },
    {
        "id": "SCAM_011",
        "title": "Accenture Digital Analyst Telegram Intercept",
        "sender_email": "accenture.drive2026@gmail.com",
        "claimed_company": "Accenture",
        "expected_label": "MALICIOUS",
        "text": """
        Accenture Solutions India.
        Offer for Associate Software Engineer.
        Due to high volume, all candidate document verification is handled via Telegram @accenture_campus_docs.
        Share your Aadhaar, PAN card, and 10th/12th marksheets within 24 hours.
        """
    },
    {
        "id": "SCAM_012",
        "title": "Cognizant GenC Urgent Acceptance Threat",
        "sender_email": "genc.recruitment@cognizant-campus.live",
        "claimed_company": "Cognizant",
        "expected_label": "MALICIOUS",
        "text": """
        Cognizant Technology Solutions.
        GenC Developer Offer. Package: 4.5 LPA.
        To secure joining date, pay ₹2,000 for biometric card initialization. Reimbursed in first salary.
        Send PAN card scan immediately. Strictly reply within 12 hours or offer will be revoked.
        """
    },
    {
        "id": "SCAM_013",
        "title": "Deloitte USI Analyst Fake Document Charge",
        "sender_email": "deloitte.careers.desk@mail.com",
        "claimed_company": "Deloitte",
        "expected_label": "MALICIOUS",
        "text": """
        Deloitte Consulting India.
        Analyst Trainee. CTC: 9.5 LPA.
        Third-party background check charge of ₹3,200 must be remitted by candidate to ensure expedited police verification.
        Submit Aadhaar card and PAN card within 24 hours.
        """
    },
    {
        "id": "SCAM_014",
        "title": "EY GDS Cybersecurity Intern Deposit Extortion",
        "sender_email": "ey.gds.hiring@top-careers.top",
        "claimed_company": "EY",
        "expected_label": "MALICIOUS",
        "text": """
        Ernst & Young Global Delivery Services.
        Role: Cybersecurity Trainee.
        Hardware insurance deposit ₹4,500 required for VPN token and encrypted laptop.
        Transfer via UPI. Submit copy of PAN and passport.
        """
    },
    {
        "id": "SCAM_015",
        "title": "PwC Technology Consultant Urgency Scam",
        "sender_email": "pwc-hiring@consulting-jobs.click",
        "claimed_company": "PwC",
        "expected_label": "MALICIOUS",
        "text": """
        PricewaterhouseCoopers India.
        Associate Consultant.
        Strict 6-hour acceptance window. Send Aadhaar front and back scan and bank passbook.
        LMS certification access fee ₹2,999 required before formal letter release.
        """
    },
    {
        "id": "SCAM_016",
        "title": "KPMG India Risk Trainee KYC Harvesting",
        "sender_email": "kpmg-recruitment@yahoo.co.in",
        "claimed_company": "KPMG",
        "expected_label": "MALICIOUS",
        "text": """
        KPMG Assurance and Consulting Services.
        Risk Analyst Trainee.
        Submit your Aadhaar card and cancelled cheque within 24 hours to hr-kpmg@yahoo.co.in.
        No formal interview needed as your profile was shortlisted through national pool.
        """
    },
    {
        "id": "SCAM_017",
        "title": "Tata Motors Engineering Intern Security Fee",
        "sender_email": "hr@tata-motors-campus.live",
        "claimed_company": "Tata",
        "expected_label": "MALICIOUS",
        "text": """
        Tata Motors Limited.
        Graduate Engineer Trainee (GET).
        Mandatory safety gear and plant uniform deposit of ₹2,200 to be deposited via PhonePe.
        Refundable with 1st month stipend. Attach Aadhaar card scan.
        """
    },
    {
        "id": "SCAM_018",
        "title": "Fake Data Entry Remote Job KYC Scam",
        "sender_email": "jobs@quick-online-work.xyz",
        "claimed_company": "DataCorp India",
        "expected_label": "MALICIOUS",
        "text": """
        Home Based Typing and Data Processing Executive.
        Earn ₹45,000 per month for 2 hours daily work. No experience required.
        To generate employee ID, send full Aadhaar card front and back copy, PAN card, and bank account details.
        Deposit software installation fee of ₹999.
        """
    },
    {
        "id": "SCAM_019",
        "title": "Synthetic AI Startup Research Intern Phish",
        "sender_email": "founder@deep-ai-labs.cc",
        "claimed_company": "DeepAI Labs",
        "expected_label": "MALICIOUS",
        "text": """
        AI Research Intern at DeepAI Labs.
        Stipend: ₹70,000/month.
        Please submit your Aadhaar card copy and bank account details on our Telegram channel @deepai_hr_bot.
        Server GPU access token fee: ₹1,500 refundable. Urgent response in 12 hours.
        """
    },
    {
        "id": "SCAM_020",
        "title": "Infosys BPM Voice Process Advance Deposit",
        "sender_email": "infosys.bpm.careers@rediffmail.com",
        "claimed_company": "Infosys",
        "expected_label": "MALICIOUS",
        "text": """
        Infosys BPM Limited - Customer Support Associate.
        Selection finalized. Training fee ₹3,000 required for voice modulation toolkit.
        Pay via Google Pay. Upload Aadhaar card scan and bank passbook.
        """
    },
    {
        "id": "SCAM_021",
        "title": "Crypto Web3 Developer Telegram Identity Theft",
        "sender_email": "recruiting@solana-web3-hiring.top",
        "claimed_company": "Solana Ventures",
        "expected_label": "MALICIOUS",
        "text": """
        Junior Rust & Smart Contract Developer.
        Compensation: $2,500/month.
        Interview conducted exclusively via Telegram t.me/web3_lead_recruiter.
        KYC requirements: Submit high-res passport scan, PAN card, and selfie holding your ID within 24 hours.
        """
    },
    {
        "id": "SCAM_022",
        "title": "Campus Placement Cell Impersonation Attack",
        "sender_email": "placement-officer@university-drive.icu",
        "claimed_company": "Campus Placement Cell",
        "expected_label": "MALICIOUS",
        "text": """
        Urgent Notice from Central Placement Office:
        A leading MNC has opened 15 emergency seats. Package 14 LPA.
        Registration portal closes in 2 hours. Submit Aadhaar number and pay ₹1,200 verification cess.
        """
    },
    {
        "id": "SCAM_023",
        "title": "Uber India Operations Associate Bond Scam",
        "sender_email": "careers@uber-india-jobs.xyz",
        "claimed_company": "Uber",
        "expected_label": "MALICIOUS",
        "text": """
        Uber Technologies India.
        Operations Associate.
        Asset security deposit of ₹3,800 required for enterprise phone and SIM dispatch.
        Reimbursed in first salary. Attach PAN card and cancelled cheque.
        """
    },
    {
        "id": "SCAM_024",
        "title": "Fake Aviation Ground Staff Pre-Joining Scam",
        "sender_email": "indigo.ground.hiring@gmail.com",
        "claimed_company": "IndiGo Airlines",
        "expected_label": "MALICIOUS",
        "text": """
        Airport Ground Staff & Customer Service Executive.
        Direct appointment letter issued. Salary: ₹38,000/month.
        Aviation gate pass and medical clearance fee ₹4,200 to be paid via UPI within 24 hours.
        Submit Aadhaar card and PAN card.
        """
    },
    {
        "id": "SCAM_025",
        "title": "Goldman Sachs Analyst Lookalike Domain Trap",
        "sender_email": "talent@goldman-sachs-careers.live",
        "claimed_company": "Goldman Sachs",
        "expected_label": "MALICIOUS",
        "text": """
        Goldman Sachs Services India.
        Offer for Summer Operations Analyst.
        Background screening vendor verification fee of ₹3,500 required before contract release.
        Send copy of PAN, passport, and Aadhaar card within 6 hours.
        """
    },

    # ==================== GENUINE OFFERS (25 Cases) ====================
    {
        "id": "GENUINE_001",
        "title": "Google India Software Engineer Bona Fide Offer",
        "sender_email": "recruiting@google.com",
        "claimed_company": "Google",
        "expected_label": "GENUINE",
        "text": """
        Dear Candidate,
        On behalf of Google India Private Limited, we are pleased to extend an offer for the role of Software Engineer.
        Your base compensation will be ₹18,00,000 per annum, plus standard target bonus and equity awards.
        This offer is contingent upon successful completion of background checks through our official portal.
        Please review the attached terms and sign electronically via Workday within 14 business days.
        Google does not charge any application or onboarding fees at any point in the recruitment process.
        """
    },
    {
        "id": "GENUINE_002",
        "title": "TCS Digital Campus Selection Letter",
        "sender_email": "campus.recruitment@tcs.com",
        "claimed_company": "TCS",
        "expected_label": "GENUINE",
        "text": """
        Tata Consultancy Services Limited.
        Ref: TCSL/DT2026/OFFER
        We are pleased to offer you the position of Systems Engineer - Digital Cadre.
        Your Gross Salary will be ₹7,00,008 per annum.
        Please login to TCS NextStep portal (nextstep.tcs.com) using your registered Reference ID to view details.
        You have 7 days to accept this offer. Official verification of your educational documents will be conducted on day of reporting.
        """
    },
    {
        "id": "GENUINE_003",
        "title": "Infosys Specialist Programmer Verified Offer",
        "sender_email": "offer_administration@infosys.com",
        "claimed_company": "Infosys",
        "expected_label": "GENUINE",
        "text": """
        Infosys Limited.
        Sub: Offer of Employment - Specialist Programmer.
        Congratulations on successfully clearing the HackWithInfy coding rounds and technical interviews.
        Your total compensation will be ₹9,50,000 per annum.
        Please confirm your acceptance via our career portal within 10 days.
        All document submissions will be managed via the secure Infosys Launchpad application post acceptance.
        """
    },
    {
        "id": "GENUINE_004",
        "title": "Razorpay SDE Intern Standard Offer",
        "sender_email": "careers@razorpay.com",
        "claimed_company": "Razorpay",
        "expected_label": "GENUINE",
        "text": """
        Hi there,
        We loved interacting with you during our engineering interviews!
        Razorpay is thrilled to offer you the position of SDE Intern (Backend).
        Stipend: ₹50,000 per month. Duration: 6 months.
        Location: Bangalore (Hybrid). Equipment (MacBook) will be provisioned directly by Razorpay IT at zero cost.
        Please sign and return the letter within 7 working days.
        """
    },
    {
        "id": "GENUINE_005",
        "title": "Microsoft India SWE Full-time Offer",
        "sender_email": "msft-jobs@microsoft.com",
        "claimed_company": "Microsoft",
        "expected_label": "GENUINE",
        "text": """
        Microsoft India (R&D) Private Limited.
        Offer for Software Engineer - Azure Core.
        Total target compensation: ₹22,00,000 INR per annum.
        Please accept via the Microsoft Action Center portal within 14 calendar days.
        Official background screening is conducted by HireRight at Microsoft's expense.
        """
    },
    {
        "id": "GENUINE_006",
        "title": "Amazon SDE-1 Bangalore Placement",
        "sender_email": "university-hiring@amazon.com",
        "claimed_company": "Amazon",
        "expected_label": "GENUINE",
        "text": """
        Amazon Development Center India.
        Formal Offer of Employment: Software Development Engineer I.
        Base Pay: ₹15,50,000 INR with relocation assistance.
        To accept, review the enclosed agreement and electronically sign on the Amazon candidate portal within 10 business days.
        """
    },
    {
        "id": "GENUINE_007",
        "title": "Wipro Project Engineer Standard Letter",
        "sender_email": "manager.campus@wipro.com",
        "claimed_company": "Wipro",
        "expected_label": "GENUINE",
        "text": """
        Wipro Limited, Doddakannelli, Sarjapur Road, Bangalore.
        Appointment Letter for Project Engineer.
        Annual compensation: INR 4,00,000.
        Acceptance valid for 7 days via Wipro Elite Candidate Dashboard.
        No fees of any kind are collected by Wipro.
        """
    },
    {
        "id": "GENUINE_008",
        "title": "Swiggy Product Management Intern",
        "sender_email": "talent.acquisition@swiggy.in",
        "claimed_company": "Swiggy",
        "expected_label": "GENUINE",
        "text": """
        Bundl Technologies Private Limited (Swiggy).
        Role: Associate Product Manager Intern.
        Stipend: ₹40,000 per month.
        Please review the job description, intellectual property assignment, and confirm by signing via DocuSign within 5 business days.
        """
    },
    {
        "id": "GENUINE_009",
        "title": "Zomato Backend Engineer Campus Hire",
        "sender_email": "engineering-hiring@zomato.com",
        "claimed_company": "Zomato",
        "expected_label": "GENUINE",
        "text": """
        Zomato Limited.
        Designation: Software Development Engineer (Backend).
        Location: Gurgaon, Haryana.
        Gross CTC: ₹14,00,000 per annum.
        Kindly acknowledge receipt and return the signed duplicate copy within 7 days.
        """
    },
    {
        "id": "GENUINE_010",
        "title": "Flipkart UI/UX Designer Offer",
        "sender_email": "campus-talent@flipkart.com",
        "claimed_company": "Flipkart",
        "expected_label": "GENUINE",
        "text": """
        Flipkart Internet Private Limited.
        Position: Associate Product Designer.
        Fixed Pay: ₹12,00,000 per annum with standard benefits.
        Please review the comprehensive compensation breakdown on Workday and submit confirmation by next Friday.
        """
    },
    {
        "id": "GENUINE_011",
        "title": "Accenture Advanced App Engineering Analyst",
        "sender_email": "india.campus@accenture.com",
        "claimed_company": "Accenture",
        "expected_label": "GENUINE",
        "text": """
        Accenture Solutions Private Limited.
        Role: Advanced Application Engineering Analyst.
        Annual CTC: ₹6,50,000.
        Log in to the Accenture Onboarding Portal to upload your graduation provisional certificate. Offer valid for 10 days.
        """
    },
    {
        "id": "GENUINE_012",
        "title": "Cognizant GenC Elevate Verified Offer",
        "sender_email": "campusqueries@cognizant.com",
        "claimed_company": "Cognizant",
        "expected_label": "GENUINE",
        "text": """
        Cognizant Technology Solutions India Pvt Ltd.
        Designation: Programmer Analyst Trainee.
        CTC: ₹4,25,000 per annum.
        Please submit acceptance through the Cognizant 1C portal within 7 calendar days.
        """
    },
    {
        "id": "GENUINE_013",
        "title": "Deloitte USI Technology Risk Consultant",
        "sender_email": "usi.recruiting@deloitte.com",
        "claimed_company": "Deloitte",
        "expected_label": "GENUINE",
        "text": """
        Deloitte Consulting India Private Limited.
        Position: Business Technology Analyst.
        Compensation: ₹8,00,000 per annum.
        Verification of educational transcripts will occur during your induction week. Welcome to Deloitte.
        """
    },
    {
        "id": "GENUINE_014",
        "title": "EY GDS Tax Technology Associate",
        "sender_email": "eygds.campus@ey.com",
        "claimed_company": "EY",
        "expected_label": "GENUINE",
        "text": """
        EY Global Delivery Services India.
        Offer for Associate - Tax Technology.
        CTC: ₹5,50,000.
        Confirm acceptance via SuccessFactors candidate profile within 10 days.
        """
    },
    {
        "id": "GENUINE_015",
        "title": "PwC AC Bangalore Data Engineering Intern",
        "sender_email": "campus.relations@pwc.com",
        "claimed_company": "PwC",
        "expected_label": "GENUINE",
        "text": """
        PricewaterhouseCoopers Acceleration Centre India.
        Data Engineering Intern. Stipend: ₹35,000/month.
        Please sign and upload the non-disclosure agreement to the PwC Taleo portal within 7 business days.
        """
    },
    {
        "id": "GENUINE_016",
        "title": "KPMG India Management Consulting Trainee",
        "sender_email": "indiahr@kpmg.com",
        "claimed_company": "KPMG",
        "expected_label": "GENUINE",
        "text": """
        KPMG India Private Limited.
        Role: Analyst - Advisory.
        Gross Salary: ₹7,50,000 per annum.
        Background screening will be handled by First Advantage on behalf of KPMG. Please accept within 10 days.
        """
    },
    {
        "id": "GENUINE_017",
        "title": "Tata Elxsi Autonomous Systems Engineer",
        "sender_email": "careers@tataelxsi.com",
        "claimed_company": "Tata",
        "expected_label": "GENUINE",
        "text": """
        Tata Elxsi Limited.
        Role: Engineer - Connected Vehicle Technologies.
        CTC: ₹6,00,000 per annum.
        Reporting location: Hoodi, Bangalore. Acceptance window is 14 days from dispatch.
        """
    },
    {
        "id": "GENUINE_018",
        "title": "Postman Software Engineering Intern",
        "sender_email": "jobs@postman.com",
        "claimed_company": "Postman",
        "expected_label": "GENUINE",
        "text": """
        Postman India.
        Role: Software Engineering Intern - Core Protocols.
        Stipend: ₹65,000 per month.
        Laptop and home office budget provisioned directly by Postman. Please sign via Greenhouse within 7 days.
        """
    },
    {
        "id": "GENUINE_019",
        "title": "Zerodha Quantitative Research Intern",
        "sender_email": "hiring@zerodha.com",
        "claimed_company": "Zerodha",
        "expected_label": "GENUINE",
        "text": """
        Zerodha Broking Limited.
        Position: Quant Researcher Intern.
        Stipend: ₹60,000/month.
        Location: Bangalore (In-office). Please confirm your availability and expected graduation date within 7 days.
        """
    },
    {
        "id": "GENUINE_020",
        "title": "Cred Product Specialist Campus Graduate",
        "sender_email": "talent@cred.club",
        "claimed_company": "Cred",
        "expected_label": "GENUINE",
        "text": """
        Dreamplug Technologies Private Limited (CRED).
        Role: Product Operations Associate.
        Compensation: ₹10,00,000 per annum.
        Review the offer terms on Lever and sign electronically within 5 business days.
        """
    },
    {
        "id": "GENUINE_021",
        "title": "Urban Company Full Stack Intern",
        "sender_email": "tech-recruiting@urbancompany.com",
        "claimed_company": "Urban Company",
        "expected_label": "GENUINE",
        "text": """
        Urban Company Engineering.
        Role: Full Stack Intern.
        Stipend: ₹45,000/month.
        Please acknowledge acceptance via DocuSign link provided.
        """
    },
    {
        "id": "GENUINE_022",
        "title": "InMobi Associate Data Scientist",
        "sender_email": "campus@inmobi.com",
        "claimed_company": "InMobi",
        "expected_label": "GENUINE",
        "text": """
        InMobi Technologies Private Limited.
        Offer for Associate Data Scientist.
        Total compensation: ₹13,50,000 INR.
        Standard 10-day decision period. Background verification commences upon joining.
        """
    },
    {
        "id": "GENUINE_023",
        "title": "PhonePe Software Engineer (FinTech)",
        "sender_email": "careers@phonepe.com",
        "claimed_company": "PhonePe",
        "expected_label": "GENUINE",
        "text": """
        PhonePe Private Limited.
        Role: Software Engineer - Merchant Payments.
        Annual Package: ₹16,00,000.
        All document submissions happen on day 1 of joining. Confirm by signing via Workday within 10 days.
        """
    },
    {
        "id": "GENUINE_024",
        "title": "Groww Backend Engineer Campus Batch",
        "sender_email": "talent@groww.in",
        "claimed_company": "Groww",
        "expected_label": "GENUINE",
        "text": """
        Nextbillion Technology Private Limited (Groww).
        Role: Software Engineer (Backend).
        CTC: ₹13,00,000 INR per annum.
        Please review the attached terms and sign electronically within 7 days.
        """
    },
    {
        "id": "GENUINE_025",
        "title": "Freshworks Product Consulting Associate",
        "sender_email": "careers@freshworks.com",
        "claimed_company": "Freshworks",
        "expected_label": "GENUINE",
        "text": """
        Freshworks Technologies India.
        Position: Associate Product Consultant.
        Compensation: ₹8,50,000 per annum.
        Electronic acceptance required through our SmartRecruiters portal within 10 business days.
        """
    }
]
