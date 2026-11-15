import re
from typing import Dict, Any, List

# Known top global enterprises frequently impersonated in recruitment fraud
KNOWN_ENTERPRISES = {
    # US Tech & Global Giants
    "google": ["google.com", "google.co.in", "alphabet.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.jobs"],
    "meta": ["meta.com", "facebook.com"],
    "netflix": ["netflix.com"],
    "salesforce": ["salesforce.com"],
    "adobe": ["adobe.com"],
    "oracle": ["oracle.com"],
    "cisco": ["cisco.com"],
    "intel": ["intel.com"],
    "nvidia": ["nvidia.com"],
    "spotify": ["spotify.com"],
    "uber": ["uber.com"],
    "airbnb": ["airbnb.com"],
    "tesla": ["tesla.com"],
    
    # Global Logistics, Aviation & Shipping
    "dp world": ["dpworld.com"],
    "dubai port world": ["dpworld.com"],
    "maersk": ["maersk.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "emirates": ["emirates.com", "emiratesgroup.com"],
    "etihad": ["etihad.com", "etihadairways.com"],
    "qatar airways": ["qatarairways.com"],
    "singapore airlines": ["singaporeair.com"],
    "british airways": ["ba.com", "britishairways.com"],
    "lufthansa": ["lufthansa.com"],
    "delta": ["delta.com"],
    "united airlines": ["united.com"],
    
    # Energy, Oil & Heavy Industry
    "aramco": ["aramco.com"],
    "saudi aramco": ["aramco.com"],
    "adnoc": ["adnoc.ae"],
    "shell": ["shell.com"],
    "bp": ["bp.com"],
    "exxonmobil": ["exxonmobil.com"],
    "chevron": ["chevron.com"],
    "totalenergies": ["totalenergies.com"],
    "petrofac": ["petrofac.com"],
    
    # Global Financial Services & Consulting (Big 4 & Strategy)
    "deloitte": ["deloitte.com"],
    "ey": ["ey.com"],
    "pwc": ["pwc.com"],
    "kpmg": ["kpmg.com"],
    "mckinsey": ["mckinsey.com"],
    "bcg": ["bcg.com"],
    "bain": ["bain.com"],
    "goldman sachs": ["goldmansachs.com", "gs.com"],
    "jpmorgan": ["jpmorgan.com", "jpmorganchase.com"],
    "morgan stanley": ["morganstanley.com"],
    "citigroup": ["citi.com", "citigroup.com"],
    "hsbc": ["hsbc.com"],
    "barclays": ["barclays.com"],
    "razorpay": ["razorpay.com"],
    
    # Global Healthcare & Pharma
    "pfizer": ["pfizer.com"],
    "johnson & johnson": ["jnj.com"],
    "astrazeneca": ["astrazeneca.com"],
    "moderna": ["modernatx.com"],
    "novartis": ["novartis.com"],
    "unitedhealth": ["uhg.com", "unitedhealthgroup.com"],
    
    # Indian IT & Major Conglomerates
    "tcs": ["tcs.com", "tataconsultancy.com"],
    "infosys": ["infosys.com"],
    "wipro": ["wipro.com"],
    "hcl": ["hcltech.com", "hcl.com"],
    "tech mahindra": ["techmahindra.com"],
    "accenture": ["accenture.com"],
    "cognizant": ["cognizant.com"],
    "swiggy": ["swiggy.in", "swiggy.com"],
    "zomato": ["zomato.com"],
    "flipkart": ["flipkart.com"],
    "tata": ["tata.com", "tatasteel.com", "tatamotors.com"],
    "tata steel": ["tatasteel.com"],
    "jsw": ["jsw.in", "jswsteel.in"],
    "jsw steel": ["jsw.in", "jswsteel.in"],
    "reliance": ["ril.com"],
    "adani": ["adani.com"],
    "l&t": ["larsentoubro.com"],
    "vedanta": ["vedantalimited.com"],
    "mahindra": ["mahindra.com"]
}

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "rediffmail.com", "aol.com"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".live", ".cc", ".icu", ".click", ".buzz", ".work"
}

def analyze_email_domain(email_or_domain: str, claimed_company: str = "") -> Dict[str, Any]:
    """
    Analyzes recruiter sender email or domain for impersonation, typosquatting,
    and fraudulent patterns.
    """
    if not email_or_domain:
        return {
            "status": "UNKNOWN",
            "risk_score": 20,
            "findings": ["No recruiter sender domain could be extracted from document/input."],
            "is_lookalike": False,
            "is_freemail": False
        }
    
    # Extract domain
    domain = email_or_domain.lower().strip()
    if "@" in domain:
        domain = domain.split("@")[-1]
    
    findings: List[str] = []
    risk_score = 0
    is_freemail = domain in FREE_MAIL_PROVIDERS
    is_lookalike = False
    lookalike_target = ""

    # Check 1: Free webmail provider used for official enterprise hiring
    if is_freemail:
        risk_score += 45
        findings.append(f"Official corporate offer delivered from public free webmail provider ({domain}). Legitimate corporations use dedicated corporate domains.")
    
    # Check 2: Suspicious high-abuse TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            risk_score += 35
            findings.append(f"Domain uses high-risk budget/abuse TLD ({tld}) instead of standard enterprise .com or .in domain.")
            break
            
    # Check 3: Domain typosquatting / lookalike detection
    clean_domain = domain.split(":")[0]
    domain_body = clean_domain.split(".")[0]
    domain_norm = re.sub(r'[^a-z0-9]', '', domain_body.lower())
    
    for company, legit_domains in KNOWN_ENTERPRISES.items():
        comp_norm = re.sub(r'[^a-z0-9]', '', company.lower())
        # Check if normalized company is substring of domain body (e.g. 'dpworld' in 'dpworldofficial')
        if comp_norm in domain_norm or company in domain:
            if clean_domain not in legit_domains and not any(clean_domain.endswith("." + ld) for ld in legit_domains):
                is_lookalike = True
                lookalike_target = company.upper()
                risk_score += 65
                findings.append(
                    f"CRITICAL LOOKALIKE: Domain '{domain}' mimics {lookalike_target}, but official authorized domain is {', '.join(legit_domains)}."
                )
                break
        
        # Case B: Claimed company matches known enterprise, but domain doesn't match
        if claimed_company and company in claimed_company.lower():
            if clean_domain not in legit_domains and not is_lookalike:
                is_lookalike = True
                lookalike_target = company.upper()
                risk_score += 55
                findings.append(
                    f"Domain mismatch: Document claims to be from {claimed_company.title()}, but email domain is '{domain}'."
                )
                break

    # Check 4: Deceptive corporate keywords appended to domain (e.g. <brand>official, <brand>-careers, <brand>-jobs)
    deceptive_suffix_match = re.search(r'(official|careers?|jobs?|hiring|portal|recruitment|verify|hr-dept|group-hr)\b', domain_body)
    if deceptive_suffix_match and not is_lookalike:
        is_lookalike = True
        risk_score += 55
        findings.append(
            f"DECEPTIVE DOMAIN SYNTAX: Domain '{domain}' appends fraudulent trust suffix ('{deceptive_suffix_match.group(0)}') to simulate official enterprise legitimacy."
        )
                
    # Check 5: Hyphenated scam syntax (e.g. "hr-careers-india.com")
    if domain.count("-") >= 2 and not is_lookalike:
        risk_score += 20
        findings.append(f"Excessive hyphenation in recruitment domain '{domain}' is typical of disposable scam infrastructure.")
        
    risk_score = min(100, risk_score)
    
    status = "SAFE"
    if risk_score >= 50:
        status = "MALICIOUS_IMPERSONATION"
    elif risk_score >= 20:
        status = "SUSPICIOUS"
        
    return {
        "domain": domain,
        "status": status,
        "risk_score": risk_score,
        "is_freemail": is_freemail,
        "is_lookalike": is_lookalike,
        "lookalike_target": lookalike_target,
        "findings": findings
    }
