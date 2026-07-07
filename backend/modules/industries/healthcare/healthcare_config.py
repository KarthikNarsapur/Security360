"""
Healthcare Industry — Framework Configuration
Maps frameworks by region (India / Global) with scan metadata.
"""

HEALTHCARE_INDIA_FRAMEWORKS = {
    "dpdp": {
        "label": "DPDP Act 2023",
        "description": "Digital Personal Data Protection Act",
        "implemented": True,
        "scan_key": "dpdp",
    },
    "dpdp_rules_2025": {
        "label": "DPDP Rules 2025",
        "description": "DPDP subordinate rules",
        "implemented": True,
        "scan_key": "dpdp_rules_2025",
    },
    "ndhm": {
        "label": "NDHM/ABDM",
        "description": "National Digital Health Mission / Ayushman Bharat Digital Mission",
        "implemented": False,
        "scan_key": "ndhm",
    },
    "spdi": {
        "label": "IT Act + SPDI Rules",
        "description": "Information Technology Act 2000 + Sensitive Personal Data Rules",
        "implemented": False,
        "scan_key": "spdi",
    },
    "certin": {
        "label": "CERT-In",
        "description": "Indian Computer Emergency Response Team Directions 2022",
        "implemented": False,
        "scan_key": "certin",
    },
    "iso27001": {
        "label": "ISO 27001",
        "description": "Information Security Management System",
        "implemented": True,
        "scan_key": "iso27001",
    },
    "iso27701": {
        "label": "ISO 27701",
        "description": "Privacy Information Management System",
        "implemented": False,
        "scan_key": "iso27701",
    },
    "nist": {
        "label": "NIST CSF",
        "description": "NIST Cybersecurity Framework",
        "implemented": True,
        "scan_key": "nist",
    },
    "cis": {
        "label": "CIS Benchmarks",
        "description": "Center for Internet Security AWS Benchmarks",
        "implemented": True,
        "scan_key": "cis",
    },
    "soc2": {
        "label": "SOC 2",
        "description": "Service Organization Control 2 Trust Service Criteria",
        "implemented": False,
        "scan_key": "soc2",
    },
}


HEALTHCARE_GLOBAL_FRAMEWORKS = {
    "hipaa": {
        "label": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act",
        "implemented": False,
        "scan_key": "hipaa",
    },
    "hitech": {
        "label": "HITECH Act",
        "description": "Health Information Technology for Economic and Clinical Health",
        "implemented": False,
        "scan_key": "hitech",
    },
    "gdpr": {
        "label": "GDPR",
        "description": "General Data Protection Regulation (EU)",
        "implemented": False,
        "scan_key": "gdpr",
    },
    "nis2": {
        "label": "NIS2 Directive",
        "description": "EU Network and Information Security Directive",
        "implemented": False,
        "scan_key": "nis2",
    },
    "pipeda": {
        "label": "PIPEDA",
        "description": "Personal Information Protection and Electronic Documents Act (Canada)",
        "implemented": False,
        "scan_key": "pipeda",
    },
    "privacy_act_1988": {
        "label": "Privacy Act 1988",
        "description": "Australian Privacy Principles",
        "implemented": False,
        "scan_key": "privacy_act_1988",
    },
    "iso27001": {
        "label": "ISO 27001",
        "description": "Information Security Management System",
        "implemented": True,
        "scan_key": "iso27001",
    },
    "iso27799": {
        "label": "ISO 27799",
        "description": "Health Informatics — Information Security Management in Health",
        "implemented": False,
        "scan_key": "iso27799",
    },
    "iso27701": {
        "label": "ISO 27701",
        "description": "Privacy Information Management System",
        "implemented": False,
        "scan_key": "iso27701",
    },
    "soc2": {
        "label": "SOC 2",
        "description": "Service Organization Control 2 Trust Service Criteria",
        "implemented": False,
        "scan_key": "soc2",
    },
    "nist": {
        "label": "NIST CSF",
        "description": "NIST Cybersecurity Framework",
        "implemented": True,
        "scan_key": "nist",
    },
    "hitrust": {
        "label": "HITRUST CSF",
        "description": "Health Information Trust Alliance Common Security Framework",
        "implemented": False,
        "scan_key": "hitrust",
    },
    "cis": {
        "label": "CIS Benchmarks",
        "description": "Center for Internet Security AWS Benchmarks",
        "implemented": True,
        "scan_key": "cis",
    },
}


def get_india_frameworks():
    """Return India healthcare framework config."""
    return HEALTHCARE_INDIA_FRAMEWORKS


def get_global_frameworks():
    """Return Global healthcare framework config."""
    return HEALTHCARE_GLOBAL_FRAMEWORKS


def get_implemented_frameworks(region="india"):
    """Return only implemented frameworks for a region."""
    source = HEALTHCARE_INDIA_FRAMEWORKS if region == "india" else HEALTHCARE_GLOBAL_FRAMEWORKS
    return {k: v for k, v in source.items() if v["implemented"]}


def get_all_scan_keys(region="india"):
    """Return scan keys for implemented frameworks."""
    implemented = get_implemented_frameworks(region)
    return [v["scan_key"] for v in implemented.values()]
