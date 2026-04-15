import boto3
from datetime import datetime, timezone, timedelta
import json

IST = timezone(timedelta(hours=5, minutes=30))


def check_account_security_contact(session):
    # [Account.1]
    print("Checking security contact information")

    account_client = session.client("account")
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]

    contacts = {
        "primary": {"exists": False, "complete": False, "details": {}},
        "alternate": {"exists": False, "complete": False, "details": {}},
    }

    try:
        primary = account_client.get_contact_information().get("ContactInformation", {})
        if primary:
            contacts["primary"]["exists"] = True
            contacts["primary"]["details"] = primary
            contacts["primary"]["complete"] = all(
                primary.get(field)
                for field in ["EmailAddress", "FullName", "PhoneNumber"]
            )
    except Exception as e:
        print(f"Error: Primary contact check failed - {e}")

    try:
        alternate = account_client.get_alternate_contact(
            AlternateContactType="SECURITY"
        ).get("AlternateContact", {})
        if alternate:
            contacts["alternate"]["exists"] = True
            contacts["alternate"]["details"] = alternate
            contacts["alternate"]["complete"] = all(
                alternate.get(field)
                for field in ["EmailAddress", "Name", "PhoneNumber"]
            )
    except account_client.exceptions.ResourceNotFoundException:
        pass
    except Exception as e:
        print(f"Warning: Alternate contact check failed - {e}")

    is_compliant = contacts["primary"]["complete"] or contacts["alternate"]["complete"]

    resources_affected = []
    if not is_compliant:
        missing_fields = {
            "primary": [
                f
                for f in ["EmailAddress", "FullName", "PhoneNumber"]
                if not contacts["primary"]["details"].get(f)
            ],
            "alternate": [
                f
                for f in ["EmailAddress", "Name", "PhoneNumber"]
                if contacts["alternate"]["exists"]
                and not contacts["alternate"]["details"].get(f)
            ],
        }

        resources_affected.append(
            {
                "account_id": account_id,
                "issue": "Missing complete security contact information",
                "missing_in_primary": missing_fields["primary"],
                "missing_in_alternate": (
                    missing_fields["alternate"]
                    if contacts["alternate"]["exists"]
                    else "No alternate contact configured"
                ),
                "current_configuration": {
                    "primary_contact": contacts["primary"]["details"],
                    "alternate_contact": (
                        contacts["alternate"]["details"]
                        if contacts["alternate"]["exists"]
                        else None
                    ),
                },
                "last_updated": datetime.now(IST).isoformat(),
            }
        )

    total_scanned = 1
    affected = len(resources_affected)

    return {
        "id": "Account.1",
        "check_name": "Security Contact Information",
        "problem_statement": "Security contact information should be provided for AWS accounts",
        "severity_score": 50,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Configure alternate contacts in AWS Account settings with security contact information",
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": affected,
        },
        "status": "passed" if affected == 0 else "failed",
        "remediation_steps": [
            "1. Sign in to the AWS Management Console and open the AWS Billing and Cost Management console",
            "2. In the navigation pane, choose Account Settings",
            "3. Scroll down to the Alternate Contacts section",
            "4. Choose Edit next to Security",
            "5. Enter the contact's full name, email address, and phone number",
            "6. Choose Update",
        ],
        "last_updated": datetime.now(IST).isoformat(),
    }
