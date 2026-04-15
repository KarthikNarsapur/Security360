import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_account_has_alternate_contact(session):
    # [Account.1]
    print("Checking Account alternate contact configuration")

    account = session.client("account")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        contact_types = ["BILLING", "OPERATIONS", "SECURITY"]
        missing = []

        for contact_type in contact_types:
            try:
                account.get_alternate_contact(AlternateContactType=contact_type)
            except account.exceptions.ResourceNotFoundException:
                missing.append(contact_type)

        if missing:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "Account",
                    "resource_id_type": "AWSAccount",
                    "issue": f"Missing alternate contact types: {', '.join(missing)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = len(contact_types)
        affected = len(resources_affected)
        return {
            "id": "Account.1",
            "check_name": "Alternate contact information configured",
            "problem_statement": "AWS account should have alternate contact details configured for Billing, Operations, and Security.",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Add missing alternate contacts under Account settings in AWS Management Console.",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Open the AWS Management Console.",
                "2. Go to 'Account settings'.",
                "3. Under 'Alternate contacts', add entries for Billing, Operations, and Security.",
                "4. Save the configuration.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Account alternate contact: {e}")
        return None


def check_account_has_organization(session):
    # [Account.2]
    print("Checking if account is part of AWS Organization")

    org = session.client("organizations")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            org.describe_organization()
        except org.exceptions.AWSOrganizationsNotInUseException:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "Account",
                    "resource_id_type": "AWSAccount",
                    "issue": "Account is not part of any AWS Organization",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)
        return {
            "id": "Account.2",
            "check_name": "Account part of AWS Organization",
            "problem_statement": "Account should be managed under AWS Organizations for centralized control and governance.",
            "severity_score": 20,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Add account to an AWS Organization or verify organization membership.",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Log in to the AWS Management Console.",
                "2. Navigate to 'AWS Organizations'.",
                "3. Create or join an organization.",
                "4. Ensure the account is listed under the organization root or the right OU.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking AWS Organization membership: {e}")
        return None
