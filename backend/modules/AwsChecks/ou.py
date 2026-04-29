def get_all_organizational_units(session):

    client = session.client("organizations")

    # Get the root ID
    root_id = client.list_roots()["Roots"][0]["Id"]

    def list_ous(parent_id):
        ous = []
        response = client.list_organizational_units_for_parent(ParentId=parent_id)
        for ou in response["OrganizationalUnits"]:
            ou_id = ou["Id"]
            ou_info = client.describe_organizational_unit(OrganizationalUnitId=ou_id)[
                "OrganizationalUnit"
            ]
            accounts = client.list_accounts_for_parent(ParentId=ou_id)["Accounts"]
            ou_data = {
                "Name": ou_info["Name"],
                "Id": ou_info["Id"],
                "Arn": ou_info["Arn"],
                "Accounts": [
                    {
                        "Name": acc["Name"],
                        "Id": acc["Id"],
                        "Email": acc["Email"],
                        "Status": acc["Status"],
                    }
                    for acc in accounts
                ],
            }
            ous.append(ou_data)
            ous.extend(list_ous(ou_id))
        return ous

    return {"organizational_units": list_ous(root_id)}


def check_scps_applied(session):
    print("check_scps_applied")
    resources = []

    try:
        org = session.client("organizations")
        root_id = org.list_roots()["Roots"][0]["Id"]
        policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])

        # Filter out the default FullAWSAccess SCP
        custom_scps = [p for p in policies if p.get("Name") != "FullAWSAccess"]

        if not custom_scps:
            resources.append({
                "resource_name": "Service Control Policies",
                "total_scps": len(policies),
                "custom_scps": 0,
                "issue": "No custom SCPs are defined. Only the default FullAWSAccess policy exists.",
            })
    except Exception as e:
        if "AWSOrganizationsNotInUseException" in str(e):
            resources.append({
                "resource_name": "AWS Organizations",
                "issue": "AWS Organizations is not enabled for this account.",
            })
        elif "AccessDeniedException" in str(e):
            pass  # Not the management account — skip silently
        else:
            print(f"Error checking SCPs: {e}")

    return {
        "check_name": "Service Control Policies Applied",
        "service": "Organizations",
        "problem_statement": "No custom Service Control Policies (SCPs) are applied to restrict account permissions.",
        "severity_score": 50,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Define SCPs to restrict unused regions, deny dangerous services, and enforce security guardrails across the organization.",
        "additional_info": {"total_scanned": 1, "affected": len(resources)},
    }


def check_region_restriction(session):
    print("check_region_restriction")
    resources = []

    try:
        org = session.client("organizations")
        policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])

        region_restricted = False
        for policy in policies:
            if policy.get("Name") == "FullAWSAccess":
                continue
            try:
                content = org.describe_policy(PolicyId=policy["Id"])["Policy"]["Content"]
                import json
                doc = json.loads(content)
                for stmt in doc.get("Statement", []):
                    condition = stmt.get("Condition", {})
                    if "aws:RequestedRegion" in str(condition):
                        region_restricted = True
                        break
            except Exception:
                continue
            if region_restricted:
                break

        if not region_restricted:
            resources.append({
                "resource_name": "Region Restriction SCP",
                "issue": "No SCP restricts AWS usage to approved regions.",
            })
    except Exception as e:
        if "AccessDeniedException" in str(e) or "AWSOrganizationsNotInUseException" in str(e):
            pass
        else:
            print(f"Error checking region restriction: {e}")

    return {
        "check_name": "Region Restriction via SCP",
        "service": "Organizations",
        "problem_statement": "No SCP restricts AWS resource creation to approved regions.",
        "severity_score": 45,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Create an SCP with a Deny statement using aws:RequestedRegion condition to limit usage to approved regions.",
        "additional_info": {"total_scanned": 1, "affected": len(resources)},
    }


def check_service_restriction(session):
    print("check_service_restriction")
    resources = []

    try:
        org = session.client("organizations")
        policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])

        service_restricted = False
        for policy in policies:
            if policy.get("Name") == "FullAWSAccess":
                continue
            try:
                content = org.describe_policy(PolicyId=policy["Id"])["Policy"]["Content"]
                import json
                doc = json.loads(content)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Deny" and stmt.get("Action"):
                        service_restricted = True
                        break
            except Exception:
                continue
            if service_restricted:
                break

        if not service_restricted:
            resources.append({
                "resource_name": "Service Restriction SCP",
                "issue": "No SCP restricts usage of unapproved AWS services.",
            })
    except Exception as e:
        if "AccessDeniedException" in str(e) or "AWSOrganizationsNotInUseException" in str(e):
            pass
        else:
            print(f"Error checking service restriction: {e}")

    return {
        "check_name": "Service Restriction via SCP",
        "service": "Organizations",
        "problem_statement": "No SCP restricts which AWS services can be used in the organization.",
        "severity_score": 40,
        "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Create SCPs to deny access to unused or risky AWS services across the organization.",
        "additional_info": {"total_scanned": 1, "affected": len(resources)},
    }
