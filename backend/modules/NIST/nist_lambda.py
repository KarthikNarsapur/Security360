import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_lambda_public_access(session):
    # [Lambda.1]
    print("Checking Lambda functions for public access")

    lambda_client = session.client("lambda")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")
        all_functions = []
        for page in paginator.paginate():
            all_functions.extend(page.get("Functions", []))

        for fn in all_functions:
            fn_name = fn["FunctionName"]
            try:
                policy = lambda_client.get_policy(FunctionName=fn_name)
                if '"AWS":"*"' in policy.get("Policy", ""):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": fn_name,
                            "resource_id_type": "LambdaFunctionName",
                            "issue": "Lambda function policy allows public access",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except lambda_client.exceptions.ResourceNotFoundException:
                # no resource policy
                continue
            except Exception as inner_e:
                print(f"Error checking Lambda {fn_name} policy: {inner_e}")

        total_scanned = len(all_functions)
        affected = len(resources_affected)
        return {
            "id": "Lambda.1",
            "check_name": "Lambda public access restriction",
            "problem_statement": "Lambda functions should not allow public ('*') access in their resource-based policies.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Restrict Lambda function policies to specific principals or AWS services.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open Lambda console.",
                "2. Select the function.",
                "3. Go to 'Permissions' tab.",
                "4. Remove any statements granting access to '*' principals.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Lambda public access: {e}")
        return None


def check_lambda_runtime_update(session):
    # [Lambda.2]
    print("Checking Lambda function runtime versions (EOL)")

    lambda_client = session.client("lambda")
    sts = session.client("sts")
    resources_affected = []

    # Reference runtimes that are actively supported (as of late 2024/2025)
    supported_runtimes = [
        "python3.10",
        "python3.11",
        "python3.12",
        "nodejs18.x",
        "nodejs20.x",
        "java11",
        "java17",
        "dotnet6",
        "dotnet8",
        "ruby3.2",
        "go1.x",
    ]

    try:
        account_id = sts.get_caller_identity()["Account"]
        paginator = lambda_client.get_paginator("list_functions")

        all_functions = []
        for page in paginator.paginate():
            all_functions.extend(page.get("Functions", []))

        for fn in all_functions:
            runtime = fn.get("Runtime", "")
            if runtime and runtime not in supported_runtimes:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": fn["FunctionName"],
                        "resource_id_type": "LambdaFunctionName",
                        "issue": f"Lambda function uses deprecated runtime '{runtime}'",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(all_functions)
        affected = len(resources_affected)
        return {
            "id": "Lambda.2",
            "check_name": "Lambda runtime up-to-date",
            "problem_statement": "Lambda functions should use supported runtimes to ensure security patches and compatibility.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Update Lambda functions to supported runtimes.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Review each function’s runtime version.",
                "2. Upgrade deprecated runtimes via console or CLI.",
                "3. Test compatibility after update.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Lambda runtime versions: {e}")
        return None
