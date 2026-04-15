import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_aws_config_enabled(session):
    # [Config.1]
    print("Checking AWS Config configuration")

    config = session.client("config")
    sts = session.client("sts")
    iam = session.client("iam")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        config_status = config.describe_configuration_recorder_status()
        recorders = config_status.get("ConfigurationRecordersStatus", [])

        if not recorders:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "issue": "AWS Config not enabled (no configuration recorders found)",
                    "region": region,
                    "details": "No configuration recorders exist in this region",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
        else:
            for recorder in recorders:
                recorder_name = recorder.get("name", "Unknown")
                recording = recorder.get("recording", False)
                last_status = recorder.get("lastStatus", "Unknown")
                last_error_code = recorder.get("lastErrorCode", "")
                last_start_time = recorder.get("lastStartTime")
                last_stop_time = recorder.get("lastStopTime")
                role_arn = recorder.get("arn", "")

                service_linked_role_info = {}
                if role_arn:
                    try:
                        role_name = role_arn.split("/")[-1]
                        role = iam.get_role(RoleName=role_name).get("Role", {})
                        service_linked_role_info = {
                            "role_name": role.get("RoleName"),
                            "role_arn": role.get("Arn"),
                            "create_date": str(role.get("CreateDate")),
                            "path": role.get("Path"),
                            "description": role.get("Description", ""),
                            "service_linked": role_name.startswith(
                                "AWSServiceRoleForConfig"
                            ),
                        }
                    except Exception as e:
                        service_linked_role_info = {
                            "error": f"Failed to get role info: {str(e)}"
                        }
                else:
                    service_linked_role_info = {
                        "error": "No roleARN associated with recorder"
                    }

                if not recording:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "issue": f"AWS Config recorder '{recorder_name}' is not recording resources",
                            "region": region,
                            "recorder_name": recorder_name,
                            "last_status": last_status,
                            "last_error_code": last_error_code,
                            "last_start_time": (
                                str(last_start_time) if last_start_time else None
                            ),
                            "last_stop_time": (
                                str(last_stop_time) if last_stop_time else None
                            ),
                            "role_info": service_linked_role_info,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

                if "AWSServiceRoleForConfig" not in role_arn:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "issue": f"AWS Config recorder '{recorder_name}' is not using service-linked role",
                            "region": region,
                            "recorder_name": recorder_name,
                            "role_info": service_linked_role_info,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        total_scanned = 1
        affected = len(resources_affected)
        return {
            "id": "Config.1",
            "check_name": "AWS Config Enabled with Service-Linked Role",
            "problem_statement": "AWS Config should be enabled and use the service-linked role for resource recording",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable AWS Config with service-linked role AWSServiceRoleForConfig",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to AWS Config service",
                "2. Set up configuration recorder",
                "3. Select 'Record all resources'",
                "4. Choose 'Use a service-linked role' option",
                "5. Enable continuous recording",
                "6. Save configuration",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking AWS Config: {e}")
        return None
