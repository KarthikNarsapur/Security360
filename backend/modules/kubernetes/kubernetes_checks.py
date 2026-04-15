import boto3
import json
import os
from Model.model import ListEKSClusterModel


def list_eks_clusters(getEks: ListEKSClusterModel):

    try:
        # step 1: fetch input values
        REGIONS = getEks.regions
        BOTO3_REGION = os.getenv("BOTO3_REGION")

        # step 2: validate inputs
        eks_roles_info = getEks.accounts or []
        username = getEks.username or ""

        if not eks_roles_info:
            return {
                "status": "error",
                "error_message": "No EKS roles found",
            }

        if not username:
            return {
                "status": "error",
                "error_message": "Username not provided",
            }

        notifications = {"success": [], "error": []}

        # step 3: loop through all provided account roles
        eks_details = []
        for role in eks_roles_info:
            try:
                account_id = role.account_id or ""
                role_arn = role.role_arn or ""
                account_name = role.account_name or ""

                # step 4: assume IAM role
                sts_client = boto3.client("sts")
                try:
                    assumed_role = sts_client.assume_role(
                        RoleArn=role_arn, RoleSessionName="SecurityAuditSession"
                    )
                except Exception as e:
                    print(f"Error assuming role for {account_id}: {e}")
                    notifications["error"].append(f"Role assume failed: {account_id}")
                    continue

                # step 5: extract temporary security credentials
                credentials = assumed_role["Credentials"]
                access_key = credentials["AccessKeyId"]
                secret_key = credentials["SecretAccessKey"]
                session_token = credentials["SessionToken"]

                failed_regions = []

                # step 6: loop through AWS regions
                for region in REGIONS:
                    try:
                        session = boto3.Session(
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key,
                            aws_session_token=session_token,
                            region_name=region,
                        )
                        if not session:
                            print(f"Failed to create session for account {account_id}")
                            failed_regions.append(region)
                            continue

                        # step 7: list EKS clusters in this region
                        eks = session.client("eks")
                        response = eks.list_clusters()
                        clusters = response.get("clusters", [])

                        for cluster_name in clusters:
                            cluster_info = eks.describe_cluster(name=cluster_name)[
                                "cluster"
                            ]
                            eks_details.append(
                                {
                                    "cluster_name": cluster_info.get("name"),
                                    "status": cluster_info.get("status"),
                                    "version": cluster_info.get("version"),
                                    "endpoint": cluster_info.get("endpoint"),
                                    "created_at": str(cluster_info.get("createdAt")),
                                    "account_id": account_id,
                                    "account_name": account_name,
                                    "region": region,
                                }
                            )

                    except Exception as e:
                        print(
                            f"Error scanning region {region} for account {account_id}: {e}"
                        )
                        failed_regions.append(region)
                        continue
                if len(failed_regions) > 0:
                    print(f"failed scan for {account_id} in regions: {failed_regions}")

                if len(failed_regions) != len(REGIONS):
                    notifications["success"].append(
                        f"Listed EKS clusters for {account_id}"
                    )

            except Exception as e:
                print(
                    f"Unexpected error processing role {role_arn} ({account_id}): {e}"
                )
                notifications["error"].append(f"Unexpected error in {account_id}")
                continue

        if len(notifications["error"]) == 0 and len(eks_details) == 0:
            return {
                "status": "error",
                "error_message": "No EKS clusters found",
                "notifications": notifications,
            }

        return {
            "status": "ok",
            "eks_clusters": eks_details,
            "notifications": notifications,
        }

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {"status": "error", "message": str(e)}
