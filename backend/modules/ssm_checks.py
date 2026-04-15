def non_compliant_patch_instances(session, scan_meta_data_global_services):
    print("non_compliant_patch_instances")
    ssm = session.client("ssm")
    response = ssm.list_compliance_summaries()
    # response = ssm.list_compliance_items(
        # Filter to retrieve only patch compliance information
        # Filters=[{"Key": "ComplianceType", "Values": ["Patch"], "Type": "EQUAL"}],
        # ResourceTypes=["ManagedInstance"],
    # )
    # response = ssm.list_compliance_items(
    #     Filters=[
    #         # {"Key": "ComplianceType", "Values": ["Patch"], "Type": "EQUAL"},
    #         {"Key": "Status", "Values": ["NON_COMPLIANT"], "Type": "EQUAL"},
    #     ],
    # )
    # for item in response["ComplianceItems"]:
    #     if item.get("Status") == "COMPLIANT":
    #         print("complience: ", item)
    #     elif item.get("Status") == "NON_COMPLIANT":
    #         print("non complience: ", item)
    # print("response: ", response)
    return response
    # for page in paginator.paginate(
    #     # Filters=[
    #     #     {"Key": "ComplianceType", "Values": ["Patch"], "Type": "EQUAL"},
    #     #     {"Key": "Status", "Values": ["NON_COMPLIANT"], "Type": "EQUAL"},
    #     # ],
    #     # ResourceTypes=["ManagedInstance"],
    # ):
    #     for item in page["ComplianceItems"]:
    #         print(f"  Resource ID: {item['ResourceId']}")
    #         print(f"  Compliance Type: {item['ComplianceType']}")
    #         print(f"  Title: {item['Title']}")
    #         print(f"  Status: {item['Status']}")
    #         print(f"  Severity: {item['Severity']}")
    #         print("-" * 30)

    # response_iterator = paginator.paginate(
    #     Filters=[
    #         {
    #             "Key": "ComplianceType",
    #             "Values": ["Patch"],
    #             "Type": "EQUAL"
    #         },
    #         {
    #             "Key": "Status",
    #             "Values": ["NON_COMPLIANT"],
    #             "Type": "EQUAL"
    #         }
    #     ],
    #     ResourceTypes=["ManagedInstance"]  # Correct way to specify resource type
    # )

    # # paginator = ssm.get_paginator("list_compliance_items")
    # # print("paginator: ", paginator)

    # non_compliant = []

    # for page in response_iterator(
    #     ResourceType="ManagedInstance",
    #     ComplianceType="Patch",
    #     Filters=[
    #         {
    #             "Key": "Status",
    #             "Values": ["NON_COMPLIANT"],
    #             "Type": "EQUAL"
    #         }
    #     ]
    # ):
    #     print("page: ", page)
    #     for item in page["ComplianceItems"]:
    #         non_compliant.append({
    #             "resource_name": item["ResourceId"],
    #             "title": item.get("Title"),
    #             "severity": item.get("Severity"),
    #             "compliance_type": item.get("ComplianceType"),
    #             "status": item.get("Status"),
    #             "execution_time": str(item.get("ExecutionSummary", {}).get("ExecutionTime")),
    #             "note": "Instance has missing or failed patches."
    #         })

    # scan_meta_data_global_services["total_scanned"] += len(non_compliant)
    # scan_meta_data_global_services["affected"] += len(non_compliant)
    # scan_meta_data_global_services["High"] += len(non_compliant)
    # scan_meta_data_global_services["services_scanned"].append("SSM")

    # return {
    #     "check_name": "Non-Compliant Patch Instances",
    #     "problem_statement": "Some managed instances have missing or failed patches.",
    #     "severity_score": 80,
    #     "severity_level": "High",
    #     "resources_affected": non_compliant,
    #     "recommendation": "Investigate and apply missing patches using Patch Manager or Systems Manager automation.",
    #     "additional_info": {"total_scanned": len(non_compliant), "affected": len(non_compliant)},
    # }
