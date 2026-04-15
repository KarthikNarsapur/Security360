import boto3

def check_unencrypted_dynamodb_tables(session):
    dynamodb = session.client('dynamodb')
    unencrypted_tables = []
    all_tables = dynamodb.list_tables()['TableNames']

    for table in all_tables:
        desc = dynamodb.describe_table(TableName=table)['Table']
        sse = desc.get('SSEDescription')
        if not sse or sse.get('Status') != 'ENABLED':
            unencrypted_tables.append(table)

    return {
        "severity": "high",
        "risk_score": 85,
        "total_scanned": len(all_tables),
        "affected": len(unencrypted_tables),
        "service": "dynamodb",
        "resources": unencrypted_tables
    }


def check_public_dynamodb_access(session, iam_client=None):
    """
    This function checks IAM policies for public (wildcard "*") access to DynamoDB resources.
    """
    if iam_client is None:
        iam_client = session.client('iam')

    public_tables = []
    scanned_policies = 0

    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local'):
        for policy in page['Policies']:
            scanned_policies += 1
            policy_arn = policy['Arn']
            versions = iam_client.list_policy_versions(PolicyArn=policy_arn)
            default_version = next(v for v in versions['Versions'] if v['IsDefaultVersion'])

            policy_doc = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version['VersionId']
            )['PolicyVersion']['Document']

            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    actions = stmt.get('Action', [])
                    resources = stmt.get('Resource', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]
                    if "*" in stmt.get('Principal', {}).get('AWS', []):
                        for res in resources:
                            if "dynamodb" in res:
                                public_tables.append(res)

    return {
        "severity": "critical",
        "risk_score": 95,
        "total_scanned": scanned_policies,
        "affected": len(public_tables),
        "service": "dynamodb",
        "resources": public_tables
    }




# # DynamoDB: Check for Table Encryption and Public Access Policies (via IAM)

# def check_dynamodb_compliance(session):
#     dynamodb = session.client('dynamodb')
#     results = {
#         "unencrypted_tables": [],
#         "public_access_tables": []
#     }

#     tables = dynamodb.list_tables()['TableNames']
#     for table in tables:
#         desc = dynamodb.describe_table(TableName=table)['Table']
#         # Check encryption
#         if not desc.get('SSEDescription') or desc['SSEDescription'].get('Status') != 'ENABLED':
#             results["unencrypted_tables"].append(table)

#         # Public access via IAM needs to be checked outside of table context

#     return results
