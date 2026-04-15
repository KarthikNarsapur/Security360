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
