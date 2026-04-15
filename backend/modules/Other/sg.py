def check_open_security_groups(session):
    ec2 = session.client('ec2')
    results = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for perm in sg['IpPermissions']:
            for ip_range in perm.get('IpRanges', []):
                if ip_range['CidrIp'] == '0.0.0.0/0':
                    results.append(sg)
    return results


def find_unused_security_groups(session):
    ec2 = session.client('ec2')
    all_sgs = {sg['GroupId'] for sg in ec2.describe_security_groups()['SecurityGroups']}
    used_sgs = set()

    for eni in ec2.describe_network_interfaces()['NetworkInterfaces']:
        for sg in eni['Groups']:
            used_sgs.add(sg['GroupId'])

    return list(all_sgs - used_sgs)


# aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]"