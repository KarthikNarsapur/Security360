def unencrypted_ebs_volumes(session):
    ec2 = session.client('ec2')
    volumes = ec2.describe_volumes()['Volumes']
    return [vol for vol in volumes if not vol['Encrypted']]
