#  DocumentDB: Check for Publicly Accessible Clusters

def check_documentdb_compliance(session):
    docdb = session.client('docdb')
    results = {
        "publicly_accessible_clusters": []
    }

    clusters = docdb.describe_db_clusters()['DBClusters']
    for cluster in clusters:
        if cluster.get('HostedZoneId'):  # Indicates possible public access
            for instance in docdb.describe_db_instances()['DBInstances']:
                if instance['DBClusterIdentifier'] == cluster['DBClusterIdentifier']:
                    if instance['PubliclyAccessible']:
                        results["publicly_accessible_clusters"].append(cluster['DBClusterIdentifier'])
                        break

    return results
