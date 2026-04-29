# ElastiCache: Check for Unencrypted or Publicly Accessible Nodes

def check_elasticache_compliance(session):
    elasticache = session.client('elasticache')
    results = {
        "unencrypted_clusters": [],
        "publicly_accessible_clusters": []
    }

    clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True)['CacheClusters']
    for cluster in clusters:
        if not cluster.get('TransitEncryptionEnabled', False):
            results["unencrypted_clusters"].append(cluster['CacheClusterId'])

        # ElastiCache is usually in private subnets — for public exposure, you'd have to check subnet routes/NATs

    return results


def check_elasticache_transit_encryption(session, scan_meta_data):
    print("check_elasticache_transit_encryption")
    elasticache = session.client("elasticache")
    resources = []

    try:
        clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True).get("CacheClusters", [])
    except Exception as e:
        print(f"Error describing ElastiCache clusters: {e}")
        clusters = []

    for cluster in clusters:
        if not cluster.get("TransitEncryptionEnabled", False):
            resources.append({
                "resource_name": cluster.get("CacheClusterId"),
                "engine": cluster.get("Engine"),
                "engine_version": cluster.get("EngineVersion"),
                "cache_node_type": cluster.get("CacheNodeType"),
                "transit_encryption": "Disabled",
                "issue": "Encryption in transit is not enabled.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "ElastiCache" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ElastiCache")

    return {
        "check_name": "ElastiCache Encryption in Transit",
        "service": "ElastiCache",
        "problem_statement": "ElastiCache clusters do not have encryption in transit enabled, exposing data to interception.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable transit encryption on ElastiCache clusters. Note: this requires recreating the cluster.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }


def check_elasticache_auth_enabled(session, scan_meta_data):
    print("check_elasticache_auth_enabled")
    elasticache = session.client("elasticache")
    resources = []

    try:
        replication_groups = elasticache.describe_replication_groups().get("ReplicationGroups", [])
    except Exception as e:
        print(f"Error describing ElastiCache replication groups: {e}")
        replication_groups = []

    for rg in replication_groups:
        if not rg.get("AuthTokenEnabled", False):
            resources.append({
                "resource_name": rg.get("ReplicationGroupId"),
                "description": rg.get("Description"),
                "status": rg.get("Status"),
                "auth_token_enabled": "No",
                "issue": "AUTH token is not enabled on replication group.",
            })

    scan_meta_data["total_scanned"] += len(replication_groups)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "ElastiCache" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ElastiCache")

    return {
        "check_name": "ElastiCache AUTH Token",
        "service": "ElastiCache",
        "problem_statement": "ElastiCache replication groups do not have AUTH token enabled, allowing unauthenticated access.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable AUTH token on Redis replication groups to require authentication for client connections.",
        "additional_info": {"total_scanned": len(replication_groups), "affected": len(resources)},
    }


def check_elasticache_public_accessibility(session, scan_meta_data):
    print("check_elasticache_public_accessibility")
    ec2 = session.client("ec2")
    elasticache = session.client("elasticache")
    resources = []

    try:
        clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True).get("CacheClusters", [])
    except Exception as e:
        print(f"Error describing ElastiCache clusters: {e}")
        clusters = []

    # Get all route tables to check for IGW routes
    route_tables = ec2.describe_route_tables().get("RouteTables", [])
    public_subnets = set()
    for rt in route_tables:
        has_igw = any(
            r.get("GatewayId", "").startswith("igw-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )
        if has_igw:
            for assoc in rt.get("Associations", []):
                if assoc.get("SubnetId"):
                    public_subnets.add(assoc["SubnetId"])

    for cluster in clusters:
        cluster_id = cluster.get("CacheClusterId")
        subnet_group_name = cluster.get("CacheSubnetGroupName")

        if not subnet_group_name:
            resources.append({
                "resource_name": cluster_id,
                "engine": cluster.get("Engine"),
                "cache_node_type": cluster.get("CacheNodeType"),
                "issue": "No subnet group configured — may be using default VPC with public access.",
            })
            continue

        try:
            sg_resp = elasticache.describe_cache_subnet_groups(
                CacheSubnetGroupName=subnet_group_name
            )
            subnet_ids = [
                s["SubnetIdentifier"]
                for s in sg_resp["CacheSubnetGroups"][0].get("Subnets", [])
            ]
            public_subnet_matches = [s for s in subnet_ids if s in public_subnets]

            if public_subnet_matches:
                resources.append({
                    "resource_name": cluster_id,
                    "engine": cluster.get("Engine"),
                    "cache_node_type": cluster.get("CacheNodeType"),
                    "subnet_group": subnet_group_name,
                    "public_subnets": public_subnet_matches,
                    "issue": f"Cluster is in {len(public_subnet_matches)} public subnet(s) with IGW routes.",
                })
        except Exception as e:
            print(f"Error checking subnet group for {cluster_id}: {e}")

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "ElastiCache" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ElastiCache")

    return {
        "check_name": "ElastiCache Public Accessibility",
        "service": "ElastiCache",
        "problem_statement": "ElastiCache clusters are deployed in public subnets with internet gateway routes, potentially exposing them to the internet.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Deploy ElastiCache clusters in private subnets only. Ensure subnet groups do not include public subnets.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }
