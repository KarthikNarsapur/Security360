import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_elasticache_encryption(session):
    # [ElastiCache.4, ElastiCache.5]
    print("Checking ElastiCache encryption at rest and in transit")

    elasticache = session.client("elasticache")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=False).get(
            "CacheClusters", []
        )

        for cluster in clusters:
            cluster_id = cluster["CacheClusterId"]
            at_rest = cluster.get("AtRestEncryptionEnabled", False)
            in_transit = cluster.get("TransitEncryptionEnabled", False)

            if not at_rest or not in_transit:
                missing = []
                if not at_rest:
                    missing.append("encryption at rest")
                if not in_transit:
                    missing.append("encryption in transit")

                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster_id,
                        "resource_id_type": "CacheClusterId",
                        "issue": f"ElastiCache cluster missing {', '.join(missing)}",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "ElastiCache.4/5",
            "check_name": "ElastiCache encryption in transit and at rest",
            "problem_statement": "ElastiCache clusters should have both encryption in transit and encryption at rest enabled.",
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable both in-transit and at-rest encryption for ElastiCache clusters.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. When creating an ElastiCache cluster, enable 'Encryption in-transit' and 'Encryption at-rest'.",
                "2. For existing clusters, create a new cluster with encryption enabled and migrate data.",
                "3. Use TLS-enabled endpoints for encrypted connections.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking ElastiCache encryption: {e}")
        return None
