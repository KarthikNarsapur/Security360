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
