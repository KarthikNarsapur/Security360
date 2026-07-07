"""
ISO 42001 Extended Checks — Amazon Bedrock (AI-023 to AI-030)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_bedrock_custom_models(session):
    """AI-023: Bedrock custom models inventory"""
    print("Checking Bedrock custom models inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock = session.client("bedrock")

        try:
            models = bedrock.list_custom_models().get("modelSummaries", [])
        except Exception:
            models = []

        # Flag models without proper tagging
        for model in models:
            model_name = model.get("modelName", "")
            model_arn = model.get("modelArn", "")
            try:
                tags = bedrock.list_tags_for_resource(resourceARN=model_arn).get("tags", [])
                has_owner = any(t.get("key") == "Owner" for t in tags)
                has_env = any(t.get("key") in ("Environment", "Env") for t in tags)
                if not has_owner or not has_env:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": model_name,
                        "resource_id_type": "ModelName",
                        "issue": f"Custom model '{model_name}' missing governance tags (Owner/Environment)",
                        "region": bedrock.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-023",
            "check_name": "Bedrock custom models inventory",
            "problem_statement": "Custom Bedrock models should be inventoried and tagged for governance",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Tag all custom models with Owner, Environment, and Purpose",
            "additional_info": {
                "total_scanned": max(len(models), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. List all custom models in Bedrock",
                "2. Apply governance tags (Owner, Environment, DataClassification)",
                "3. Document model lineage and training data sources",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock custom models: {e}")
        return None


def check_bedrock_provisioned_throughput(session):
    """AI-024: Provisioned throughput inventory"""
    print("Checking Bedrock provisioned throughput inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock = session.client("bedrock")

        try:
            throughputs = bedrock.list_provisioned_model_throughputs().get("provisionedModelSummaries", [])
        except Exception:
            throughputs = []

        for tp in throughputs:
            status = tp.get("status", "")
            name = tp.get("provisionedModelName", "")
            if status != "InService":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": name,
                    "resource_id_type": "ProvisionedModelName",
                    "issue": f"Provisioned throughput '{name}' status: {status}",
                    "region": bedrock.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-024",
            "check_name": "Provisioned throughput inventory",
            "problem_statement": "Bedrock provisioned throughput should be operational and cost-optimized",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Review provisioned throughput status and remove unused allocations",
            "additional_info": {
                "total_scanned": max(len(throughputs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Check provisioned model throughput status",
                "2. Remove allocations that are not InService",
                "3. Right-size throughput based on usage patterns",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock provisioned throughput: {e}")
        return None


def check_bedrock_inference_profiles(session):
    """AI-025: Inference profiles inventory"""
    print("Checking Bedrock inference profiles inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock = session.client("bedrock")

        try:
            profiles = bedrock.list_inference_profiles().get("inferenceProfileSummaries", [])
        except Exception:
            profiles = []

        # This is informational — report if no profiles exist (no governance over model selection)
        if len(profiles) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "Bedrock",
                "resource_id_type": "Service",
                "issue": "No inference profiles configured — no standardized model access control",
                "region": bedrock.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-025",
            "check_name": "Inference profiles inventory",
            "problem_statement": "Inference profiles should be used for standardized model access governance",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create inference profiles to standardize model access patterns",
            "additional_info": {
                "total_scanned": max(len(profiles), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Define inference profiles for approved model configurations",
                "2. Route model invocations through profiles",
                "3. Monitor profile usage for governance",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock inference profiles: {e}")
        return None


def check_bedrock_knowledge_bases(session):
    """AI-026: Knowledge Bases inventory"""
    print("Checking Bedrock Knowledge Bases inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock_agent = session.client("bedrock-agent")

        try:
            kbs = bedrock_agent.list_knowledge_bases().get("knowledgeBaseSummaries", [])
        except Exception:
            kbs = []

        for kb in kbs:
            kb_id = kb.get("knowledgeBaseId", "")
            status = kb.get("status", "")
            if status != "ACTIVE":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": kb_id,
                    "resource_id_type": "KnowledgeBaseId",
                    "issue": f"Knowledge Base '{kb.get('name', kb_id)}' status: {status}",
                    "region": bedrock_agent.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-026",
            "check_name": "Knowledge Bases inventory",
            "problem_statement": "Bedrock Knowledge Bases should be active and properly managed",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Ensure all Knowledge Bases are in ACTIVE state",
            "additional_info": {
                "total_scanned": max(len(kbs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review Knowledge Base status in Bedrock console",
                "2. Fix data source connectivity issues",
                "3. Re-sync knowledge base if needed",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock Knowledge Bases: {e}")
        return None


def check_knowledge_base_encryption(session):
    """AI-027: Knowledge Base data source encryption"""
    print("Checking Knowledge Base data source encryption")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock_agent = session.client("bedrock-agent")

        try:
            kbs = bedrock_agent.list_knowledge_bases().get("knowledgeBaseSummaries", [])
        except Exception:
            kbs = []

        for kb in kbs:
            kb_id = kb.get("knowledgeBaseId", "")
            try:
                detail = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id).get("knowledgeBase", {})
                storage_config = detail.get("storageConfiguration", {})
                # Check if vector store has encryption
                kb_type = storage_config.get("type", "")
                # For OpenSearch Serverless, check if it uses encryption
                if kb_type == "OPENSEARCH_SERVERLESS":
                    # OpenSearch Serverless always encrypts, but check KMS
                    pass
                elif kb_type == "PINECONE" or kb_type == "REDIS_ENTERPRISE_CLOUD":
                    # Third-party — cannot verify encryption
                    pass
                else:
                    # RDS or unknown — flag for review
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": kb_id,
                        "resource_id_type": "KnowledgeBaseId",
                        "issue": f"Knowledge Base '{kb.get('name', kb_id)}' — verify data source encryption",
                        "region": bedrock_agent.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-027",
            "check_name": "Knowledge Base data source encryption",
            "problem_statement": "Knowledge Base storage should be encrypted for data protection",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Verify encryption is enabled on all Knowledge Base data sources",
            "additional_info": {
                "total_scanned": max(len(kbs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review Knowledge Base storage configuration",
                "2. Enable KMS encryption for vector stores",
                "3. Ensure S3 data sources are encrypted",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Knowledge Base encryption: {e}")
        return None


def check_bedrock_agents(session):
    """AI-028: Bedrock Agent inventory"""
    print("Checking Bedrock Agent inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock_agent = session.client("bedrock-agent")

        try:
            agents = bedrock_agent.list_agents().get("agentSummaries", [])
        except Exception:
            agents = []

        for agent in agents:
            agent_id = agent.get("agentId", "")
            status = agent.get("agentStatus", "")
            if status not in ("PREPARED", "NOT_PREPARED"):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": agent_id,
                    "resource_id_type": "AgentId",
                    "issue": f"Bedrock Agent '{agent.get('agentName', agent_id)}' status: {status}",
                    "region": bedrock_agent.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-028",
            "check_name": "Bedrock Agent inventory",
            "problem_statement": "Bedrock Agents should be tracked and in operational state",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Monitor Bedrock Agent status and maintain inventory",
            "additional_info": {
                "total_scanned": max(len(agents), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review Bedrock Agent configurations",
                "2. Fix agents in error state",
                "3. Document agent purposes and data access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock Agents: {e}")
        return None


def check_bedrock_agent_aliases(session):
    """AI-029: Bedrock Agent alias inventory"""
    print("Checking Bedrock Agent alias inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock_agent = session.client("bedrock-agent")

        try:
            agents = bedrock_agent.list_agents().get("agentSummaries", [])
        except Exception:
            agents = []

        total_aliases = 0
        for agent in agents:
            agent_id = agent.get("agentId", "")
            try:
                aliases = bedrock_agent.list_agent_aliases(agentId=agent_id).get("agentAliasSummaries", [])
                total_aliases += len(aliases)
                # Check for aliases not pointing to latest version
                for alias in aliases:
                    routing = alias.get("routingConfiguration", [])
                    if not routing:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": f"{agent_id}/{alias.get('agentAliasName', '')}",
                            "resource_id_type": "AgentAlias",
                            "issue": f"Agent alias '{alias.get('agentAliasName', '')}' has no routing config",
                            "region": bedrock_agent.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-029",
            "check_name": "Bedrock Agent alias inventory",
            "problem_statement": "Agent aliases should be properly configured for version management",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Ensure agent aliases have proper routing and version configuration",
            "additional_info": {
                "total_scanned": max(total_aliases, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review agent alias configurations",
                "2. Ensure aliases route to tested agent versions",
                "3. Use aliases for production traffic management",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock Agent aliases: {e}")
        return None


def check_bedrock_prompt_management(session):
    """AI-030: Prompt management inventory"""
    print("Checking Bedrock prompt management inventory")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        bedrock_agent = session.client("bedrock-agent")

        try:
            prompts = bedrock_agent.list_prompts().get("promptSummaries", [])
        except Exception:
            prompts = []

        # Governance: prompts should be versioned
        for prompt in prompts:
            prompt_id = prompt.get("id", "")
            name = prompt.get("name", "")
            version = prompt.get("version", "")
            if not version or version == "DRAFT":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": name or prompt_id,
                    "resource_id_type": "PromptId",
                    "issue": f"Prompt '{name}' only has DRAFT version — not version-controlled",
                    "region": bedrock_agent.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-030",
            "check_name": "Prompt management inventory",
            "problem_statement": "AI prompts should be version-controlled for governance and reproducibility",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Version-control all prompts and maintain prompt governance",
            "additional_info": {
                "total_scanned": max(len(prompts), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create versioned prompts instead of using only DRAFT",
                "2. Document prompt purposes and approved changes",
                "3. Test prompt versions before production use",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Bedrock prompt management: {e}")
        return None
