use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationEvidence {
    pub not_before: i64,
    pub not_on_or_after: i64,
    pub policy_issuer: String,
    pub target: DelegationTarget,
    pub policy_sets: Vec<PolicySet>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationTarget {
    pub access_subject: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicySet {
    pub max_delegation_depth: i32,
    pub target: PolicySetTarget,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicySetTarget {
    pub environment: PolicySetTargetEnvironment,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicySetTargetEnvironment {
    pub licenses: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub target: ResourceTarget,
    pub rules: Vec<ResourceRules>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTarget {
    pub resource: Resource,
    pub actions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub identifiers: Vec<String>,
    pub attributes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRules {
    pub effect: String,
}

pub fn verify_delegation_evidence(
    delegation_evidence: &DelegationEvidence,
    resource_type: String,
) -> bool {
    let policy_sets = &delegation_evidence.policy_sets;
    if policy_sets.len() == 0 {
        return false;
    }
    let policies = &policy_sets[0].policies;
    if policies.len() == 0 {
        return false;
    }
    let policy = policies
        .iter()
        .find(|p| resource_type == p.target.resource.resource_type);
    if let None = policy {
        return false;
    }
    let rules = &policy.unwrap().rules;
    if rules.len() == 0 {
        return false;
    }

    return rules.get(0).unwrap().effect == "Permit";
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationEvidenceContainer {
    pub delegation_evidence: DelegationEvidence,
}
