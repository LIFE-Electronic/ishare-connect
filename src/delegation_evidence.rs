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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<Environment>,
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

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    pub service_providers: Vec<String>,
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

pub fn build_append_delegation_request(
    not_before: i64,
    not_on_or_after: i64,
    policy_issuer: String,
    access_subject: String,
    resource_type: String,
    service_provider: String,
    actions: Vec<String>,
    identifiers: Option<Vec<String>>,
    attributes: Option<Vec<String>>,
) -> DelegationEvidenceContainer {
    let actual_identifiers = match identifiers {
        None => vec!["*".to_owned()],
        Some(id) => id,
    };

    let actual_attributes = match attributes {
        None => vec!["*".to_owned()],
        Some(attr) => attr,
    };

    let service_providers = vec![service_provider];

    let new_policy = Policy {
        rules: vec![ResourceRules {
            effect: "Permit".to_owned(),
        }],
        target: ResourceTarget {
            actions,
            resource: Resource {
                resource_type,
                identifiers: actual_identifiers,
                attributes: actual_attributes,
            },
            environment: Some(Environment { service_providers }),
        },
    };

    let delegation_evidence = DelegationEvidence {
        not_before,
        not_on_or_after,
        policy_issuer,
        target: DelegationTarget { access_subject },
        policy_sets: vec![PolicySet {
            max_delegation_depth: 1,
            target: PolicySetTarget {
                environment: PolicySetTargetEnvironment {
                    licenses: vec!["ISHARE.0001".to_owned()],
                },
            },

            policies: vec![new_policy],
        }],
    };

    return DelegationEvidenceContainer {
        delegation_evidence,
    };
}

pub fn build_filter_delegation_request(
    not_before: i64,
    not_on_or_after: i64,
    policy_issuer: String,
    access_subject: String,
    resource_type: String,
    service_provider: String,
    actions: Vec<String>,
    identifiers: Vec<String>,
    attributes: Vec<String>,
    policies: Vec<Policy>,
) -> DelegationEvidenceContainer {
    let service_providers = vec![service_provider];

    let new_policies = policies
        .into_iter()
        .filter(|p| {
            !(p.target.resource.resource_type == resource_type
                && p.target.resource.identifiers == identifiers
                && p.target.actions == actions
                && p.target.resource.attributes == attributes
                && p.target
                    .environment
                    .as_ref()
                    .is_some_and(|e| e.service_providers == service_providers))
        })
        .collect();

    let delegation_evidence = DelegationEvidence {
        not_before,
        not_on_or_after,
        policy_issuer,
        target: DelegationTarget { access_subject },
        policy_sets: vec![PolicySet {
            max_delegation_depth: 1,
            target: PolicySetTarget {
                environment: PolicySetTargetEnvironment {
                    licenses: vec!["ISHARE.0001".to_owned()],
                },
            },

            policies: new_policies,
        }],
    };

    return DelegationEvidenceContainer {
        delegation_evidence,
    };
}
