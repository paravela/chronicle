use iref::{AsIri, Iri};
use json::{object, JsonValue};

use crate::{
    attributes::{Attribute, Attributes},
    prov::{
        operations::{ChronicleOperation, CreateNamespace, DerivationType},
        vocab::{Chronicle, ChronicleOperations, Prov},
        ChronicleIri, NamePart, UuidPart,
    },
};

use super::{ExpandedJson, ProvModel};
use crate::prov::operations::*;
pub trait ToJson {
    fn to_json(&self) -> ExpandedJson;
}

impl ToJson for ProvModel {
    /// Write the model out as a JSON-LD document in expanded form
    fn to_json(&self) -> ExpandedJson {
        let mut doc = json::Array::new();

        for (id, ns) in self.namespaces.iter() {
            doc.push(object! {
                "@id": (*id.to_string()),
                "@type": Iri::from(Chronicle::Namespace).as_str(),
                "http://www.w3.org/2000/01/rdf-schema#label": [{
                    "@value": ns.name.as_str(),
                }]
            })
        }

        for ((ns, id), identity) in self.identities.iter() {
            doc.push(object! {
                "@id": (*id.to_string()),
                "@type": Iri::from(Chronicle::Identity).as_str(),
                "http://blockchaintp.com/chronicle/ns#publicKey": [{
                    "@value": identity.public_key.to_string(),
                }],
                "http://blockchaintp.com/chronicle/ns#hasNamespace": [{
                    "@id": ns.to_string()
                }],
            })
        }

        for ((ns, id), attachment) in self.attachments.iter() {
            let mut attachmentdoc = object! {
                "@id": (*id.to_string()),
                "@type": Iri::from(Chronicle::HasEvidence).as_str(),
                "http://blockchaintp.com/chronicle/ns#entitySignature": attachment.signature.to_string(),
                "http://blockchaintp.com/chronicle/ns#signedAtTime": attachment.signature_time.to_rfc3339(),
                "http://blockchaintp.com/chronicle/ns#signedBy": {
                    "@id": attachment.signer.to_string()
                },
                "http://blockchaintp.com/chronicle/ns#hasNamespace": [{
                    "@id": ns.to_string()
                }],
            };

            if let Some(locator) = attachment.locator.as_ref() {
                let mut values = json::Array::new();

                values.push(object! {
                    "@value": JsonValue::String(locator.to_owned()),
                });

                attachmentdoc
                    .insert(Iri::from(Chronicle::Locator).as_str(), values)
                    .ok();
            }

            doc.push(attachmentdoc);
        }

        for ((_, id), agent) in self.agents.iter() {
            let mut typ = vec![Iri::from(Prov::Agent).to_string()];
            if let Some(x) = agent.domaintypeid.as_ref() {
                typ.push(x.to_string())
            }

            let mut agentdoc = object! {
                "@id": (*id.to_string()),
                "@type": typ,
                "http://www.w3.org/2000/01/rdf-schema#label": [{
                   "@value": agent.name.as_str(),
                }]
            };

            let agent_key = (agent.namespaceid.clone(), agent.id.clone());

            if let Some((_, identity)) = self.has_identity.get(&agent_key) {
                agentdoc
                    .insert(
                        Iri::from(Chronicle::HasIdentity).as_str(),
                        object! {"@id": identity.to_string()},
                    )
                    .ok();
            }

            if let Some(identities) = self.had_identity.get(&agent_key) {
                let mut values = json::Array::new();

                for (_, id) in identities {
                    values.push(object! { "@id": id.to_string()});
                }
                agentdoc
                    .insert(Iri::from(Chronicle::HadIdentity).as_str(), values)
                    .ok();
            }

            if let Some(delegation) = self
                .delegation
                .get(&(agent.namespaceid.to_owned(), id.to_owned()))
            {
                let mut ids = json::Array::new();
                let mut qualified_ids = json::Array::new();

                for delegation in delegation.iter() {
                    ids.push(object! {"@id": delegation.delegate_id.to_string()});
                    qualified_ids.push(object! {"@id": delegation.id.to_string()});
                }

                agentdoc
                    .insert(Iri::from(Prov::ActedOnBehalfOf).as_str(), ids)
                    .ok();

                agentdoc
                    .insert(Iri::from(Prov::QualifiedDelegation).as_str(), qualified_ids)
                    .ok();
            }

            let mut values = json::Array::new();

            values.push(object! {
                "@id": JsonValue::String(agent.namespaceid.to_string()),
            });

            agentdoc
                .insert(Iri::from(Chronicle::HasNamespace).as_str(), values)
                .ok();

            Self::write_attributes(&mut agentdoc, agent.attributes.values());

            doc.push(agentdoc);
        }

        for (_, associations) in self.association.iter() {
            for association in associations {
                let mut associationdoc = object! {
                    "@id": association.id.to_string(),
                    "@type": Iri::from(Prov::Association).as_str(),
                };

                let mut values = json::Array::new();

                values.push(object! {
                    "@id": JsonValue::String(association.agent_id.to_string()),
                });

                associationdoc
                    .insert(Iri::from(Prov::Responsible).as_str(), values)
                    .ok();

                associationdoc
                    .insert(
                        Iri::from(Prov::HadActivity).as_str(),
                        vec![object! {
                            "@id": JsonValue::String(association.activity_id.to_string()),
                        }],
                    )
                    .ok();

                if let Some(role) = &association.role {
                    associationdoc
                        .insert(
                            Iri::from(Prov::HadRole).as_str(),
                            vec![JsonValue::String(role.to_string())],
                        )
                        .ok();
                }

                let mut values = json::Array::new();

                values.push(object! {
                    "@id": JsonValue::String(association.namespace_id.to_string()),
                });

                associationdoc
                    .insert(Iri::from(Chronicle::HasNamespace).as_str(), values)
                    .ok();

                doc.push(associationdoc);
            }
        }

        for (_, delegations) in self.delegation.iter() {
            for delegation in delegations {
                let mut delegationdoc = object! {
                    "@id": delegation.id.to_string(),
                    "@type": Iri::from(Prov::Delegation).as_str(),
                };

                if let Some(activity_id) = &delegation.activity_id {
                    delegationdoc
                        .insert(
                            Iri::from(Prov::HadActivity).as_str(),
                            vec![object! {
                                "@id": JsonValue::String(activity_id.to_string()),
                            }],
                        )
                        .ok();
                }

                if let Some(role) = &delegation.role {
                    delegationdoc
                        .insert(
                            Iri::from(Prov::HadRole).as_str(),
                            vec![JsonValue::String(role.to_string())],
                        )
                        .ok();
                }

                let mut responsible_ids = json::Array::new();
                responsible_ids.push(
                    object! { "@id": JsonValue::String(delegation.responsible_id.to_string())},
                );

                delegationdoc
                    .insert(Iri::from(Prov::Responsible).as_str(), responsible_ids)
                    .ok();

                let mut delegate_ids = json::Array::new();
                delegate_ids
                    .push(object! { "@id": JsonValue::String(delegation.delegate_id.to_string())});

                delegationdoc
                    .insert(Iri::from(Prov::ActedOnBehalfOf).as_str(), delegate_ids)
                    .ok();

                let mut values = json::Array::new();

                values.push(object! {
                    "@id": JsonValue::String(delegation.namespace_id.to_string()),
                });

                delegationdoc
                    .insert(Iri::from(Chronicle::HasNamespace).as_str(), values)
                    .ok();

                doc.push(delegationdoc);
            }
        }

        for ((namespace, id), activity) in self.activities.iter() {
            let mut typ = vec![Iri::from(Prov::Activity).to_string()];
            if let Some(x) = activity.domaintypeid.as_ref() {
                typ.push(x.to_string())
            }

            let mut activitydoc = object! {
                "@id": (*id.to_string()),
                "@type": typ,
                "http://www.w3.org/2000/01/rdf-schema#label": [{
                   "@value": activity.name.as_str(),
                }]
            };

            if let Some(time) = activity.started {
                let mut values = json::Array::new();
                values.push(object! {"@value": time.to_rfc3339()});

                activitydoc
                    .insert("http://www.w3.org/ns/prov#startedAtTime", values)
                    .ok();
            }

            if let Some(time) = activity.ended {
                let mut values = json::Array::new();
                values.push(object! {"@value": time.to_rfc3339()});

                activitydoc
                    .insert("http://www.w3.org/ns/prov#endedAtTime", values)
                    .ok();
            }

            if let Some(asoc) = self.association.get(&(namespace.to_owned(), id.to_owned())) {
                let mut ids = json::Array::new();

                let mut qualified_ids = json::Array::new();
                for asoc in asoc.iter() {
                    ids.push(object! {"@id": asoc.agent_id.to_string()});
                    qualified_ids.push(object! {"@id": asoc.id.to_string()});
                }

                activitydoc
                    .insert(&Iri::from(Prov::WasAssociatedWith).to_string(), ids)
                    .ok();

                activitydoc
                    .insert(
                        &Iri::from(Prov::QualifiedAssociation).to_string(),
                        qualified_ids,
                    )
                    .ok();
            }

            if let Some(useage) = self.useage.get(&(namespace.to_owned(), id.to_owned())) {
                let mut ids = json::Array::new();

                for useage in useage.iter() {
                    ids.push(object! {"@id": useage.entity_id.to_string()});
                }

                activitydoc
                    .insert(&Iri::from(Prov::Used).to_string(), ids)
                    .ok();
            }

            let mut values = json::Array::new();

            values.push(object! {
                "@id": JsonValue::String(activity.namespaceid.to_string()),
            });

            activitydoc
                .insert(Iri::from(Chronicle::HasNamespace).as_str(), values)
                .ok();

            Self::write_attributes(&mut activitydoc, activity.attributes.values());

            doc.push(activitydoc);
        }

        for ((namespace, id), entity) in self.entities.iter() {
            let mut typ = vec![Iri::from(Prov::Entity).to_string()];
            if let Some(x) = entity.domaintypeid.as_ref() {
                typ.push(x.to_string())
            }

            let mut entitydoc = object! {
                "@id": (*id.to_string()),
                "@type": typ,
                "http://www.w3.org/2000/01/rdf-schema#label": [{
                   "@value": entity.name.as_str()
                }]
            };

            if let Some(derivation) = self.derivation.get(&(namespace.to_owned(), id.to_owned())) {
                let mut derived_ids = json::Array::new();
                let mut primary_ids = json::Array::new();
                let mut quotation_ids = json::Array::new();
                let mut revision_ids = json::Array::new();

                for derivation in derivation.iter() {
                    let id = object! {"@id": derivation.used_id.to_string()};
                    match derivation.typ {
                        Some(DerivationType::PrimarySource) => primary_ids.push(id),
                        Some(DerivationType::Quotation) => quotation_ids.push(id),
                        Some(DerivationType::Revision) => revision_ids.push(id),
                        _ => derived_ids.push(id),
                    }
                }
                if !derived_ids.is_empty() {
                    entitydoc
                        .insert(Iri::from(Prov::WasDerivedFrom).as_str(), derived_ids)
                        .ok();
                }
                if !primary_ids.is_empty() {
                    entitydoc
                        .insert(Iri::from(Prov::HadPrimarySource).as_str(), primary_ids)
                        .ok();
                }
                if !quotation_ids.is_empty() {
                    entitydoc
                        .insert(Iri::from(Prov::WasQuotedFrom).as_str(), quotation_ids)
                        .ok();
                }
                if !revision_ids.is_empty() {
                    entitydoc
                        .insert(Iri::from(Prov::WasRevisionOf).as_str(), revision_ids)
                        .ok();
                }
            }

            if let Some(generation) = self.generation.get(&(namespace.to_owned(), id.to_owned())) {
                let mut ids = json::Array::new();

                for generation in generation.iter() {
                    ids.push(object! {"@id": generation.activity_id.to_string()});
                }

                entitydoc
                    .insert(Iri::from(Prov::WasGeneratedBy).as_str(), ids)
                    .ok();
            }

            let entity_key = (entity.namespaceid.clone(), entity.id.clone());

            if let Some((_, identity)) = self.has_evidence.get(&entity_key) {
                entitydoc
                    .insert(
                        Iri::from(Chronicle::HasEvidence).as_str(),
                        object! {"@id": identity.to_string()},
                    )
                    .ok();
            }

            if let Some(identities) = self.had_attachment.get(&entity_key) {
                let mut values = json::Array::new();

                for (_, id) in identities {
                    values.push(object! { "@id": id.to_string()});
                }
                entitydoc
                    .insert(Iri::from(Chronicle::HadEvidence).as_str(), values)
                    .ok();
            }

            let mut values = json::Array::new();

            values.push(object! {
                "@id": JsonValue::String(entity.namespaceid.to_string()),
            });

            entitydoc
                .insert(Iri::from(Chronicle::HasNamespace).as_str(), values)
                .ok();

            Self::write_attributes(&mut entitydoc, entity.attributes.values());

            doc.push(entitydoc);
        }

        ExpandedJson(doc.into())
    }
}

fn we_need_to_update_the_ld_library_to_a_version_that_supports_serde(
    json: &serde_json::Value,
) -> JsonValue {
    json::parse(&json.to_string()).unwrap()
}

impl ProvModel {
    fn write_attributes<'a, I: Iterator<Item = &'a Attribute>>(doc: &mut JsonValue, attributes: I) {
        let mut attribute_node = object! {};

        for attribute in attributes {
            attribute_node
                .insert(
                    &*attribute.typ,
                    we_need_to_update_the_ld_library_to_a_version_that_supports_serde(
                        &attribute.value,
                    ),
                )
                .ok();
        }

        doc.insert(
            &Chronicle::Value.as_iri().to_string(),
            object! {"@value" : attribute_node, "@type": "@json"},
        )
        .ok();
    }
}

impl ToJson for ChronicleOperation {
    fn to_json(&self) -> ExpandedJson {
        let mut operation: Vec<JsonValue> = json::Array::new();

        let o = match self {
            ChronicleOperation::CreateNamespace(CreateNamespace { id, .. }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::CreateNamespace);

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(id.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o
            }
            ChronicleOperation::AgentExists(AgentExists { namespace, name }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::AgentExists);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(OperationValue::string(name), ChronicleOperations::AgentName);

                o
            }
            ChronicleOperation::AgentActsOnBehalfOf(ActsOnBehalfOf {
                namespace,
                id: _, // This is derivable from components
                delegate_id,
                activity_id,
                role,
                responsible_id,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::AgentActsOnBehalfOf);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(delegate_id.name_part()),
                    ChronicleOperations::DelegateId,
                );

                o.has_value(
                    OperationValue::string(responsible_id.name_part()),
                    ChronicleOperations::ResponsibleId,
                );

                if let Some(role) = role {
                    o.has_value(OperationValue::string(role), ChronicleOperations::Role);
                }

                if let Some(activity_id) = activity_id {
                    o.has_value(
                        OperationValue::string(activity_id.name_part()),
                        ChronicleOperations::ActivityName,
                    );
                }

                o
            }
            ChronicleOperation::RegisterKey(RegisterKey {
                namespace,
                id,
                publickey,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::RegisterKey);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::AgentName,
                );

                o.has_value(
                    OperationValue::string(publickey.to_owned()),
                    ChronicleOperations::PublicKey,
                );

                o
            }
            ChronicleOperation::ActivityExists(ActivityExists { namespace, name }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::ActivityExists);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(name),
                    ChronicleOperations::ActivityName,
                );

                o
            }
            ChronicleOperation::StartActivity(StartActivity {
                namespace,
                id,
                time,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::StartActivity);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::ActivityName,
                );

                o.has_value(
                    OperationValue::string(time.to_rfc3339()),
                    ChronicleOperations::StartActivityTime,
                );

                o
            }
            ChronicleOperation::EndActivity(EndActivity {
                namespace,
                id,
                time,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::EndActivity);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::ActivityName,
                );

                o.has_value(
                    OperationValue::string(time.to_rfc3339()),
                    ChronicleOperations::EndActivityTime,
                );

                o
            }
            ChronicleOperation::ActivityUses(ActivityUses {
                namespace,
                id,
                activity,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::ActivityUses);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::EntityName,
                );

                o.has_value(
                    OperationValue::string(activity.name_part()),
                    ChronicleOperations::ActivityName,
                );

                o
            }
            ChronicleOperation::EntityExists(EntityExists { namespace, name }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::EntityExists);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(name),
                    ChronicleOperations::EntityName,
                );

                o
            }
            ChronicleOperation::WasGeneratedBy(WasGeneratedBy {
                namespace,
                id,
                activity,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::WasGeneratedBy);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::EntityName,
                );

                o.has_value(
                    OperationValue::string(activity.name_part()),
                    ChronicleOperations::ActivityName,
                );

                o
            }
            ChronicleOperation::EntityHasEvidence(EntityHasEvidence {
                namespace,
                identityid,
                id,
                locator,
                agent,
                signature,
                signature_time,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::EntityHasEvidence);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::EntityName,
                );

                o.has_value(
                    OperationValue::string(agent.name_part()),
                    ChronicleOperations::AgentName,
                );

                if let Some(locator) = locator {
                    o.has_value(
                        OperationValue::string(locator),
                        ChronicleOperations::Locator,
                    );
                }

                if let Some(signature) = signature {
                    o.has_value(
                        OperationValue::string(signature),
                        ChronicleOperations::Signature,
                    );
                }

                if let Some(signature_time) = signature_time {
                    o.has_value(
                        OperationValue::string(signature_time.to_rfc3339()),
                        ChronicleOperations::SignatureTime,
                    );
                }

                if let Some(identity_id) = identityid {
                    o.has_id(
                        OperationValue::identity(identity_id.clone().into()),
                        ChronicleOperations::Identity,
                    );
                }

                o
            }
            ChronicleOperation::EntityDerive(EntityDerive {
                namespace,
                id,
                used_id,
                activity_id,
                typ,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::EntityDerive);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::EntityName,
                );

                o.has_value(
                    OperationValue::string(used_id.name_part()),
                    ChronicleOperations::UsedEntityName,
                );

                if let Some(activity) = activity_id {
                    o.has_value(
                        OperationValue::string(activity.name_part()),
                        ChronicleOperations::ActivityName,
                    );
                }

                if let Some(typ) = typ {
                    o.derivation(typ);
                }

                o
            }
            ChronicleOperation::SetAttributes(SetAttributes::Entity {
                namespace,
                id,
                attributes,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::SetAttributes);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::EntityName,
                );

                if let Some(domaintypeid) = &attributes.typ {
                    let id = OperationValue::string(domaintypeid.name_part());
                    o.has_value(id, ChronicleOperations::DomaintypeId);
                }

                o.attributes_object(attributes);

                o
            }
            ChronicleOperation::SetAttributes(SetAttributes::Activity {
                namespace,
                id,
                attributes,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::SetAttributes);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::ActivityName,
                );

                if let Some(domaintypeid) = &attributes.typ {
                    let id = OperationValue::string(domaintypeid.name_part());
                    o.has_value(id, ChronicleOperations::DomaintypeId);
                }

                o.attributes_object(attributes);

                o
            }
            ChronicleOperation::SetAttributes(SetAttributes::Agent {
                namespace,
                id,
                attributes,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::SetAttributes);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(id.name_part()),
                    ChronicleOperations::AgentName,
                );

                if let Some(domaintypeid) = &attributes.typ {
                    let id = OperationValue::string(domaintypeid.name_part());
                    o.has_value(id, ChronicleOperations::DomaintypeId);
                }

                o.attributes_object(attributes);

                o
            }
            ChronicleOperation::WasAssociatedWith(WasAssociatedWith {
                id: _,
                role,
                namespace,
                activity_id,
                agent_id,
            }) => {
                let mut o = JsonValue::new_operation(ChronicleOperations::WasAssociatedWith);

                o.has_value(
                    OperationValue::string(namespace.name_part()),
                    ChronicleOperations::NamespaceName,
                );

                o.has_value(
                    OperationValue::string(namespace.uuid_part()),
                    ChronicleOperations::NamespaceUuid,
                );

                o.has_value(
                    OperationValue::string(activity_id.name_part()),
                    ChronicleOperations::ActivityName,
                );

                o.has_value(
                    OperationValue::string(agent_id.name_part()),
                    ChronicleOperations::AgentName,
                );

                if let Some(role) = role {
                    o.has_value(OperationValue::string(role), ChronicleOperations::Role);
                }

                o
            }
        };
        operation.push(o);
        super::ExpandedJson(operation.into())
    }
}

struct OperationValue(String);

impl OperationValue {
    fn string(value: impl ToString) -> Self {
        OperationValue(value.to_string())
    }

    fn identity(id: ChronicleIri) -> Self {
        OperationValue(id.to_string())
    }
}

trait Operate {
    fn new_operation(op: ChronicleOperations) -> Self;
    fn new_type(id: OperationValue, op: ChronicleOperations) -> Self;
    fn new_value(id: OperationValue) -> Self;
    fn new_id(id: OperationValue) -> Self;
    fn has_value(&mut self, value: OperationValue, op: ChronicleOperations);
    fn has_id(&mut self, id: OperationValue, op: ChronicleOperations);
    fn attributes_object(&mut self, attributes: &Attributes);
    fn derivation(&mut self, typ: &DerivationType);
}

impl Operate for JsonValue {
    fn new_type(id: OperationValue, op: ChronicleOperations) -> Self {
        object! {
            "@id": id.0,
            "@type": iref::Iri::from(op).as_str(),
        }
    }

    fn new_value(id: OperationValue) -> Self {
        object! {
            "@value": id.0
        }
    }

    fn new_id(id: OperationValue) -> Self {
        object! {
            "@id": id.0
        }
    }

    fn has_value(&mut self, value: OperationValue, op: ChronicleOperations) {
        let key = iref::Iri::from(op).to_string();
        let mut values: Vec<JsonValue> = json::Array::new();
        let object = Self::new_value(value);
        values.push(object);
        self.insert(&key, values).ok();
    }

    fn has_id(&mut self, id: OperationValue, op: ChronicleOperations) {
        let key = iref::Iri::from(op).to_string();
        let mut value: Vec<JsonValue> = json::Array::new();
        let object = Self::new_id(id);
        value.push(object);
        self.insert(&key, value).ok();
    }

    fn new_operation(op: ChronicleOperations) -> Self {
        let id = OperationValue::string("_:n1");
        Self::new_type(id, op)
    }

    fn attributes_object(&mut self, attributes: &Attributes) {
        let mut attribute_node = object! {};
        for attribute in attributes.attributes.values() {
            attribute_node
                .insert(
                    &*attribute.typ,
                    we_need_to_update_the_ld_library_to_a_version_that_supports_serde(
                        &attribute.value,
                    ),
                )
                .ok();
        }

        self.insert(
            &iref::Iri::from(ChronicleOperations::Attributes).to_string(),
            object! {"@value" : attribute_node, "@type": "@json"},
        )
        .ok();
    }

    fn derivation(&mut self, typ: &DerivationType) {
        let typ = match typ {
            DerivationType::Revision => "Revision",
            DerivationType::Quotation => "Quotation",
            DerivationType::PrimarySource => "PrimarySource",
        };
        let id = OperationValue::string(typ);

        self.has_value(id, ChronicleOperations::DerivationType);
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use serde_json::json;
    use uuid::Uuid;

    use crate::{
        attributes::{Attribute, Attributes},
        prov::{
            operations::{
                ActivityExists, ActivityUses, ActsOnBehalfOf, CreateNamespace, EntityDerive,
                EntityExists, EntityHasEvidence, RegisterKey, SetAttributes, StartActivity,
                WasGeneratedBy,
            },
            to_json_ld::ToJson,
            ActivityId, AgentId, DomaintypeId, EntityId, NamePart, NamespaceId, Role,
        },
    };

    use super::{ChronicleOperation, DerivationType};

    fn uuid() -> Uuid {
        let bytes = [
            0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
            0xd7, 0xd8,
        ];
        Uuid::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_create_namespace() {
        let name = "testns";
        let id = NamespaceId::from_name(name, uuid());

        let op = ChronicleOperation::CreateNamespace(CreateNamespace::new(id, name, uuid()));
        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#CreateNamespace",
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_create_agent() {
        let uuid = uuid();
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid);
        let name: crate::prov::Name =
            crate::prov::NamePart::name_part(&crate::prov::AgentId::from_name("test_agent"))
                .clone();
        let op: ChronicleOperation =
            super::ChronicleOperation::AgentExists(crate::prov::operations::AgentExists {
                namespace,
                name,
            });
        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#AgentExists",
            "http://blockchaintp.com/chronicleoperations/ns#agentName": [
              {
                "@value": "test_agent"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_agent_acts_on_behalf_of() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let responsible_id = AgentId::from_name("test_agent");
        let delegate_id = AgentId::from_name("test_delegate");
        let activity_id = Some(ActivityId::from_name("test_activity"));
        let role = Some(Role::from("test_role"));

        let op: ChronicleOperation = ChronicleOperation::AgentActsOnBehalfOf(ActsOnBehalfOf::new(
            &namespace,
            &responsible_id,
            &delegate_id,
            activity_id.as_ref(),
            role,
        ));

        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#AgentActsOnBehalfOf",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#delegateId": [
              {
                "@value": "test_delegate"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#responsibleId": [
              {
                "@value": "test_agent"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#role": [
              {
                "@value": "test_role"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_register_key() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = crate::prov::AgentId::from_name("test_agent");
        let publickey =
            "02197db854d8c6a488d4a0ef3ef1fcb0c06d66478fae9e87a237172cf6f6f7de23".to_string();

        let op: ChronicleOperation = ChronicleOperation::RegisterKey(RegisterKey {
            namespace,
            id,
            publickey,
        });

        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#RegisterKey",
            "http://blockchaintp.com/chronicleoperations/ns#agentName": [
              {
                "@value": "test_agent"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#publicKey": [
              {
                "@value": "02197db854d8c6a488d4a0ef3ef1fcb0c06d66478fae9e87a237172cf6f6f7de23"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_create_activity() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let name = NamePart::name_part(&ActivityId::from_name("test_activity")).to_owned();

        let op: ChronicleOperation =
            ChronicleOperation::ActivityExists(ActivityExists { namespace, name });

        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#ActivityExists",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn start_activity() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = ActivityId::from_name("test_activity");
        let time = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(61, 0),
            chrono::Utc,
        );
        let op: ChronicleOperation = ChronicleOperation::StartActivity(StartActivity {
            namespace,
            id,
            time,
        });

        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#StartActivity",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#startActivityTime": [
              {
                "@value": "1970-01-01T00:01:01+00:00"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_end_activity() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = ActivityId::from_name("test_activity");
        let time = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(61, 0),
            chrono::Utc,
        );
        let op: ChronicleOperation =
            super::ChronicleOperation::EndActivity(crate::prov::operations::EndActivity {
                namespace,
                id,
                time,
            });

        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#endactivity",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#endActivityTime": [
              {
                "@value": "1970-01-01T00:01:01+00:00"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_activity_uses() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = EntityId::from_name("test_entity");
        let activity = ActivityId::from_name("test_activity");
        let op: ChronicleOperation = ChronicleOperation::ActivityUses(ActivityUses {
            namespace,
            id,
            activity,
        });

        let x = op.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#ActivityUses",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_create_entity() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = NamePart::name_part(&EntityId::from_name("test_entity")).to_owned();
        let operation: ChronicleOperation = ChronicleOperation::EntityExists(EntityExists {
            namespace,
            name: id,
        });

        let x = operation.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#EntityExists",
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_generate_entity() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = EntityId::from_name("test_entity");
        let activity = ActivityId::from_name("test_activity");
        let operation: ChronicleOperation = ChronicleOperation::WasGeneratedBy(WasGeneratedBy {
            namespace,
            id,
            activity,
        });

        let x = operation.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#WasGeneratedBy",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_entity_attach() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = EntityId::from_name("test_entity");
        let agent = AgentId::from_name("test_agent");
        let operation: ChronicleOperation =
            ChronicleOperation::EntityHasEvidence(EntityHasEvidence {
                namespace,
                identityid: None,
                id,
                locator: None,
                agent,
                signature: None,
                signature_time: None,
            });

        let x = operation.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#EntityHasEvidence",
            "http://blockchaintp.com/chronicleoperations/ns#agentName": [
              {
                "@value": "test_agent"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_entity_derive() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = EntityId::from_name("test_entity");
        let used_id = EntityId::from_name("test_used_entity");
        let activity_id = Some(ActivityId::from_name("test_activity"));
        let typ = Some(DerivationType::Revision);
        let operation: ChronicleOperation = ChronicleOperation::EntityDerive(EntityDerive {
            namespace,
            id,
            used_id,
            activity_id,
            typ,
        });

        let x = operation.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#EntityDerive",
            "http://blockchaintp.com/chronicleoperations/ns#activityName": [
              {
                "@value": "test_activity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#derivationType": [
              {
                "@value": "Revision"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#usedEntityName": [
              {
                "@value": "test_used_entity"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_set_attributes_entity() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = EntityId::from_name("test_entity");
        let domain = DomaintypeId::from_name("test_domain");
        let attributes = Attributes {
            typ: Some(domain),
            attributes: BTreeMap::new(),
        };
        let operation: ChronicleOperation =
            ChronicleOperation::SetAttributes(SetAttributes::Entity {
                namespace,
                id,
                attributes,
            });
        let x = operation.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#SetAttributes",
            "http://blockchaintp.com/chronicleoperations/ns#attributes": {
              "@type": "@json",
              "@value": {}
            },
            "http://blockchaintp.com/chronicleoperations/ns#domaintypeId": [
              {
                "@value": "test_domain"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }

    #[tokio::test]
    async fn test_set_attributes_entity_multiple_attributes() {
        let namespace: NamespaceId = NamespaceId::from_name("testns", uuid());
        let id = EntityId::from_name("test_entity");
        let domain = DomaintypeId::from_name("test_domain");
        let attrs = {
            let mut h: BTreeMap<String, Attribute> = BTreeMap::new();

            let attr = Attribute {
                typ: "Bool".to_string(),
                value: json!("Bool"),
            };
            h.insert("bool_attribute".to_string(), attr);

            let attr = Attribute {
                typ: "String".to_string(),
                value: json!("String"),
            };
            h.insert("string_attribute".to_string(), attr);

            let attr = Attribute {
                typ: "Int".to_string(),
                value: json!("Int"),
            };
            h.insert("int_attribute".to_string(), attr);

            h
        };

        let attributes = Attributes {
            typ: Some(domain),
            attributes: attrs,
        };
        let operation: ChronicleOperation =
            ChronicleOperation::SetAttributes(SetAttributes::Entity {
                namespace,
                id,
                attributes,
            });
        let x = operation.to_json();
        let x: serde_json::Value = serde_json::from_str(&x.0.to_string()).unwrap();
        insta::assert_json_snapshot!(&x, @r###"
        [
          {
            "@id": "_:n1",
            "@type": "http://blockchaintp.com/chronicleoperations/ns#SetAttributes",
            "http://blockchaintp.com/chronicleoperations/ns#attributes": {
              "@type": "@json",
              "@value": {
                "Bool": "Bool",
                "Int": "Int",
                "String": "String"
              }
            },
            "http://blockchaintp.com/chronicleoperations/ns#domaintypeId": [
              {
                "@value": "test_domain"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#entityName": [
              {
                "@value": "test_entity"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceName": [
              {
                "@value": "testns"
              }
            ],
            "http://blockchaintp.com/chronicleoperations/ns#namespaceUuid": [
              {
                "@value": "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
              }
            ]
          }
        ]
        "###);
    }
}
