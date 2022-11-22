use std::{path::PathBuf, pin::Pin, sync::Arc};

use chrono::{DateTime, Utc};
use derivative::*;
use futures::AsyncRead;

use serde::{Deserialize, Serialize};

use crate::{
    attributes::Attributes,
    prov::{
        operations::DerivationType, ActivityId, AgentId, ChronicleIri, ChronicleTransactionId,
        EntityId, ExternalId, ProvModel, Role,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamespaceCommand {
    Create { external_id: ExternalId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyImport {
    FromPath { path: PathBuf },
    FromPEMBuffer { buffer: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyRegistration {
    Generate,
    ImportVerifying(KeyImport),
    ImportSigning(KeyImport),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentCommand {
    Create {
        external_id: ExternalId,
        namespace: ExternalId,
        attributes: Attributes,
    },
    RegisterKey {
        id: AgentId,
        namespace: ExternalId,
        registration: KeyRegistration,
    },
    UseInContext {
        id: AgentId,
        namespace: ExternalId,
    },
    Delegate {
        id: AgentId,
        delegate: AgentId,
        activity: Option<ActivityId>,
        namespace: ExternalId,
        role: Option<Role>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityCommand {
    Create {
        external_id: ExternalId,
        namespace: ExternalId,
        attributes: Attributes,
    },
    Instant {
        id: ActivityId,
        namespace: ExternalId,
        time: Option<DateTime<Utc>>,
        agent: Option<AgentId>,
    },
    Start {
        id: ActivityId,
        namespace: ExternalId,
        time: Option<DateTime<Utc>>,
        agent: Option<AgentId>,
    },
    End {
        id: ActivityId,
        namespace: ExternalId,
        time: Option<DateTime<Utc>>,
        agent: Option<AgentId>,
    },
    Use {
        id: EntityId,
        namespace: ExternalId,
        activity: ActivityId,
    },
    Generate {
        id: EntityId,
        namespace: ExternalId,
        activity: ActivityId,
    },
    WasInformedBy {
        id: ActivityId,
        namespace: ExternalId,
        informing_activity: ActivityId,
    },
    Associate {
        id: ActivityId,
        namespace: ExternalId,
        responsible: AgentId,
        role: Option<Role>,
    },
}

impl ActivityCommand {
    pub fn create(
        external_id: impl AsRef<str>,
        namespace: impl AsRef<str>,
        attributes: Attributes,
    ) -> Self {
        Self::Create {
            external_id: external_id.as_ref().into(),
            namespace: namespace.as_ref().into(),
            attributes,
        }
    }

    pub fn start(
        id: ActivityId,
        namespace: impl AsRef<str>,
        time: Option<DateTime<Utc>>,
        agent: Option<AgentId>,
    ) -> Self {
        Self::Start {
            id,
            namespace: namespace.as_ref().into(),
            time,
            agent,
        }
    }

    pub fn end(
        id: ActivityId,
        namespace: impl AsRef<str>,
        time: Option<DateTime<Utc>>,
        agent: Option<AgentId>,
    ) -> Self {
        Self::End {
            id,
            namespace: namespace.as_ref().into(),
            time,
            agent,
        }
    }

    pub fn instant(
        id: ActivityId,
        namespace: impl AsRef<str>,
        time: Option<DateTime<Utc>>,
        agent: Option<AgentId>,
    ) -> Self {
        Self::End {
            id,
            namespace: namespace.as_ref().into(),
            time,
            agent,
        }
    }

    pub fn r#use(id: EntityId, namespace: impl AsRef<str>, activity: ActivityId) -> Self {
        Self::Use {
            id,
            namespace: namespace.as_ref().into(),
            activity,
        }
    }

    pub fn was_informed_by(
        id: ActivityId,
        namespace: impl AsRef<str>,
        informing_activity: ActivityId,
    ) -> Self {
        Self::WasInformedBy {
            id,
            namespace: namespace.as_ref().into(),
            informing_activity,
        }
    }

    pub fn generate(id: EntityId, namespace: impl AsRef<str>, activity: ActivityId) -> Self {
        Self::Generate {
            id,
            namespace: namespace.as_ref().into(),
            activity,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone)]
pub enum PathOrFile {
    Path(PathBuf),
    File(#[derivative(Debug = "ignore")] Arc<Pin<Box<dyn AsyncRead + Sync + Send>>>), //Non serialisable variant, used in process
}

impl Serialize for PathOrFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PathOrFile::Path(path) => path.serialize(serializer),
            _ => {
                unreachable!()
            }
        }
    }
}

impl<'de> Deserialize<'de> for PathOrFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(PathOrFile::Path(PathBuf::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityCommand {
    Create {
        external_id: ExternalId,
        namespace: ExternalId,
        attributes: Attributes,
    },
    Attach {
        id: EntityId,
        namespace: ExternalId,
        file: PathOrFile,
        locator: Option<String>,
        agent: Option<AgentId>,
    },
    Derive {
        id: EntityId,
        namespace: ExternalId,
        derivation: Option<DerivationType>,
        activity: Option<ActivityId>,
        used_entity: EntityId,
    },
}

impl EntityCommand {
    pub fn create(
        external_id: impl AsRef<str>,
        namespace: impl AsRef<str>,
        attributes: Attributes,
    ) -> Self {
        Self::Create {
            external_id: external_id.as_ref().into(),
            namespace: namespace.as_ref().into(),
            attributes,
        }
    }

    pub fn attach(
        id: EntityId,
        namespace: impl AsRef<str>,
        file: PathOrFile,
        locator: Option<String>,
        agent: Option<AgentId>,
    ) -> Self {
        Self::Attach {
            id,
            namespace: namespace.as_ref().into(),
            file,
            locator,
            agent,
        }
    }

    pub fn detach(
        id: EntityId,
        namespace: impl AsRef<str>,
        derivation: Option<DerivationType>,
        activity: Option<ActivityId>,
        used_entity: EntityId,
    ) -> Self {
        Self::Derive {
            id,
            namespace: namespace.as_ref().into(),
            derivation,
            activity,
            used_entity,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCommand {
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiCommand {
    NameSpace(NamespaceCommand),
    Agent(AgentCommand),
    Activity(ActivityCommand),
    Entity(EntityCommand),
    Query(QueryCommand),
}

#[derive(Debug)]
pub enum ApiResponse {
    /// The api has successfully executed the operation, but has no useful output
    Unit,
    /// The api has validated the command and submitted a transaction to a ledger
    Submission {
        subject: ChronicleIri,
        prov: Box<ProvModel>,
        tx_id: ChronicleTransactionId,
    },
    /// The api has successfully executed the query
    QueryReply { prov: Box<ProvModel> },
}

impl ApiResponse {
    pub fn submission(
        subject: impl Into<ChronicleIri>,
        prov: ProvModel,
        tx_id: ChronicleTransactionId,
    ) -> Self {
        ApiResponse::Submission {
            subject: subject.into(),
            prov: Box::new(prov),
            tx_id,
        }
    }

    pub fn unit() -> Self {
        ApiResponse::Unit
    }

    pub fn query_reply(prov: ProvModel) -> Self {
        ApiResponse::QueryReply {
            prov: Box::new(prov),
        }
    }
}