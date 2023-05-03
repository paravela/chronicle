use common::{
    k256::ecdsa::{signature::Signer, Signature, SigningKey},
    ledger::Offset,
    protocol::{create_operation_submission_request, serialize_submission, ProtocolError},
    prov::{ChronicleTransaction, ChronicleTransactionId},
};
use custom_error::custom_error;
use openssl::sha::Sha512;
use prost::Message;
use rand::{prelude::StdRng, Rng, SeedableRng};
use tracing::{debug, instrument};

use crate::{address::PREFIX, sawtooth::event_filter::FilterType};

use super::sawtooth::*;

custom_error! {pub MessageBuilderError
    Serialize{source: serde_cbor::Error}                              = "Could not serialize as CBOR",
}

#[derive(Debug, Clone)]
pub struct MessageBuilder {
    signer: SigningKey,
    family_name: String,
    family_version: String,
    rng: StdRng,
}

impl MessageBuilder {
    #[allow(dead_code)]
    pub fn new(signer: SigningKey, family_name: &str, family_version: &str) -> Self {
        let rng = StdRng::from_entropy();
        Self {
            signer,
            family_name: family_name.to_owned(),
            family_version: family_version.to_owned(),
            rng,
        }
    }

    fn generate_nonce(&mut self) -> String {
        let bytes = self.rng.gen::<[u8; 20]>();
        hex::encode(bytes)
    }

    pub fn get_head_block_id_request() -> ClientBlockGetByNumRequest {
        ClientBlockGetByNumRequest { block_num: 0 }
    }

    #[allow(dead_code)]
    pub fn make_subscription_request(&self, offset: &Offset) -> ClientEventsSubscribeRequest {
        let mut request = ClientEventsSubscribeRequest::default();
        let mut delta_subscription = EventSubscription::default();
        let filter_address = EventFilter {
            key: "address".to_string(),
            match_string: (*PREFIX).to_string(),
            filter_type: FilterType::RegexAll as _,
        };

        delta_subscription.filters = vec![filter_address];
        delta_subscription.event_type = "chronicle/prov-update".to_owned();

        let block_subscription = EventSubscription {
            event_type: "sawtooth/block-commit".to_owned(),
            filters: vec![],
        };

        offset.map(|offset| {
            request.last_known_block_ids = vec![offset.to_string()];
        });

        request.subscriptions = vec![delta_subscription, block_subscription];

        request
    }

    pub fn wrap_tx_as_sawtooth_batch(&self, tx: Transaction) -> Batch {
        let mut batch = Batch::default();

        let mut header = BatchHeader::default();

        let pubkey = hex::encode(self.signer.verifying_key().to_bytes());
        header.transaction_ids = vec![tx.header_signature.clone()];
        header.signer_public_key = pubkey;

        let encoded_header = header.encode_to_vec();
        let s: Signature = self.signer.sign(&encoded_header);
        let s = s.normalize_s().unwrap_or(s);
        let s = hex::encode(s.as_ref());

        debug!(batch_header=?header, batch_header_signature=?s);

        batch.transactions = vec![tx];
        batch.header = encoded_header;
        batch.header_signature = s;
        batch.trace = true;

        batch
    }

    #[instrument]
    pub async fn make_sawtooth_transaction(
        &mut self,
        input_addresses: Vec<String>,
        output_addresses: Vec<String>,
        dependencies: Vec<String>,
        payload: &ChronicleTransaction,
    ) -> Result<(Transaction, ChronicleTransactionId), ProtocolError> {
        let submission = create_operation_submission_request(payload).await?;
        let bytes = serialize_submission(&submission);

        let mut hasher = Sha512::new();
        hasher.update(&bytes);

        let pubkey = hex::encode(self.signer.verifying_key().to_bytes());

        let header = TransactionHeader {
            payload_sha512: hex::encode(hasher.finish()),
            family_name: self.family_name.clone(),
            family_version: self.family_version.clone(),
            nonce: self.generate_nonce(),
            batcher_public_key: pubkey.clone(),
            signer_public_key: pubkey,
            dependencies,
            inputs: input_addresses,
            outputs: output_addresses,
        };

        let encoded_header = header.encode_to_vec();
        let s: Signature = self.signer.sign(&encoded_header);
        let s = s.normalize_s().unwrap_or(s);

        let s = hex::encode(s.to_vec());

        debug!(transaction_header=?header, transaction_header_signature=?s);

        Ok((
            Transaction {
                header: encoded_header,
                header_signature: s.clone(),
                payload: bytes,
            },
            ChronicleTransactionId::from(&*s),
        ))
    }
}

#[cfg(test)]
mod test {
    use common::{
        prov::{
            operations::{ChronicleOperation, CreateNamespace},
            AuthId, ChronicleTransaction, NamespaceId,
        },
        signing::DirectoryStoredKeys,
    };
    use openssl::sha::Sha512;
    use prost::Message;
    use protobuf::Message as ProtoMessage;
    use sawtooth_sdk::messages::{batch::Batch, transaction::TransactionHeader};
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::MessageBuilder;

    #[tokio::test]
    async fn sawtooth_batch_roundtrip() {
        let keystore = DirectoryStoredKeys::new(TempDir::new().unwrap().into_path()).unwrap();
        keystore.generate_chronicle().unwrap();

        let mut builder = MessageBuilder::new(
            keystore.chronicle_signing().unwrap(),
            "external_id",
            "version",
        );

        let uuid = Uuid::new_v4();

        let signed_identity = AuthId::chronicle().signed_identity(&keystore).unwrap();

        let batch = ChronicleTransaction::new(
            vec![ChronicleOperation::CreateNamespace(CreateNamespace {
                id: NamespaceId::from_external_id("t", uuid),
                external_id: "t".into(),
                uuid,
            })],
            signed_identity,
        );

        let input_addresses = vec!["inone".to_owned(), "intwo".to_owned()];
        let output_addresses = vec!["outtwo".to_owned(), "outtwo".to_owned()];
        let dependencies = vec!["dependency".to_owned()];

        let (proto_tx, _id) = builder
            .make_sawtooth_transaction(input_addresses, output_addresses, dependencies, &batch)
            .await
            .unwrap();

        let batch = builder.wrap_tx_as_sawtooth_batch(proto_tx);

        let batch_sdk_parsed: Batch =
            protobuf::Message::parse_from_bytes(&batch.encode_to_vec()).unwrap();

        for tx in batch_sdk_parsed.transactions {
            let header = TransactionHeader::parse_from_bytes(tx.header.as_slice()).unwrap();

            let mut hasher = Sha512::new();
            hasher.update(&tx.payload);
            let computed_hash = hasher.finish();

            assert_eq!(header.payload_sha512, hex::encode(computed_hash));
        }
    }
}
