//! PoP-seal wallet operations.
//!
//! This module implements asset custody where the single-use seals are NOT
//! Bitcoin transaction outputs but entries of a **proof-of-publication
//! ledger** (Peter Todd, *Scalable Semi-Trustless Asset Transfer via
//! Single-Use-Seals and Proof-of-Publication*, 2017), as implemented by the
//! [`pop-ledger`](https://github.com/gofman8/pop-ledger) crates.
//!
//! A seal is a `(ledger position, pubkey)` tuple; transferring an asset
//! closes the sender's seal(s) by publishing a BIP340 signature over the
//! transfer body into the ledger's merkelized key-value tree. Receivers do
//! full client-side validation from genesis: header chain, inclusion proofs,
//! non-publication (single-use) proofs and sum preservation — the ledger
//! operator is trusted only for censorship resistance, never for validity.
//!
//! Seal keys are derived from the wallet mnemonic at `m/9797'/<index>'`, so
//! PoP holdings are recoverable from the wallet backup phrase (the state
//! file caches proofs, which the ledger can re-serve).
//!
//! Flow: [`Wallet::pop_issue_asset`] →
//! [`Wallet::pop_blind_receive`] (receiver) →
//! [`Wallet::pop_send`] (sender publishes closures) → ledger seals the entry
//! → [`Wallet::pop_get_transfer_package`] (sender, out-of-band delivery) →
//! [`Wallet::pop_accept_transfer`] (receiver validates from genesis).

use super::*;

use pop_client::PopClient;
use pop_core::secp256k1::{All, Keypair, Message, Secp256k1, XOnlyPublicKey};
use pop_core::{
    AssetGenesis, InputRef, Output, Publication, SealDef, TokenProof, TransferBody, TransferStep,
    H32,
};

/// File inside the wallet directory holding the PoP state.
const POP_STATE_FILE: &str = "pop_state.json";
/// Hardened BIP32 purpose for PoP seal keys: `m/9797'/<index>'`.
const POP_KEY_PURPOSE: u32 = 9797;
/// Prefix of serialized PoP invoices.
const POP_INVOICE_PREFIX: &str = "utexopop1";

fn pop_err(details: impl ToString) -> Error {
    Error::Pop {
        details: details.to_string(),
    }
}

// ----------------------------------------------------------- public types ---

/// A PoP-issued (or received) asset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopAsset {
    /// Asset ID (hash of the PoP genesis, hex)
    pub asset_id: String,
    /// Asset name
    pub name: String,
    /// Asset ticker
    pub ticker: String,
    /// Decimal precision
    pub precision: u8,
    /// Total issued supply
    pub issued_supply: u64,
    /// Optional RGB contract id this asset is bridged from
    pub rgb_contract: Option<String>,
}

/// A coin: an unspent (or spent) output held under a PoP seal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopCoin {
    /// Asset ID (hex)
    pub asset_id: String,
    /// Amount held by this coin
    pub amount: u64,
    /// Seal pubkey (x-only, hex)
    pub seal_pubkey: String,
    /// Ledger entry index the seal was defined against
    pub defined_at: u64,
    /// Whether the coin is still spendable (its seal is unclosed)
    pub spendable: bool,
}

/// Balance of a PoP asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopBalance {
    /// Sum of spendable coins
    pub settled: u64,
    /// Amounts published for sending but whose transfer package has not been
    /// assembled yet (change in flight)
    pub pending_change: u64,
}

/// Data returned by [`Wallet::pop_blind_receive`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopReceiveData {
    /// Serialized invoice to hand to the sender
    pub invoice: String,
    /// The fresh seal pubkey (x-only, hex) — also the receive identifier
    pub seal_pubkey: String,
    /// Ledger entry index the seal is defined against
    pub defined_at: u64,
}

/// Result of [`Wallet::pop_send`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopSendResult {
    /// Hash of the transfer body (hex) — identifies the in-flight transfer
    pub transfer_id: String,
    /// Ledger entry index the closures will be sealed into
    pub entry_index: u64,
}

/// Result of [`Wallet::pop_accept_transfer`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopReceivedTransfer {
    /// Asset ID (hex)
    pub asset_id: String,
    /// Amount received
    pub amount: u64,
}

/// Status of the ledger the wallet is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopLedgerStatus {
    /// Ledger ID (hex)
    pub ledger_id: String,
    /// Ledger operator pubkey (x-only, hex)
    pub operator_pubkey: String,
    /// Index the currently-open entry will get when sealed
    pub next_index: u64,
}

/// PoP invoice: the receiver's fresh seal plus the ledger it lives on.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopInvoice {
    /// Ledger ID (hex)
    pub ledger_id: H32,
    /// Ledger operator pubkey
    pub operator_pubkey: XOnlyPublicKey,
    /// The receiving seal
    pub seal: SealDef,
}

impl PopInvoice {
    /// Serialize to the compact invoice string handed to the sender.
    pub fn serialize(&self) -> String {
        let json = serde_json::to_string(self).expect("invoice serializes");
        format!(
            "{POP_INVOICE_PREFIX}{}",
            general_purpose::STANDARD_NO_PAD.encode(json)
        )
    }

    /// Parse an invoice string.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let b64 = s
            .strip_prefix(POP_INVOICE_PREFIX)
            .ok_or_else(|| pop_err("invalid PoP invoice prefix"))?;
        let json = general_purpose::STANDARD_NO_PAD
            .decode(b64)
            .map_err(|e| pop_err(format!("invalid PoP invoice encoding: {e}")))?;
        serde_json::from_slice(&json).map_err(|e| pop_err(format!("invalid PoP invoice: {e}")))
    }
}

/// Transfer package delivered out-of-band from sender to receiver.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct PopTransferPackage {
    /// Full client-side-validation proof targeted at the receiver's output
    pub proof: TokenProof,
}

// ---------------------------------------------------------- stored state ---

#[derive(Debug, Clone, Deserialize, Serialize)]
struct StoredCoin {
    asset_id: H32,
    source: InputRef,
    output: Output,
    key_index: u32,
    proof: TokenProof,
    spent: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PendingReceive {
    seal: SealDef,
    key_index: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PendingSend {
    body: TransferBody,
    /// Steps merged from the spent coins' proofs (deduped, topological),
    /// without the new step (which needs the closure witnesses).
    prior_steps: Vec<TransferStep>,
    genesis: AssetGenesis,
    change_key_index: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct PopStore {
    version: u32,
    ledger_id: Option<H32>,
    operator_pubkey: Option<XOnlyPublicKey>,
    assets: Vec<AssetGenesis>,
    coins: Vec<StoredCoin>,
    pending_receives: Vec<PendingReceive>,
    pending_sends: Vec<PendingSend>,
    next_key_index: u32,
}

impl PopStore {
    fn asset(&self, asset_id: &H32) -> Option<&AssetGenesis> {
        self.assets.iter().find(|g| g.asset_id() == *asset_id)
    }
}

// ------------------------------------------------------------- internals ---

impl Wallet {
    fn pop_state_path(&self) -> PathBuf {
        self.internals.wallet_dir.join(POP_STATE_FILE)
    }

    fn pop_load_store(&self) -> Result<PopStore, Error> {
        let path = self.pop_state_path();
        if !path.exists() {
            return Ok(PopStore::default());
        }
        let json = fs::read_to_string(&path)?;
        serde_json::from_str(&json).map_err(|e| pop_err(format!("corrupt PoP state: {e}")))
    }

    fn pop_save_store(&self, store: &PopStore) -> Result<(), Error> {
        let path = self.pop_state_path();
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(store).map_err(pop_err)?)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Derive the PoP seal keypair at `m/9797'/<index>'` from the wallet
    /// mnemonic.
    fn pop_derive_keypair(&self, secp: &Secp256k1<All>, index: u32) -> Result<Keypair, Error> {
        let mnemonic_str = self.keys.mnemonic.as_ref().ok_or(Error::WatchOnly)?;
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)?;
        let bitcoin_network = self.internals.wallet_data.bitcoin_network;
        let master_xprv =
            Xpriv::new_master(bitcoin_network, &mnemonic.to_seed("")).map_err(pop_err)?;
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(POP_KEY_PURPOSE).expect("valid child number"),
            ChildNumber::from_hardened_idx(index).map_err(pop_err)?,
        ]);
        let derived = master_xprv.derive_priv(secp, &path).map_err(pop_err)?;
        Ok(Keypair::from_secret_key(secp, &derived.private_key))
    }

    /// Derive a fresh seal against the ledger's currently-open entry,
    /// advancing the key index in `store`.
    fn pop_fresh_seal(
        &self,
        secp: &Secp256k1<All>,
        store: &mut PopStore,
        next_index: u64,
    ) -> Result<(u32, SealDef), Error> {
        let key_index = store.next_key_index;
        store.next_key_index += 1;
        let keypair = self.pop_derive_keypair(secp, key_index)?;
        Ok((
            key_index,
            SealDef {
                pubkey: keypair.x_only_public_key().0,
                defined_at: next_index,
            },
        ))
    }

    /// Bind the wallet to the client's ledger on first use; afterwards verify
    /// every call talks to the same ledger.
    fn pop_bind_ledger(
        &self,
        client: &dyn PopClient,
        store: &mut PopStore,
    ) -> Result<pop_core::LedgerInfo, Error> {
        let info = client.info().map_err(pop_err)?;
        match (&store.ledger_id, &store.operator_pubkey) {
            (None, _) => {
                store.ledger_id = Some(info.ledger_id);
                store.operator_pubkey = Some(info.operator_pubkey);
            }
            (Some(id), Some(op)) => {
                if *id != info.ledger_id || *op != info.operator_pubkey {
                    return Err(pop_err(
                        "PoP client points to a different ledger than this wallet is bound to",
                    ));
                }
            }
            _ => return Err(pop_err("corrupt PoP state: partial ledger binding")),
        }
        Ok(info)
    }

    /// Merge the steps of several proofs, deduplicating by body hash while
    /// preserving topological order.
    fn pop_merge_steps(proofs: &[&TokenProof]) -> Vec<TransferStep> {
        let mut seen: HashSet<H32> = HashSet::new();
        let mut merged = Vec::new();
        for proof in proofs {
            for step in &proof.steps {
                if seen.insert(step.body.msg_hash()) {
                    merged.push(step.clone());
                }
            }
        }
        merged
    }
}

#[cfg(test)]
impl Wallet {
    /// Test-only access to seal key derivation.
    pub(crate) fn pop_test_derive_keypair(&self, index: u32) -> Keypair {
        self.pop_derive_keypair(&Secp256k1::new(), index).unwrap()
    }
}

// ------------------------------------------------------------ public API ---

impl Wallet {
    /// Return the status of the PoP ledger `client` points to, binding this
    /// wallet to it on first use.
    pub fn pop_ledger_status(&self, client: &dyn PopClient) -> Result<PopLedgerStatus, Error> {
        let mut store = self.pop_load_store()?;
        let info = self.pop_bind_ledger(client, &mut store)?;
        self.pop_save_store(&store)?;
        Ok(PopLedgerStatus {
            ledger_id: info.ledger_id.to_string(),
            operator_pubkey: info.operator_pubkey.to_string(),
            next_index: info.next_index,
        })
    }

    /// Issue a new PoP-native asset, assigning each amount in `amounts` to a
    /// fresh wallet-derived seal.
    ///
    /// Like an RGB genesis, issuance needs no publication: the genesis itself
    /// defines the initial outputs; only transfers close seals.
    pub fn pop_issue_asset(
        &self,
        client: &dyn PopClient,
        name: String,
        ticker: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<PopAsset, Error> {
        if amounts.is_empty() || amounts.contains(&0) {
            return Err(pop_err("issuance amounts must be non-empty and non-zero"));
        }
        let secp = Secp256k1::new();
        let mut store = self.pop_load_store()?;
        let info = self.pop_bind_ledger(client, &mut store)?;

        let mut outputs = Vec::with_capacity(amounts.len());
        let mut key_indices = Vec::with_capacity(amounts.len());
        for amount in &amounts {
            let (key_index, seal) = self.pop_fresh_seal(&secp, &mut store, info.next_index)?;
            key_indices.push(key_index);
            outputs.push(Output {
                seal,
                amount: *amount,
            });
        }
        let genesis = AssetGenesis {
            ledger_id: info.ledger_id,
            name: name.clone(),
            ticker: ticker.clone(),
            precision,
            outputs: outputs.clone(),
            rgb_contract: None,
            timestamp: now().unix_timestamp() as u64,
        };
        let issued_supply = genesis
            .supply()
            .ok_or_else(|| pop_err("issuance overflows u64"))?;
        let asset_id = genesis.asset_id();

        for (vout, (output, key_index)) in outputs.iter().zip(key_indices).enumerate() {
            let target = InputRef {
                source: asset_id,
                vout: vout as u32,
            };
            store.coins.push(StoredCoin {
                asset_id,
                source: target,
                output: *output,
                key_index,
                proof: TokenProof {
                    genesis: genesis.clone(),
                    steps: vec![],
                    target,
                },
                spent: false,
            });
        }
        store.assets.push(genesis);
        self.pop_save_store(&store)?;
        info!(self.internals.logger, "PoP asset issued: {asset_id}");
        Ok(PopAsset {
            asset_id: asset_id.to_string(),
            name,
            ticker,
            precision,
            issued_supply,
            rgb_contract: None,
        })
    }

    /// Create a fresh receiving seal and return the invoice to hand to the
    /// sender (the PoP analogue of `blind_receive`).
    pub fn pop_blind_receive(&self, client: &dyn PopClient) -> Result<PopReceiveData, Error> {
        let secp = Secp256k1::new();
        let mut store = self.pop_load_store()?;
        let info = self.pop_bind_ledger(client, &mut store)?;
        let (key_index, seal) = self.pop_fresh_seal(&secp, &mut store, info.next_index)?;
        store.pending_receives.push(PendingReceive { seal, key_index });
        self.pop_save_store(&store)?;
        let invoice = PopInvoice {
            ledger_id: info.ledger_id,
            operator_pubkey: info.operator_pubkey,
            seal,
        };
        Ok(PopReceiveData {
            invoice: invoice.serialize(),
            seal_pubkey: seal.pubkey.to_string(),
            defined_at: seal.defined_at,
        })
    }

    /// Send `amount` of `asset_id` to a [`PopInvoice`]: coin-select, build
    /// the transfer body (recipient output + change output when needed) and
    /// close every input seal by publishing its signature to the ledger.
    ///
    /// The closures become final when the ledger seals the entry; then
    /// [`Wallet::pop_get_transfer_package`] assembles the proof for the
    /// receiver.
    pub fn pop_send(
        &self,
        client: &dyn PopClient,
        invoice: &str,
        asset_id: &str,
        amount: u64,
    ) -> Result<PopSendResult, Error> {
        if amount == 0 {
            return Err(pop_err("amount must be non-zero"));
        }
        let invoice = PopInvoice::parse(invoice)?;
        let asset_id: H32 = asset_id
            .parse()
            .map_err(|_| pop_err("invalid PoP asset id"))?;
        let secp = Secp256k1::new();
        let mut store = self.pop_load_store()?;
        let info = self.pop_bind_ledger(client, &mut store)?;
        if invoice.ledger_id != info.ledger_id || invoice.operator_pubkey != info.operator_pubkey {
            return Err(pop_err("invoice belongs to a different PoP ledger"));
        }
        let genesis = store
            .asset(&asset_id)
            .ok_or_else(|| pop_err("unknown PoP asset"))?
            .clone();

        // coin selection: accumulate spendable coins until amount is covered
        let mut selected: Vec<usize> = vec![];
        let mut input_sum: u64 = 0;
        for (i, coin) in store.coins.iter().enumerate() {
            if coin.spent || coin.asset_id != asset_id {
                continue;
            }
            selected.push(i);
            input_sum = input_sum
                .checked_add(coin.output.amount)
                .ok_or_else(|| pop_err("input sum overflows u64"))?;
            if input_sum >= amount {
                break;
            }
        }
        if input_sum < amount {
            #[cfg(any(feature = "electrum", feature = "esplora"))]
            return Err(Error::InsufficientAssignments {
                asset_id: asset_id.to_string(),
                available: AssignmentsCollection {
                    fungible: input_sum,
                    ..Default::default()
                },
            });
            #[cfg(not(any(feature = "electrum", feature = "esplora")))]
            return Err(pop_err(format!(
                "insufficient assignments: available {input_sum}, needed {amount}"
            )));
        }

        // outputs: recipient at vout 0, change (if any) at vout 1
        let mut outputs = vec![Output {
            seal: invoice.seal,
            amount,
        }];
        let change = input_sum - amount;
        let mut change_key_index = None;
        if change > 0 {
            let (key_index, seal) = self.pop_fresh_seal(&secp, &mut store, info.next_index)?;
            change_key_index = Some(key_index);
            outputs.push(Output {
                seal,
                amount: change,
            });
        }
        let body = TransferBody {
            asset_id,
            inputs: selected
                .iter()
                .map(|&i| store.coins[i].source)
                .collect(),
            outputs,
            rgb_commitment: None,
        };
        let msg = body.msg_hash();

        // sign the body with every input seal key, then publish the closures;
        // record the pending send FIRST so a crash cannot lose burned seals
        let mut publications = Vec::with_capacity(selected.len());
        for &i in &selected {
            let coin = &store.coins[i];
            let keypair = self.pop_derive_keypair(&secp, coin.key_index)?;
            let sig = secp.sign_schnorr(&Message::from_digest(*msg.as_bytes()), &keypair);
            publications.push(Publication {
                pubkey: coin.output.seal.pubkey,
                msg_hash: msg,
                sig,
            });
        }
        let prior_steps =
            Self::pop_merge_steps(&selected.iter().map(|&i| &store.coins[i].proof).collect::<Vec<_>>());
        for &i in &selected {
            store.coins[i].spent = true;
        }
        store.pending_sends.push(PendingSend {
            body,
            prior_steps,
            genesis,
            change_key_index,
        });
        self.pop_save_store(&store)?;

        let mut entry_index = info.next_index;
        for publication in publications {
            entry_index = client.publish(publication).map_err(pop_err)?;
        }
        info!(self.internals.logger, "PoP transfer published: {msg}");
        Ok(PopSendResult {
            transfer_id: msg.to_string(),
            entry_index,
        })
    }

    /// Assemble the transfer package for the receiver once the ledger has
    /// sealed the entry containing the closures of transfer `transfer_id`
    /// (returned by [`Wallet::pop_send`]).
    ///
    /// Also materializes the change coin (with its own proof) in the wallet.
    /// Errors if the entry is not sealed yet — retry after the ledger's next
    /// heartbeat.
    pub fn pop_get_transfer_package(
        &self,
        client: &dyn PopClient,
        transfer_id: &str,
    ) -> Result<String, Error> {
        let transfer_id: H32 = transfer_id
            .parse()
            .map_err(|_| pop_err("invalid transfer id"))?;
        let secp = Secp256k1::new();
        let mut store = self.pop_load_store()?;
        let operator_pubkey = store
            .operator_pubkey
            .ok_or_else(|| pop_err("wallet not bound to a PoP ledger"))?;
        let pending_idx = store
            .pending_sends
            .iter()
            .position(|p| p.body.msg_hash() == transfer_id)
            .ok_or_else(|| pop_err("unknown transfer id"))?;
        let pending = store.pending_sends[pending_idx].clone();

        // fetch the closure witness of every input seal
        let mut closes = Vec::with_capacity(pending.body.inputs.len());
        for input in &pending.body.inputs {
            let coin = store
                .coins
                .iter()
                .find(|c| c.source == *input)
                .ok_or_else(|| pop_err("corrupt PoP state: missing input coin"))?;
            let witness = client
                .find_witness(&coin.output.seal.pubkey, coin.output.seal.defined_at)
                .map_err(pop_err)?
                .ok_or_else(|| {
                    pop_err("entry not sealed yet — retry after the ledger's next heartbeat")
                })?;
            closes.push(witness);
        }

        let mut steps = pending.prior_steps.clone();
        steps.push(TransferStep {
            body: pending.body.clone(),
            closes,
        });
        let proof = TokenProof {
            genesis: pending.genesis.clone(),
            steps,
            target: InputRef {
                source: transfer_id,
                vout: 0,
            },
        };
        // sanity: never hand out a package that does not verify
        pop_core::verify_token_proof(&secp, &operator_pubkey, &proof)
            .map_err(|e| pop_err(format!("assembled package fails validation: {e}")))?;

        // materialize the change coin
        if let Some(change_key_index) = pending.change_key_index {
            let change_target = InputRef {
                source: transfer_id,
                vout: 1,
            };
            let change_proof = TokenProof {
                target: change_target,
                ..proof.clone()
            };
            pop_core::verify_token_proof(&secp, &operator_pubkey, &change_proof)
                .map_err(|e| pop_err(format!("change proof fails validation: {e}")))?;
            store.coins.push(StoredCoin {
                asset_id: pending.body.asset_id,
                source: change_target,
                output: pending.body.outputs[1],
                key_index: change_key_index,
                proof: change_proof,
                spent: false,
            });
        }
        store.pending_sends.remove(pending_idx);
        self.pop_save_store(&store)?;

        serde_json::to_string(&PopTransferPackage { proof }).map_err(pop_err)
    }

    /// Validate an incoming transfer package (full client-side validation
    /// from genesis: header chain, inclusion, non-publication, sums) and, if
    /// the target output pays one of this wallet's pending receives, store
    /// the coin.
    pub fn pop_accept_transfer(&self, package: &str) -> Result<PopReceivedTransfer, Error> {
        let secp = Secp256k1::new();
        let mut store = self.pop_load_store()?;
        let operator_pubkey = store
            .operator_pubkey
            .ok_or_else(|| pop_err("wallet not bound to a PoP ledger"))?;
        let ledger_id = store
            .ledger_id
            .ok_or_else(|| pop_err("wallet not bound to a PoP ledger"))?;
        let package: PopTransferPackage =
            serde_json::from_str(package).map_err(|e| pop_err(format!("invalid package: {e}")))?;
        if package.proof.genesis.ledger_id != ledger_id {
            return Err(pop_err("package belongs to a different PoP ledger"));
        }

        let verified = pop_core::verify_token_proof(&secp, &operator_pubkey, &package.proof)
            .map_err(|e| pop_err(format!("package fails validation: {e}")))?;

        let receive_idx = store
            .pending_receives
            .iter()
            .position(|r| r.seal == verified.output.seal)
            .ok_or_else(|| pop_err("target output does not pay any pending receive"))?;
        let receive = store.pending_receives.remove(receive_idx);

        if store.asset(&verified.asset_id).is_none() {
            store.assets.push(package.proof.genesis.clone());
        }
        store.coins.push(StoredCoin {
            asset_id: verified.asset_id,
            source: package.proof.target,
            output: verified.output,
            key_index: receive.key_index,
            proof: package.proof,
            spent: false,
        });
        self.pop_save_store(&store)?;
        info!(
            self.internals.logger,
            "PoP transfer accepted: {} of {}", verified.output.amount, verified.asset_id
        );
        Ok(PopReceivedTransfer {
            asset_id: verified.asset_id.to_string(),
            amount: verified.output.amount,
        })
    }

    /// List the wallet's PoP assets.
    pub fn pop_list_assets(&self) -> Result<Vec<PopAsset>, Error> {
        let store = self.pop_load_store()?;
        Ok(store
            .assets
            .iter()
            .map(|g| PopAsset {
                asset_id: g.asset_id().to_string(),
                name: g.name.clone(),
                ticker: g.ticker.clone(),
                precision: g.precision,
                issued_supply: g.supply().unwrap_or(u64::MAX),
                rgb_contract: g.rgb_contract.clone(),
            })
            .collect())
    }

    /// List the wallet's PoP coins, optionally filtered by asset.
    pub fn pop_list_coins(&self, asset_id: Option<String>) -> Result<Vec<PopCoin>, Error> {
        let filter: Option<H32> = match asset_id {
            Some(s) => Some(s.parse().map_err(|_| pop_err("invalid PoP asset id"))?),
            None => None,
        };
        let store = self.pop_load_store()?;
        Ok(store
            .coins
            .iter()
            .filter(|c| filter.is_none_or(|f| c.asset_id == f))
            .map(|c| PopCoin {
                asset_id: c.asset_id.to_string(),
                amount: c.output.amount,
                seal_pubkey: c.output.seal.pubkey.to_string(),
                defined_at: c.output.seal.defined_at,
                spendable: !c.spent,
            })
            .collect())
    }

    /// Balance of a PoP asset.
    pub fn pop_get_asset_balance(&self, asset_id: &str) -> Result<PopBalance, Error> {
        let asset_id: H32 = asset_id
            .parse()
            .map_err(|_| pop_err("invalid PoP asset id"))?;
        let store = self.pop_load_store()?;
        let settled = store
            .coins
            .iter()
            .filter(|c| !c.spent && c.asset_id == asset_id)
            .map(|c| c.output.amount)
            .sum();
        let pending_change = store
            .pending_sends
            .iter()
            .filter(|p| p.body.asset_id == asset_id)
            .flat_map(|p| p.body.outputs.get(1))
            .map(|o| o.amount)
            .sum();
        Ok(PopBalance {
            settled,
            pending_change,
        })
    }
}
