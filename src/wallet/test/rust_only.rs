use super::*;

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // prepare PSBT
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let mut psbt_copy = psbt.clone();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(psbt.proprietary.is_empty());

    // color PSBT
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    let vout = output.0 as u32;
    output_map.insert(vout, AMOUNT); // sending AMOUNT since color_psbt doesn't support change
    let asset_coloring_info = AssetColoringInfo {
        output_map,
            blinded_map: std::collections::HashMap::new(),
        static_blinding: Some(blinding),
        output_blinding: HashMap::new(),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info.clone())
        .unwrap();

    // check PSBT
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(!psbt.proprietary.is_empty());
    let vout = vout + 1;

    // check fascia
    assert_eq!(fascia.bundles().len(), 1);
    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let im_keys = bundle.input_map.keys();
    assert_eq!(im_keys.len(), 1);
    let mut transitions = bundle.known_transitions.iter().map(|kt| &kt.transition);
    assert_eq!(transitions.len(), 1);
    let transition = transitions.next().unwrap();
    let assignments = &transition.assignments;
    assert_eq!(assignments.len(), 1);
    let (_, fungible) = assignments.iter().next().unwrap();
    let fungible = fungible.as_fungible();
    assert_eq!(fungible.len(), 1);
    let fungible = fungible.first().unwrap();
    let seal = fungible.revealed_seal().unwrap();
    let state = fungible.as_revealed_state();
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), vout);
    assert_eq!(seal.blinding, blinding);
    assert_eq!(state.as_u64(), AMOUNT);

    // check beneficiaries
    assert_eq!(beneficiaries.len(), 1);
    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), vout);
    assert_eq!(seal.blinding, blinding);

    // color PSBT and consume
    let transfers = party_send
        .wallet
        .color_psbt_and_consume(&mut psbt_copy, coloring_info)
        .unwrap();

    // check that the two color_psbt* methods produce matching PSBTs (no additional changes)
    assert_eq!(psbt, psbt_copy);

    // push consignment to proxy
    let txid = psbt_copy.unsigned_tx.compute_txid().to_string();
    let transfers_dir = party_send.wallet.get_transfers_dir().join(&txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    assert_eq!(transfers.len(), 1);
    transfers
        .first()
        .unwrap()
        .save_file(&consignment_path)
        .unwrap();
    party_send
        .wallet
        .post_consignment(
            PROXY_URL,
            txid.clone(),
            consignment_path,
            txid.clone(),
            Some(vout),
        )
        .unwrap();

    // accept transfer
    let consignment_endpoint = RgbTransport::from_str(&PROXY_ENDPOINT).unwrap();
    recv_party
        .wallet
        .accept_transfer(txid.clone(), vout, consignment_endpoint, blinding)
        .unwrap();

    // consume fascia
    party_send.wallet.consume_fascia(fascia, None).unwrap();
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_unspents_vanilla_success() {
    initialize();

    // wallets
    let mut party = get_empty_party!();

    // no unspents
    let bak_info_before = party.db_backup_info_opt();
    assert!(bak_info_before.is_none());
    let unspent_list = party.list_unspents_vanilla(None);
    let bak_info_after = party.db_backup_info_opt();
    assert!(bak_info_after.is_none());
    assert_eq!(unspent_list.len(), 0);

    let _guard = stop_mining();

    send_to_address(party.get_address());

    // one unspent, no confirmations
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 0);
    let unspent_list = party.list_unspents_vanilla(Some(0));
    assert_eq!(unspent_list.len(), 1);

    drop(_guard);
    mine(false);

    // one unspent, 1 confirmation
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 1);
    let unspent_list = party.list_unspents_vanilla(Some(0));
    assert_eq!(unspent_list.len(), 1);

    party.create_utxos_default();

    // one unspent (change), colored unspents not listed
    mine(false);
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_unspents_vanilla_skip_sync() {
    initialize();

    let mut party = get_empty_party!();

    fund_wallet(party.get_address());

    // no unspents if skipping sync
    let unspents = party
        .wallet
        .list_unspents_vanilla(party.online, MIN_CONFIRMATIONS, true)
        .unwrap();
    assert_eq!(unspents.len(), 0);

    // 1 unspent after manually syncing
    party
        .wallet
        .sync(
            party.online,
            SyncOptions {
                keychain: SyncKeychain::Vanilla {
                    lookback: INDEXER_SYNC_LOOKBACK as u32,
                },
                strategy: SyncStrategy::FastSync,
            },
        )
        .unwrap();
    let unspents = party
        .wallet
        .list_unspents_vanilla(party.online, MIN_CONFIRMATIONS, true)
        .unwrap();
    assert_eq!(unspents.len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn save_new_asset_success() {
    initialize();
    let asset_amount: u64 = 66;

    // wallets
    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();

    // NIA
    let nia_asset = party.issue_asset_nia(None);
    party.check_save_new_asset(
        &mut rcv_party,
        &nia_asset.asset_id,
        Assignment::Fungible(asset_amount),
    );
    assert!(rcv_party.db_check_asset_exists(&nia_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&nia_asset.asset_id);
    assert_eq!(asset_model.id, nia_asset.asset_id);
    assert_eq!(asset_model.initial_supply, AMOUNT.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert_eq!(asset_model.ticker.unwrap(), TICKER);
    assert_eq!(asset_model.schema, AssetSchema::Nia);

    // CFA
    let cfa_asset = party.issue_asset_cfa(None, None);
    party.check_save_new_asset(
        &mut rcv_party,
        &cfa_asset.asset_id,
        Assignment::Fungible(asset_amount),
    );
    assert!(rcv_party.db_check_asset_exists(&cfa_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&cfa_asset.asset_id);
    assert_eq!(asset_model.id, cfa_asset.asset_id);
    assert_eq!(asset_model.initial_supply, AMOUNT.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert!(asset_model.ticker.is_none());
    assert_eq!(asset_model.schema, AssetSchema::Cfa);

    // UDA
    let image_str = ["tests", "qrcode.png"].join(MAIN_SEPARATOR_STR);
    let uda_asset =
        party.issue_asset_uda(Some(DETAILS), Some(FILE_STR), vec![&image_str, FILE_STR]);
    party.create_utxos(false, None, None, FEE_RATE, None);
    party.check_save_new_asset(&mut rcv_party, &uda_asset.asset_id, Assignment::NonFungible);
    assert!(rcv_party.db_check_asset_exists(&uda_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&uda_asset.asset_id);
    assert_eq!(asset_model.id, uda_asset.asset_id);
    assert_eq!(asset_model.initial_supply, 1.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert_eq!(asset_model.ticker.unwrap(), TICKER);
    assert_eq!(asset_model.schema, AssetSchema::Uda);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_uda() {
    initialize();

    let nonce = 42u64;

    // wallets
    let mut party_send = get_funded_noutxo_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    let mut recv_party = get_empty_party!();
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    // create a custom BDK wallet with p2wpkh descriptor to avoid p2tr outputs,
    // so that the OP_RETURN is appended at the end
    let mnemonic = Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    let custom_bdk_wallet =
        BdkWallet::create(format!("wpkh({xprv}/0/*)"), format!("wpkh({xprv}/1/*)"))
            .network(BdkNetwork::Regtest)
            .create_wallet_no_persist()
            .unwrap();
    let p2wpkh_addr = custom_bdk_wallet
        .peek_address(KeychainKind::External, 0)
        .address;

    // prepare PSBT: drain all wallet UTXOs to the p2wpkh address (no p2tr outputs, no change)
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .drain_wallet()
        .drain_to(p2wpkh_addr.script_pubkey())
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(psbt.proprietary.is_empty());

    // color PSBT
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    output_map.insert(0u32, 1u64); // UDA: assign to vout 0, amount 1
    let asset_coloring_info = AssetColoringInfo {
        output_map,
            blinded_map: std::collections::HashMap::new(),
        static_blinding: None,
        output_blinding: HashMap::new(),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: None,
        nonce: Some(nonce),
    };
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();

    // check PSBT: OP_RETURN is appended at the end
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(!psbt.proprietary.is_empty());
    assert!(
        psbt.unsigned_tx
            .output
            .last()
            .unwrap()
            .script_pubkey
            .is_op_return()
    );

    // check fascia
    assert_eq!(fascia.bundles().len(), 1);
    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let im_keys = bundle.input_map.keys();
    assert_eq!(im_keys.len(), 1);
    let mut transitions = bundle.known_transitions.iter().map(|kt| &kt.transition);
    assert_eq!(transitions.len(), 1);
    let transition = transitions.next().unwrap();
    let assignments = &transition.assignments;
    assert_eq!(assignments.len(), 1);
    let (_, structured) = assignments.iter().next().unwrap();
    let structured = structured.as_structured();
    assert_eq!(structured.len(), 1);
    let seal = structured.first().unwrap().revealed_seal().unwrap();
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), 0);

    // check beneficiaries
    assert_eq!(beneficiaries.len(), 1);
    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), 0);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_fail() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // prepare PSBT
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();

    // prepare coloring data
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);

    // wrong contract ID
    let fake_cid = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E";
    let asset_coloring_info = AssetColoringInfo {
        output_map: output_map.clone(),
            blinded_map: std::collections::HashMap::new(),
        static_blinding: Some(blinding),
        output_blinding: HashMap::new(),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> =
        HashMap::from_iter([(ContractId::from_str(fake_cid).unwrap(), asset_coloring_info)]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert!(
        matches!(result, Err(Error::Internal { details: m }) if m.contains(&format!("contract {fake_cid} is unknown")))
    );

    // wrong output map vout
    let fake_o_map: HashMap<u32, u64> = HashMap::from_iter([(666, AMOUNT)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map: fake_o_map,
            blinded_map: std::collections::HashMap::new(),
        static_blinding: Some(blinding),
        output_blinding: HashMap::new(),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "invalid vout in output_map, does not exist in the given PSBT";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));

    // wrong output map amount
    let fake_o_map = output_map.keys().map(|k| (*k, 999u64)).collect();
    let asset_coloring_info = AssetColoringInfo {
        output_map: fake_o_map,
            blinded_map: std::collections::HashMap::new(),
        static_blinding: Some(blinding),
        output_blinding: HashMap::new(),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info.clone());
    let msg = "total amount in output_map (999) greater than available (666)";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn post_consignment_fail() {
    initialize();

    // wallets
    let party = get_empty_party!();

    // fake data
    let fake_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let transfers_dir = party.wallet.get_transfers_dir().join(fake_txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    std::fs::File::create(&consignment_path).unwrap();

    // proxy error
    let invalid_proxy_url = "http://127.6.6.6:7777/json-rpc";
    let result = party.wallet.post_consignment(
        invalid_proxy_url,
        fake_txid.to_string(),
        consignment_path.clone(),
        fake_txid.to_string(),
        Some(0),
    );
    assert_matches!(
        result,
        Err(Error::Proxy { details: m })
        if m.contains("error sending request for url")
            || m.contains("request or response body error for url"));

    // invalid transport endpoint
    let invalid_proxy_url = &format!("http://{PROXY_HOST_MOD_API}");
    let result = party.wallet.post_consignment(
        invalid_proxy_url,
        fake_txid.to_string(),
        consignment_path.clone(),
        fake_txid.to_string(),
        Some(0),
    );
    assert!(
        matches!(result, Err(Error::InvalidTransportEndpoint { details: m }) if m == "invalid result")
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_indexer_url_electrum_success() {
    initialize();

    let result = check_indexer_url(ELECTRUM_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Electrum));

    let result = check_indexer_url(ELECTRUM_2_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Electrum));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_indexer_url_electrum_fail() {
    initialize();

    let result = check_indexer_url(ELECTRUM_BLOCKSTREAM_URL, BitcoinNetwork::Regtest);
    let verbose_unsupported =
        "verbose transactions are unsupported by the provided electrum service";
    assert_matches!(result, Err(Error::InvalidIndexer { details: m }) if m.contains(verbose_unsupported));
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn check_indexer_url_esplora_success() {
    initialize();

    let result = check_indexer_url(ESPLORA_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Esplora));
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn check_indexer_url_esplora_fail() {
    initialize();

    let result = check_indexer_url(PROXY_URL, BitcoinNetwork::Regtest);
    let invalid_indexer = s!("not a valid electrum nor esplora server");
    assert_matches!(result, Err(Error::InvalidIndexer { details: m }) if m == invalid_indexer);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_proxy_url_success() {
    initialize();

    assert!(check_proxy_url(PROXY_URL).is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_proxy_url_fail() {
    initialize();

    let result = check_proxy_url(PROXY_URL_MOD_PROTO);
    assert_matches!(result, Err(Error::InvalidProxyProtocol { version: _ }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn accept_transfer_fail() {
    initialize();

    let mut party = get_empty_party!();

    // invalid txid
    let consignment_endpoint = RgbTransport::from_str(&PROXY_ENDPOINT).unwrap();
    let result = party
        .wallet
        .accept_transfer(s!("invalidTxid"), 0, consignment_endpoint, 0);
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn get_tx_height_fail() {
    initialize();

    let party = get_empty_party!();

    // invalid txid
    let result = party.wallet.get_tx_height(s!("invalidTxid"));
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_success() {
    initialize();

    let party = get_empty_party!();

    let result = party.wallet.update_witnesses(0, vec![]);
    assert!(result.is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn upsert_witness_success() {
    initialize();

    let party = get_empty_party!();

    let result = party
        .wallet
        .upsert_witness(RgbTxid::from_str(FAKE_TXID).unwrap(), WitnessOrd::Tentative);
    assert!(result.is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn create_consignments_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let psbt = party.send_begin_result(&recipient_map).unwrap().psbt;
    let result = party.wallet.create_consignments(psbt.clone());
    assert!(result.is_ok());
    let psbt = Psbt::from_str(&psbt).unwrap();
    let txid = psbt.extract_tx().unwrap().compute_txid().to_string();
    let consignment_path = party
        .wallet
        .get_asset_transfer_dir(party.wallet.get_transfers_dir().join(txid), &asset.asset_id)
        .join(CONSIGNMENT_FILE);
    assert!(consignment_path.is_file());
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_success() {
    initialize();

    let amount: u64 = 66;
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);

    let send_result = party.send_result(&recipient_map).unwrap();
    let txid = send_result.txid;
    assert!(!txid.is_empty());

    let (_, asset_transfer, _) = party.get_test_transfer_sender(&txid);
    let asset_id = asset_transfer.asset_id.clone().unwrap();
    let consignment_pathbuf = party.wallet.get_send_consignment_path(&asset_id, &txid);
    let consignment_path = consignment_pathbuf.to_string_lossy();

    let indexer_url = if cfg!(feature = "electrum") {
        ELECTRUM_URL
    } else {
        ESPLORA_URL
    };

    let result = validate_consignment_offchain(
        consignment_path.as_ref(),
        &txid,
        indexer_url,
        BitcoinNetwork::Regtest,
    )
    .unwrap();

    assert!(
        result.valid,
        "offchain validation should succeed for consignment with bundled witness"
    );
    assert!(result.error.is_none());
    assert!(result.details.is_none());
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_invalid_txid() {
    initialize();

    let amount: u64 = 66;
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);

    let send_result = party.send_result(&recipient_map).unwrap();
    let txid = send_result.txid;
    let (_, asset_transfer, _) = party.get_test_transfer_sender(&txid);
    let asset_id = asset_transfer.asset_id.clone().unwrap();
    let consignment_pathbuf = party.wallet.get_send_consignment_path(&asset_id, &txid);
    let consignment_path = consignment_pathbuf.to_string_lossy();

    let indexer_url = if cfg!(feature = "electrum") {
        ELECTRUM_URL
    } else {
        ESPLORA_URL
    };

    let result = validate_consignment_offchain(
        consignment_path.as_ref(),
        "not-a-valid-txid",
        indexer_url,
        BitcoinNetwork::Regtest,
    );

    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_file_not_found() {
    initialize();

    let indexer_url = if cfg!(feature = "electrum") {
        ELECTRUM_URL
    } else {
        ESPLORA_URL
    };

    let result = validate_consignment_offchain(
        "/nonexistent/path/consignment.rgb",
        "e5a3e577309df31bd606f48049049d2e1e02b048206ba232944fcc053a176ccb",
        indexer_url,
        BitcoinNetwork::Regtest,
    );

    assert_matches!(result, Err(Error::Internal { details: _ }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn offline() {
    initialize();

    let mut wallet = get_test_wallet(true, None);
    let result = wallet.list_unspents_vanilla(Online { id: 0 }, MIN_CONFIRMATIONS, false);
    assert_matches!(result, Err(Error::Offline));
}

// --- carrier-stash resolver invariant (E7) ---------------------------------------------------
//
// An un-broadcast ("Tentative") colored branch — a colored TES-R ladder rung, or the un-broadcast
// side of an off-chain split — must survive `update_witnesses` with the plain blockchain
// resolver.
// Before the guard, one such call archived every rung of the branch: `succeeded=2`, no error, and
// `get_asset_balance` unchanged, because the balance is computed from the sqlite tables while the
// destruction happens in the RGB stock. Every assertion below therefore probes the STOCK with a
// read-only `color_psbt` dry run, never the balance.

/// Whether the bitcoind node knows nothing about `txid` (neither mined nor in the mempool). Used
/// to prove that an off-chain rung is, and stays, un-broadcast.
#[cfg(feature = "electrum")]
fn tx_unknown_to_node(txid: &str) -> bool {
    let mut args = bitcoin_cli();
    args.extend([s!("getrawtransaction"), txid.to_string()]);
    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to query bitcoind");
    !output.status.success()
}

/// Build an un-broadcast colored tier spending `prev` into a single P2TR output, consume its
/// fascia. This is exactly the shape of an off-chain (never broadcast) ladder rung.
#[cfg(feature = "electrum")]
fn offchain_tier(
    wallet: &Wallet,
    prev: OutPoint,
    dest: &str,
    value: u64,
    contract_id: ContractId,
    amount: u64,
    blinding: u64,
) -> (bdk_wallet::bitcoin::Txid, u32) {
    let mut psbt = unsigned_spend_psbt(prev, dest, value);
    let coloring_info = tier_coloring_info(contract_id, amount, blinding);
    wallet
        .color_psbt_and_consume(&mut psbt, coloring_info)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid();
    // coloring puts the opret first (the payload output is P2TR), so the seal is not at vout 0
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| !o.script_pubkey.is_op_return())
        .unwrap() as u32;
    (txid, vout)
}

#[cfg(feature = "electrum")]
fn unsigned_spend_psbt(prev: OutPoint, dest: &str, value: u64) -> Psbt {
    let address = BdkAddress::from_str(dest)
        .unwrap()
        .require_network(BdkNetwork::Regtest)
        .unwrap();
    let tx = BdkTransaction {
        version: bdk_wallet::bitcoin::transaction::Version(3),
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: vec![bdk_wallet::bitcoin::TxIn {
            previous_output: prev,
            script_sig: Default::default(),
            // a relative-CSV-shaped nSequence, like a TES-R tier
            sequence: bdk_wallet::bitcoin::Sequence(10),
            witness: bdk_wallet::bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: BdkAmount::from_sat(value),
            script_pubkey: address.script_pubkey(),
        }],
    };
    Psbt::from_unsigned_tx(tx).unwrap()
}

#[cfg(feature = "electrum")]
fn tier_coloring_info(contract_id: ContractId, amount: u64, blinding: u64) -> ColoringInfo {
    ColoringInfo {
        asset_info_map: HashMap::from([(
            contract_id,
            AssetColoringInfo {
                output_map: HashMap::from([(0u32, amount)]),
                blinded_map: HashMap::new(),
                static_blinding: Some(blinding),
                output_blinding: HashMap::new(),
            },
        )]),
        static_blinding: Some(blinding),
        nonce: None,
    }
}

/// Read-only probe of the RGB stock: can it still see `amount` allocated at `prev`?
///
/// Uses `color_psbt` (NOT `color_psbt_and_consume`), so nothing is written to the stash. This is
/// the assertion that matters: `get_asset_balance` keeps reporting the full settled balance even
/// when the stash is dead.
#[cfg(feature = "electrum")]
fn stock_sees_allocation(
    wallet: &Wallet,
    prev: OutPoint,
    dest: &str,
    contract_id: ContractId,
    amount: u64,
    blinding: u64,
) -> bool {
    let mut psbt = unsigned_spend_psbt(prev, dest, 1000);
    let coloring_info = tier_coloring_info(contract_id, amount, blinding);
    match wallet.color_psbt(&mut psbt, coloring_info) {
        Ok(_) => true,
        Err(Error::InvalidColoringInfo { details }) => {
            println!("stock probe on {prev} failed: {details}");
            false
        }
        Err(e) => panic!("unexpected stock probe error: {e:?}"),
    }
}

/// Build a 2-rung, never-broadcast colored ladder over an issued asset.
/// Returns (contract id, destination address, root outpoint, rung 1 outpoint, rung 2 outpoint).
#[cfg(feature = "electrum")]
fn build_offchain_ladder(
    party: &mut SinglesigParty,
    blinding: u64,
    amount: u64,
) -> (ContractId, String, OutPoint, OutPoint, OutPoint) {
    let asset = party.issue_asset_nia(Some(&[amount]));
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    let root = party
        .list_unspents(false)
        .iter()
        .find_map(|u| {
            u.rgb_allocations
                .iter()
                .any(|a| a.asset_id.as_deref() == Some(&asset.asset_id))
                .then(|| OutPoint {
                    txid: bdk_wallet::bitcoin::Txid::from_str(&u.utxo.outpoint.txid).unwrap(),
                    vout: u.utxo.outpoint.vout,
                })
        })
        .expect("no allocation for the issued asset");

    let dest = party.get_address();
    let (txid_1, vout_1) = offchain_tier(
        &party.wallet,
        root,
        &dest,
        900,
        contract_id,
        amount,
        blinding,
    );
    let rung_1 = OutPoint {
        txid: txid_1,
        vout: vout_1,
    };
    let (txid_2, vout_2) = offchain_tier(
        &party.wallet,
        rung_1,
        &dest,
        800,
        contract_id,
        amount,
        blinding,
    );
    let rung_2 = OutPoint {
        txid: txid_2,
        vout: vout_2,
    };

    // neither rung is on chain nor in the mempool, by design
    for txid in [txid_1, txid_2] {
        assert!(
            tx_unknown_to_node(&txid.to_string()),
            "rung {txid} unexpectedly known to the node"
        );
    }

    // the stock knows both rungs before anything else happens
    assert!(stock_sees_allocation(
        &party.wallet,
        rung_1,
        &dest,
        contract_id,
        amount,
        blinding
    ));
    assert!(stock_sees_allocation(
        &party.wallet,
        rung_2,
        &dest,
        contract_id,
        amount,
        blinding
    ));

    (contract_id, dest, root, rung_1, rung_2)
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_keeps_offchain_ladder_alive() {
    initialize();

    let blinding = 61;
    let amount = AMOUNT;
    let mut party = get_funded_party!();
    let (contract_id, dest, root, rung_1, rung_2) =
        build_offchain_ladder(&mut party, blinding, amount);

    // the call that used to kill the ladder: plain blockchain resolver, no forced witness
    let update_res = party.wallet.update_witnesses(0, vec![]).unwrap();
    println!("update_witnesses: {update_res:?}");

    // one call -> both rungs ALIVE (before the guard: both dead, with succeeded=2 and no error)
    assert!(
        stock_sees_allocation(&party.wallet, rung_1, &dest, contract_id, amount, blinding),
        "rung 1 was archived by update_witnesses"
    );
    assert!(
        stock_sees_allocation(&party.wallet, rung_2, &dest, contract_id, amount, blinding),
        "rung 2 (the ladder tip) was archived by update_witnesses"
    );
    // the on-chain root keeps working as well
    assert!(stock_sees_allocation(
        &party.wallet,
        root,
        &dest,
        contract_id,
        amount,
        blinding
    ));

    // it stays alive across repeated calls and a mined block
    mine(false);
    party.wallet.update_witnesses(0, vec![]).unwrap();
    party.refresh_all();
    party.wallet.update_witnesses(0, vec![]).unwrap();
    assert!(stock_sees_allocation(
        &party.wallet,
        rung_2,
        &dest,
        contract_id,
        amount,
        blinding
    ));

    // the guard is not a blanket "never archive": an explicit force still archives, so a caller
    // that really wants to drop an un-broadcast branch can still do it
    let forced = vec![RgbTxid::from_str(&rung_1.txid.to_string()).unwrap()];
    party.wallet.update_witnesses(0, forced).unwrap();
    assert!(
        !stock_sees_allocation(&party.wallet, rung_1, &dest, contract_id, amount, blinding),
        "an explicitly forced witness must still be archivable"
    );
    assert!(
        !stock_sees_allocation(&party.wallet, rung_2, &dest, contract_id, amount, blinding),
        "archiving a rung must invalidate its descendants"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn revalidate_offchain_bundles_repairs_archived_ladder() {
    initialize();

    let blinding = 62;
    let amount = AMOUNT;
    let mut party = get_funded_party!();
    let (contract_id, dest, _root, rung_1, rung_2) =
        build_offchain_ladder(&mut party, blinding, amount);

    let backup = party.wallet.backup_invalid_bundles().unwrap();
    assert!(backup.is_empty());

    // deliberately destroy the ladder, the only way that is still possible: an explicit force
    let forced = vec![
        RgbTxid::from_str(&rung_1.txid.to_string()).unwrap(),
        RgbTxid::from_str(&rung_2.txid.to_string()).unwrap(),
    ];
    party.wallet.update_witnesses(0, forced).unwrap();
    assert!(!stock_sees_allocation(
        &party.wallet,
        rung_1,
        &dest,
        contract_id,
        amount,
        blinding
    ));
    assert!(!stock_sees_allocation(
        &party.wallet,
        rung_2,
        &dest,
        contract_id,
        amount,
        blinding
    ));
    // the bundles are now recorded as invalid in the (persisted) stock
    let broken = party.wallet.backup_invalid_bundles().unwrap();
    assert!(!broken.is_empty());

    // repair, WITHOUT broadcasting anything: root-spend first
    let update_res = party
        .wallet
        .revalidate_offchain_bundles(vec![rung_1.txid.to_string(), rung_2.txid.to_string()])
        .unwrap();
    println!("revalidate_offchain_bundles: {update_res:?}");
    assert!(update_res.failed.is_empty());

    // both rungs are back
    assert!(
        stock_sees_allocation(&party.wallet, rung_1, &dest, contract_id, amount, blinding),
        "rung 1 was not repaired"
    );
    assert!(
        stock_sees_allocation(&party.wallet, rung_2, &dest, contract_id, amount, blinding),
        "rung 2 was not repaired"
    );
    // and nothing was broadcast to get there
    for txid in [rung_1.txid, rung_2.txid] {
        assert!(
            tx_unknown_to_node(&txid.to_string()),
            "repair broadcast {txid}"
        );
    }
    // the invalid-bundle set is back to the backed-up one
    assert_eq!(party.wallet.backup_invalid_bundles().unwrap(), backup);

    // an unknown TXID cannot be revalidated: it is reported as failed, nothing is resurrected.
    // NB: the stock only ever iterates the witness ords it already holds, so without the explicit
    // unvisited-witness accounting in `update_witnesses_guarded` this call would silently report
    // success (`failed` empty, `succeeded` counting the *other*, unrelated witnesses) and a caller
    // would believe a branch had been repaired when nothing at all happened.
    let fake_txid = RgbTxid::from_str(FAKE_TXID).unwrap();
    let invalid_before = party.wallet.backup_invalid_bundles().unwrap();
    let update_res = party
        .wallet
        .revalidate_offchain_bundles(vec![FAKE_TXID.to_string()])
        .unwrap();
    println!("revalidate_offchain_bundles(unknown): {update_res:?}");
    assert!(
        update_res.failed.contains_key(&fake_txid),
        "an unknown TXID must be reported in UpdateRes::failed, got {update_res:?}"
    );
    // nothing was resurrected and nothing was invalidated by the failed repair
    assert_eq!(party.wallet.backup_invalid_bundles().unwrap(), invalid_before);
    assert!(
        stock_sees_allocation(&party.wallet, rung_2, &dest, contract_id, amount, blinding),
        "a failed repair must not disturb the repaired ladder"
    );

    // a TXID that cannot even be parsed is rejected outright
    let result = party.wallet.revalidate_offchain_bundles(vec![s!("invalid")]);
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn restore_invalid_bundles_success() {
    initialize();

    let blinding = 63;
    let amount = AMOUNT;
    let mut party = get_funded_party!();
    let (contract_id, dest, _root, rung_1, rung_2) =
        build_offchain_ladder(&mut party, blinding, amount);

    // a backup taken while everything is healthy holds no invalid bundle
    let healthy = party.wallet.backup_invalid_bundles().unwrap();
    assert!(healthy.is_empty());
    assert!(healthy.bundle_ids().is_empty());

    // break the ladder and back up the broken set
    let forced = vec![RgbTxid::from_str(&rung_1.txid.to_string()).unwrap()];
    party.wallet.update_witnesses(0, forced).unwrap();
    let broken = party.wallet.backup_invalid_bundles().unwrap();
    assert!(!broken.is_empty());
    assert_eq!(broken.bundle_ids().len(), broken.len());

    // restoring the healthy backup clears the invalid-bundle set
    party.wallet.restore_invalid_bundles(&healthy).unwrap();
    assert!(party.wallet.backup_invalid_bundles().unwrap().is_empty());

    // restoring the broken backup puts it back, exactly
    party.wallet.restore_invalid_bundles(&broken).unwrap();
    assert_eq!(party.wallet.backup_invalid_bundles().unwrap(), broken);

    // clearing the invalid set alone is NOT a repair: the witness ord is still Archived, so the
    // rungs stay invisible until the witnesses are revalidated as offchain ones
    party.wallet.restore_invalid_bundles(&healthy).unwrap();
    assert!(!stock_sees_allocation(
        &party.wallet,
        rung_2,
        &dest,
        contract_id,
        amount,
        blinding
    ));
    party
        .wallet
        .revalidate_offchain_bundles(vec![rung_1.txid.to_string(), rung_2.txid.to_string()])
        .unwrap();
    assert!(stock_sees_allocation(
        &party.wallet,
        rung_2,
        &dest,
        contract_id,
        amount,
        blinding
    ));
}
