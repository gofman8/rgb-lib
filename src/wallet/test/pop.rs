//! PoP-seal wallet E2E tests, hermetic via the embedded in-process ledger.

use super::*;

use pop_client::{EmbeddedClient, PopClient};

fn pop_wallets_and_ledger() -> (Wallet, Wallet, EmbeddedClient) {
    let sender = get_test_wallet(true, None);
    let receiver = get_test_wallet(true, None);
    let ledger = EmbeddedClient::new("rgb-lib-pop-test");
    (sender, receiver, ledger)
}

#[test]
fn pop_issue_send_accept_roundtrip() {
    let (sender, receiver, ledger) = pop_wallets_and_ledger();

    // issue 1000 to the sender
    let asset = sender
        .pop_issue_asset(
            &ledger,
            s!("PoP Test Coin"),
            s!("PTC"),
            2,
            vec![600, 400],
        )
        .unwrap();
    assert_eq!(asset.issued_supply, 1000);
    let balance = sender.pop_get_asset_balance(&asset.asset_id).unwrap();
    assert_eq!(balance.settled, 1000);
    assert_eq!(sender.pop_list_assets().unwrap().len(), 1);
    assert_eq!(sender.pop_list_coins(None).unwrap().len(), 2);

    // receiver creates an invoice; sender pays 700 (spends both coins, 300 change)
    let receive_data = receiver.pop_blind_receive(&ledger).unwrap();
    let send_result = sender
        .pop_send(&ledger, &receive_data.invoice, &asset.asset_id, 700)
        .unwrap();

    // entry not sealed yet: package assembly must fail cleanly
    assert!(matches!(
        sender.pop_get_transfer_package(&ledger, &send_result.transfer_id),
        Err(Error::Pop { .. })
    ));

    // ledger seals the entry (heartbeat)
    ledger.close_entry().unwrap();

    let package = sender
        .pop_get_transfer_package(&ledger, &send_result.transfer_id)
        .unwrap();
    let received = receiver.pop_accept_transfer(&package).unwrap();
    assert_eq!(received.asset_id, asset.asset_id);
    assert_eq!(received.amount, 700);

    // balances: sender keeps 300 change, receiver holds 700
    let sender_balance = sender.pop_get_asset_balance(&asset.asset_id).unwrap();
    assert_eq!(sender_balance.settled, 300);
    assert_eq!(sender_balance.pending_change, 0);
    let receiver_balance = receiver.pop_get_asset_balance(&asset.asset_id).unwrap();
    assert_eq!(receiver_balance.settled, 700);

    // the receiver learned the asset from the package's genesis
    let receiver_assets = receiver.pop_list_assets().unwrap();
    assert_eq!(receiver_assets.len(), 1);
    assert_eq!(receiver_assets[0].ticker, "PTC");

    // second hop: receiver sends 500 back — proof chain now has two steps
    let back_invoice = sender.pop_blind_receive(&ledger).unwrap();
    let back_send = receiver
        .pop_send(&ledger, &back_invoice.invoice, &asset.asset_id, 500)
        .unwrap();
    ledger.close_entry().unwrap();
    let back_package = receiver
        .pop_get_transfer_package(&ledger, &back_send.transfer_id)
        .unwrap();
    let back_received = sender.pop_accept_transfer(&back_package).unwrap();
    assert_eq!(back_received.amount, 500);
    assert_eq!(
        sender.pop_get_asset_balance(&asset.asset_id).unwrap().settled,
        800
    );
    assert_eq!(
        receiver
            .pop_get_asset_balance(&asset.asset_id)
            .unwrap()
            .settled,
        200
    );
}

#[test]
fn pop_double_spend_is_prevented() {
    let (sender, receiver, ledger) = pop_wallets_and_ledger();

    let asset = sender
        .pop_issue_asset(&ledger, s!("Double"), s!("DBL"), 0, vec![100])
        .unwrap();

    // first spend consumes the only coin
    let invoice1 = receiver.pop_blind_receive(&ledger).unwrap();
    sender
        .pop_send(&ledger, &invoice1.invoice, &asset.asset_id, 100)
        .unwrap();

    // wallet-level: the coin is spent, second send has nothing to select
    let invoice2 = receiver.pop_blind_receive(&ledger).unwrap();
    assert!(matches!(
        sender.pop_send(&ledger, &invoice2.invoice, &asset.asset_id, 100),
        Err(Error::InsufficientAssignments { .. })
    ));

    // ledger-level: even signing a second closure manually is rejected,
    // because the pubkey already published
    let secp = pop_core::secp256k1::Secp256k1::new();
    let store_json =
        std::fs::read_to_string(sender.get_wallet_dir().join("pop_state.json")).unwrap();
    let store: serde_json::Value = serde_json::from_str(&store_json).unwrap();
    let key_index = store["coins"][0]["keyIndex"]
        .as_u64()
        .or_else(|| store["coins"][0]["key_index"].as_u64())
        .unwrap() as u32;
    let keypair = sender.pop_test_derive_keypair(key_index);
    let msg = pop_core::tagged_hash("test/double-spend", b"second closure");
    let sig = secp.sign_schnorr(
        &pop_core::secp256k1::Message::from_digest(*msg.as_bytes()),
        &keypair,
    );
    let result = ledger.publish(pop_core::Publication {
        pubkey: keypair.x_only_public_key().0,
        msg_hash: msg,
        sig,
    });
    assert!(result.is_err());
}

#[test]
fn pop_tampered_package_is_rejected() {
    let (sender, receiver, ledger) = pop_wallets_and_ledger();

    let asset = sender
        .pop_issue_asset(&ledger, s!("Tamper"), s!("TMP"), 0, vec![50])
        .unwrap();
    let receive_data = receiver.pop_blind_receive(&ledger).unwrap();
    let send_result = sender
        .pop_send(&ledger, &receive_data.invoice, &asset.asset_id, 50)
        .unwrap();
    ledger.close_entry().unwrap();
    let package = sender
        .pop_get_transfer_package(&ledger, &send_result.transfer_id)
        .unwrap();

    // inflate the received amount inside the package
    let tampered = package.replace("\"amount\":50", "\"amount\":5000");
    assert_ne!(tampered, package);
    assert!(matches!(
        receiver.pop_accept_transfer(&tampered),
        Err(Error::Pop { .. })
    ));

    // the genuine package still verifies
    receiver.pop_accept_transfer(&package).unwrap();

    // replaying the same package must fail (pending receive consumed)
    assert!(matches!(
        receiver.pop_accept_transfer(&package),
        Err(Error::Pop { .. })
    ));
}

/// Full deployment-shape E2E: a real `pop-node` process (spawned from the
/// binary given via `POP_NODE_BIN`), its timed heartbeat sealing entries, and
/// two regtest wallets driving the flow over HTTP.
///
/// Run with:
/// `POP_NODE_BIN=/path/to/pop-node cargo test --features pop pop_http_node_regtest_flow`
#[test]
fn pop_http_node_regtest_flow() {
    let Ok(node_bin) = std::env::var("POP_NODE_BIN") else {
        println!("POP_NODE_BIN not set, skipping HTTP node E2E");
        return;
    };
    let data_dir = std::env::temp_dir().join(format!("pop-node-rgb-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let bind = "127.0.0.1:39950";

    struct NodeGuard(std::process::Child);
    impl Drop for NodeGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }
    let _node = NodeGuard(
        std::process::Command::new(&node_bin)
            .args([
                "--bind",
                bind,
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--name",
                "rgb-lib-regtest-e2e",
                "--close-interval",
                "1",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn pop-node"),
    );

    let client = pop_client::HttpClient::new(&format!("http://{bind}"));
    // wait for the node to come up
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while client.info().is_err() {
        assert!(std::time::Instant::now() < deadline, "pop-node did not start");
        std::thread::sleep(Duration::from_millis(200));
    }

    // regtest wallets (get_test_wallet uses BitcoinNetwork::Regtest)
    let sender = get_test_wallet(true, None);
    let receiver = get_test_wallet(true, None);

    let asset = sender
        .pop_issue_asset(&client, s!("Regtest HTTP Coin"), s!("RHC"), 0, vec![250])
        .unwrap();
    let receive_data = receiver.pop_blind_receive(&client).unwrap();
    let send_result = sender
        .pop_send(&client, &receive_data.invoice, &asset.asset_id, 100)
        .unwrap();

    // the node's own heartbeat (1s interval) seals the entry — poll for the
    // witness instead of closing manually
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let package = loop {
        match sender.pop_get_transfer_package(&client, &send_result.transfer_id) {
            Ok(package) => break package,
            Err(_) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "entry was never sealed by the heartbeat"
                );
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    };

    let received = receiver.pop_accept_transfer(&package).unwrap();
    assert_eq!(received.amount, 100);
    assert_eq!(
        sender.pop_get_asset_balance(&asset.asset_id).unwrap().settled,
        150
    );
    assert_eq!(
        receiver
            .pop_get_asset_balance(&asset.asset_id)
            .unwrap()
            .settled,
        100
    );
    println!(
        "HTTP regtest flow OK: issued 250, sent 100 over pop-node at {bind}, change 150"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn pop_invoice_roundtrip_and_wrong_ledger() {
    let (sender, receiver, ledger) = pop_wallets_and_ledger();

    let asset = sender
        .pop_issue_asset(&ledger, s!("Ledger"), s!("LDG"), 0, vec![10])
        .unwrap();

    // an invoice from a different ledger is refused by pop_send
    let other_ledger = EmbeddedClient::new("other-ledger");
    let foreign_invoice = receiver.pop_blind_receive(&other_ledger).unwrap();
    assert!(matches!(
        sender.pop_send(&ledger, &foreign_invoice.invoice, &asset.asset_id, 10),
        Err(Error::Pop { .. })
    ));

    // garbage invoices are refused
    assert!(matches!(
        sender.pop_send(&ledger, "not-an-invoice", &asset.asset_id, 10),
        Err(Error::Pop { .. })
    ));

    // seal keys are recoverable from the mnemonic: same index → same pubkey
    let kp_a = sender.pop_test_derive_keypair(0);
    let kp_b = sender.pop_test_derive_keypair(0);
    assert_eq!(kp_a.x_only_public_key().0, kp_b.x_only_public_key().0);
    let kp_c = sender.pop_test_derive_keypair(1);
    assert_ne!(kp_a.x_only_public_key().0, kp_c.x_only_public_key().0);
}
