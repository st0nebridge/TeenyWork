/// Tests for Stratum V1 protocol handling.

#[cfg(test)]
mod tests {
    use crate::stratum::client::StratumClient;
    use serde_json;

    #[test]
    fn test_subscribe_request() {
        let client = StratumClient::new();
        let request = client.subscribe_request();
        assert_eq!(request["method"], "mining.subscribe");
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["id"], 1);
    }

    #[test]
    fn test_authorize_request() {
        let client = StratumClient::new();
        let request = client.authorize_request("test.worker");
        assert_eq!(request["method"], "mining.authorize");
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["id"], 2);
        assert_eq!(request["params"], serde_json::json!(["test.worker", "x"]));
    }

    #[test]
    fn test_parse_job_notification() {
        let client = StratumClient::new();

        // Create a mock notification
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "mining.notify",
            "params": [
                "1",
                "ab".repeat(32),
                "01000000",
                "ffffffff",
                ["cd".repeat(32)],
                "1f000000",
                "1a13e967",
                "12345678",
                true,
            ]
        });

        let job = client.parse_job_notification(&notification).unwrap();
        assert_eq!(job.job_id, "1");
        assert_eq!(job.prev_block_hash, "ab".repeat(32));
        assert_eq!(job.coinbase_version, 0x1f000000);
        assert_eq!(job.n_time, 0x12345678);
        assert_eq!(job.n_bits, 0x1a13e967);
        assert!(job.clean_jobs);
    }

    #[test]
    fn test_hex_parsing() {
        // Test hex parsing in client module
        use crate::stratum::client::parse_hex_u32;
        let value = parse_hex_u32("12345678").unwrap();
        assert_eq!(value, 0x12345678);
    }

    /// The `mining.notify` example from the Stratum V1 protocol documentation,
    /// with two merkle branches added.
    fn realistic_notify() -> serde_json::Value {
        serde_json::json!({
            "id": null,
            "method": "mining.notify",
            "params": [
                "bf",
                "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000",
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008",
                "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000",
                [
                    "6a1f2e2f9b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6",
                    "e2a3c41d0f5b6a798c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
                ],
                "00000002",
                "1c2ac4af",
                "504e86b9",
                false
            ]
        })
    }

    fn notify_with(index: usize, value: serde_json::Value) -> serde_json::Value {
        let mut notify = realistic_notify();
        notify["params"][index] = value;
        notify
    }

    #[test]
    fn parses_every_field_of_a_realistic_mining_notify() {
        let job = StratumClient::new()
            .parse_job_notification(&realistic_notify())
            .unwrap();
        let prefix = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008";
        let suffix = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000";
        assert_eq!(job.job_id, "bf");
        assert_eq!(
            job.prev_block_hash,
            "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000"
        );
        assert_eq!(job.coinbase_prefix, prefix);
        assert_eq!(job.coinbase_suffix, suffix);
        assert_eq!(job.coinbase_data, format!("{prefix}{suffix}"));
        assert_eq!(
            job.merkle_branches,
            vec![
                "6a1f2e2f9b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6".to_string(),
                "e2a3c41d0f5b6a798c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d".to_string(),
            ]
        );
        assert_eq!(
            job.merkle_root, "",
            "the root needs the per-lease extranonces"
        );
        assert_eq!(job.coinbase_version, 2);
        assert_eq!(job.n_bits, 0x1c2ac4af);
        assert_eq!(job.n_time, 0x504e86b9);
        assert!(!job.clean_jobs);
    }

    #[test]
    fn rejects_a_notify_without_a_job_id_or_previous_block_hash() {
        let client = StratumClient::new();
        for (index, value) in [
            (0, serde_json::json!(null)),
            (0, serde_json::json!(42)),
            (0, serde_json::json!("")),
            (1, serde_json::json!(null)),
            (1, serde_json::json!(7)),
        ] {
            assert!(
                client
                    .parse_job_notification(&notify_with(index, value.clone()))
                    .is_err(),
                "param {index} = {value}"
            );
        }
    }

    #[test]
    fn rejects_malformed_hex_and_wrong_lengths_in_a_notify() {
        let client = StratumClient::new();
        let cases = [
            (1, serde_json::json!("00".repeat(31))),
            (1, serde_json::json!("00".repeat(33))),
            (1, serde_json::json!(format!("zz{}", "00".repeat(31)))),
            (2, serde_json::json!("0")),
            (2, serde_json::json!("zz")),
            (2, serde_json::json!("")),
            (3, serde_json::json!("abc")),
            (3, serde_json::json!("xyz0")),
            (4, serde_json::json!(["00".repeat(31)])),
            (4, serde_json::json!(["zz".repeat(32)])),
            (4, serde_json::json!([7])),
            (4, serde_json::json!("not-an-array")),
            (5, serde_json::json!("0000002")),
            (5, serde_json::json!("000000002")),
            (5, serde_json::json!("zzzzzzzz")),
            (5, serde_json::json!("+0000002")),
            (6, serde_json::json!("1c2ac4a")),
            (6, serde_json::json!("1c2ac4ag")),
            (7, serde_json::json!("504e86b")),
            (7, serde_json::json!(1347323577)),
            (8, serde_json::json!("true")),
        ];
        for (index, value) in cases {
            assert!(
                client
                    .parse_job_notification(&notify_with(index, value.clone()))
                    .is_err(),
                "param {index} = {value}"
            );
        }
        let mut short = realistic_notify();
        short["params"].as_array_mut().unwrap().pop();
        assert!(client.parse_job_notification(&short).is_err());
    }

    #[test]
    fn parse_hex_u32_rejects_instead_of_returning_zero() {
        use crate::stratum::client::parse_hex_u32;
        assert_eq!(parse_hex_u32("1c2ac4af"), Ok(0x1c2ac4af));
        assert_eq!(parse_hex_u32("00000000"), Ok(0));
        for malformed in [
            "",
            "zz",
            "1234567",
            "123456789",
            "+1234567",
            "-1234567",
            "0x123456",
            " 1234567",
        ] {
            assert!(parse_hex_u32(malformed).is_err(), "{malformed:?}");
        }
    }
}
