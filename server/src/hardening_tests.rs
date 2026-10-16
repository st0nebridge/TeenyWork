//! @module hardening_tests
//! @description Regression tests for the server's limits: bounded challenge,
//! lease and token tables and remembered solutions; leases that only their
//! own proof can spend, at most eight per challenge; extranonce2 values kept
//! when a lease is refused; a token slot held from before a proof's work is
//! spent; pool-search proofs that earn no token; the JSON body cap; strict
//! `C2A_POOL_TLS`. Also a guard that the listener stays HTTP/1.1-only, which
//! keeps actix's HTTP/2 stack, and the `h2` advisories, out of reach.

use super::*;
use crate::access_proof_replay_tests::{
    candidates, json_body, prove, replay_state, serve_job, solve,
};
use crate::test_support::ScratchDir;
use actix_web::http::StatusCode;
use actix_web::test as actix_test;

async fn issue_challenge(state: &web::Data<AppState>) -> (StatusCode, serde_json::Value) {
    let response = challenge_endpoint(
        state.clone(),
        actix_test::TestRequest::post().to_http_request(),
        web::Json(ChallengeRequest {
            resource: "/forms/contact".to_string(),
            high_confidence_bot: false,
        }),
    )
    .await
    .unwrap();
    json_body(response).await
}

async fn lease_for(
    state: &web::Data<AppState>,
    challenge_id: &str,
    worker_id: &str,
) -> (StatusCode, serde_json::Value) {
    let response = lease_endpoint(
        state.clone(),
        web::Json(LeaseRequest {
            challenge_id: challenge_id.to_string(),
            worker_id: worker_id.to_string(),
        }),
    )
    .await
    .unwrap();
    json_body(response).await
}

async fn new_challenge_id(state: &web::Data<AppState>) -> String {
    let (status, challenge) = issue_challenge(state).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    challenge["challenge_id"].as_str().unwrap().to_string()
}

#[actix_web::test]
async fn a_full_challenge_table_refuses_new_challenges_with_503() {
    let dir = ScratchDir::new("hardening-challenges");
    let state = replay_state(&dir).await;
    *state.challenges.lock().await = ExpiringTable::new(2);
    for _ in 0..2 {
        assert_eq!(issue_challenge(&state).await.0, StatusCode::OK);
    }
    let (status, body) = issue_challenge(&state).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, serde_json::json!(AT_CAPACITY));
}

#[actix_web::test]
async fn a_full_lease_table_refuses_without_taking_an_extranonce2() {
    let dir = ScratchDir::new("hardening-leases");
    let state = replay_state(&dir).await;
    *state.leases.lock().await = ExpiringTable::new(1);
    let first = new_challenge_id(&state).await;
    let second = new_challenge_id(&state).await;
    assert_eq!(lease_for(&state, &first, "worker").await.0, StatusCode::OK);
    let (status, body) = lease_for(&state, &second, "worker").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(state.stratum_pool.lock().await.next_extranonce_2, Some(1));
}

#[actix_web::test]
async fn a_refused_second_lease_does_not_use_up_an_extranonce2() {
    let dir = ScratchDir::new("hardening-conflict");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    let (status, lease) = lease_for(&state, &challenge_id, "worker").await;
    assert_eq!(status, StatusCode::OK, "{lease}");
    assert_eq!(lease["extranonce_2"], "00");
    for _ in 0..5 {
        let (status, body) = lease_for(&state, &challenge_id, "worker").await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    }
    let other = new_challenge_id(&state).await;
    let (status, next) = lease_for(&state, &other, "worker").await;
    assert_eq!(status, StatusCode::OK, "{next}");
    assert_eq!(
        next["extranonce_2"], "01",
        "conflicting requests must not have advanced the counter"
    );
}

#[actix_web::test]
async fn a_proof_cannot_spend_a_lease_issued_for_another_challenge() {
    let dir = ScratchDir::new("hardening-foreign-lease");
    let state = replay_state(&dir).await;
    let victim_challenge = new_challenge_id(&state).await;
    let (_, victim_lease) = lease_for(&state, &victim_challenge, "victim").await;
    let attacker_challenge = new_challenge_id(&state).await;
    let (_, attacker_lease) = lease_for(&state, &attacker_challenge, "attacker").await;

    // The attacker names the victim's lease under their own challenge.
    let solutions = solve(&victim_lease, 0);
    let response = proof_endpoint(
        state.clone(),
        web::Json(ProofRequest {
            challenge_id: attacker_challenge.clone(),
            lease_id: victim_lease["lease_id"].as_str().unwrap().to_string(),
            worker_id: "victim".to_string(),
            candidates: candidates(&victim_lease, &solutions),
            hashes_attempted: 0,
            elapsed_ms: 0,
        }),
    )
    .await
    .unwrap();
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, victim) = prove(&state, &victim_lease, &solutions).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the victim's lease survives: {victim}"
    );
    assert!(victim["token"].is_string());
    let (status, attacker) = prove(&state, &attacker_lease, &solve(&attacker_lease, 0)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a mismatched proof does not spend the attacker's own lease either: {attacker}"
    );
}

#[actix_web::test]
async fn a_full_token_table_refuses_the_proof_before_spending_the_challenge() {
    let dir = ScratchDir::new("hardening-tokens");
    let state = replay_state(&dir).await;
    *state.access_tokens.lock().await = ExpiringTable::new(0);
    let challenge_id = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
    let (status, body) = prove(&state, &lease, &solve(&lease, 0)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        state.challenges.lock().await.contains_key(&challenge_id),
        "the challenge is kept for a retry"
    );

    *state.access_tokens.lock().await = ExpiringTable::new(1);
    let (_, retry_lease) = lease_for(&state, &challenge_id, "worker").await;
    let (status, retried) = prove(&state, &retry_lease, &solve(&retry_lease, 0)).await;
    assert_eq!(status, StatusCode::OK, "{retried}");
}

#[actix_web::test]
async fn json_bodies_over_64_kib_are_refused_before_parsing() {
    let dir = ScratchDir::new("hardening-json");
    let state = replay_state(&dir).await;
    let app =
        actix_test::init_service(App::new().app_data(state).configure(configure_routes)).await;

    let padding = "a".repeat(MAX_JSON_BODY_BYTES);
    let oversized = actix_test::TestRequest::post()
        .uri("/api/proof")
        .insert_header(("Content-Type", "application/json"))
        .set_payload(format!(r#"{{"challenge_id":"{padding}"}}"#))
        .to_request();
    let response = actix_test::call_service(&app, oversized).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let small = actix_test::TestRequest::post()
        .uri("/api/proof")
        .insert_header(("Content-Type", "application/json"))
        .set_payload(r#"{"challenge_id":"x"}"#)
        .to_request();
    let response = actix_test::call_service(&app, small).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a small malformed proof still reaches the JSON parser"
    );
}

#[test]
fn pool_tls_is_on_unless_explicitly_false() {
    assert_eq!(pool_tls_setting(None), Ok(true));
    for on in ["true", "TRUE", " True "] {
        assert_eq!(pool_tls_setting(Some(on)), Ok(true), "{on:?}");
    }
    for off in ["false", "FALSE", "False"] {
        assert_eq!(pool_tls_setting(Some(off)), Ok(false), "{off:?}");
    }
    for refused in ["", "1", "0", "yes", "no", "on", "ture", "flase"] {
        assert!(pool_tls_setting(Some(refused)).is_err(), "{refused:?}");
    }
}

/// Not a regression test: `.bind()` never served HTTP/2 (only the opt-in
/// `bind_auto_h2c` does). This pins it, because the server relies on actix's
/// HTTP/2 stack being unreachable.
#[actix_web::test]
async fn the_plaintext_listener_answers_only_http1() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = ScratchDir::new("hardening-h2");
    let state = replay_state(&dir).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = actix_web::HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .configure(configure_routes)
    })
    .workers(1)
    .disable_signals()
    .listen(listener)
    .unwrap()
    .run();
    let handle = server.handle();
    actix_rt::spawn(server);

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    // The HTTP/2 connection preface and an empty SETTINGS frame.
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let mut reply = vec![0u8; 64];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut reply))
        .await
        .expect("the server answers")
        .unwrap();
    handle.stop(false).await;
    assert!(
        reply[..read].starts_with(b"HTTP/1.1 "),
        "an HTTP/2 preface must get an HTTP/1.1 answer, got {:?}",
        String::from_utf8_lossy(&reply[..read])
    );
}

#[actix_web::test]
async fn expired_challenges_leases_and_grants_are_reclaimed_at_their_own_expiry() {
    let dir = ScratchDir::new("hardening-expiry");
    let state = replay_state(&dir).await;
    let started = Utc::now();
    let leased = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &leased, "worker").await;
    let unleased = new_challenge_id(&state).await;
    let (status, granted) = prove(&state, &lease, &solve(&lease, 0)).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    let token = granted["token"].as_str().unwrap().to_string();
    let after = |seconds: i64| started + chrono::TimeDelta::seconds(seconds);

    // A second lease, never proved, for the challenge that has none.
    let (status, _) = lease_for(&state, &unleased, "worker").await;
    assert_eq!(status, StatusCode::OK);
    let mut leases = state.leases.lock().await;
    assert!(leases.has_room(after(80)) && leases.contains_key(&unleased));
    assert!(
        leases.has_room(after(100)) && !leases.contains_key(&unleased),
        "90 s"
    );
    drop(leases);
    let mut challenges = state.challenges.lock().await;
    assert!(challenges.has_room(after(880)) && challenges.contains_key(&unleased));
    assert!(
        challenges.has_room(after(920)) && !challenges.contains_key(&unleased),
        "15 min"
    );
    drop(challenges);
    let mut grants = state.access_tokens.lock().await;
    assert!(grants.has_room(after(3580)) && grants.contains_key(&token));
    assert!(
        grants.has_room(after(3620)) && !grants.contains_key(&token),
        "1 hour"
    );
}

#[actix_web::test]
async fn a_proof_without_a_live_lease_is_refused() {
    let dir = ScratchDir::new("hardening-no-lease");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
    let solution = solve(&lease, 0);

    // Expire the lease in place.
    let mut expired = state.leases.lock().await.remove(&challenge_id).unwrap();
    expired.expires_at = Utc::now() - chrono::TimeDelta::seconds(1);
    state
        .leases
        .lock()
        .await
        .insert(challenge_id.clone(), expired, Utc::now())
        .unwrap();
    let (status, body) = prove(&state, &lease, &solution).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        serde_json::json!("Invalid, expired, or mismatched work lease")
    );
    assert!(
        !state.leases.lock().await.contains_key(&challenge_id),
        "an expired lease is dropped"
    );

    let (status, body) = prove(&state, &lease, &solution).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        serde_json::json!("Unknown or already-used work lease")
    );
}

#[actix_web::test]
async fn the_simd_solver_is_served_as_webassembly() {
    let dir = ScratchDir::new("hardening-simd-asset");
    let state = replay_state(&dir).await;
    std::fs::create_dir_all(dir.join("browser")).unwrap();
    std::fs::write(
        dir.join("browser").join("wasm-challenger-simd.wasm"),
        b"\0asm",
    )
    .unwrap();
    let response = static_file_handler(
        state,
        web::Path::from("wasm-challenger-simd.wasm".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/wasm"
    );
}

async fn challenge_status(
    state: &web::Data<AppState>,
    resource: &str,
    high_confidence_bot: bool,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = actix_test::TestRequest::post();
    if let Some(key) = bearer {
        request = request.insert_header(("Authorization", format!("Bearer {key}")));
    }
    let response = challenge_endpoint(
        state.clone(),
        request.to_http_request(),
        web::Json(ChallengeRequest {
            resource: resource.to_string(),
            high_confidence_bot,
        }),
    )
    .await
    .unwrap();
    json_body(response).await
}

#[actix_web::test]
async fn challenge_requests_are_checked_before_a_challenge_is_held() {
    let dir = ScratchDir::new("hardening-challenge-input");
    let state = crate::test_support::test_state(&dir, Some("site-key"));
    let longest = format!("/{}", "a".repeat(2047));
    let too_long = format!("/{}", "a".repeat(2048));
    assert_eq!(
        challenge_status(&state, "", false, None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        challenge_status(&state, &too_long, false, None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        challenge_status(&state, &longest, false, None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        state.challenges.lock().await.len(),
        1,
        "only the valid request holds a challenge"
    );

    let (status, _) = challenge_status(&state, "/forms/contact", true, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a high-confidence challenge needs the key"
    );
    let (status, _) = challenge_status(&state, "/forms/contact", true, Some("wrong-key")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, challenge) =
        challenge_status(&state, "/forms/contact", true, Some("site-key")).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    assert_eq!(
        challenge["required_work_units"], 16,
        "12 configured bits plus the bonus of 4"
    );
}

#[actix_web::test]
async fn lease_requests_need_a_worker_id_of_1_to_128_bytes() {
    let dir = ScratchDir::new("hardening-worker-id");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    for refused in [String::new(), "w".repeat(129)] {
        let (status, body) = lease_for(&state, &challenge_id, &refused).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let (status, lease) = lease_for(&state, &challenge_id, &"w".repeat(128)).await;
    assert_eq!(status, StatusCode::OK, "{lease}");
    assert_eq!(
        lease["extranonce_2"], "00",
        "refused requests took no extranonce2"
    );
}

#[actix_web::test]
async fn a_lease_is_spent_only_with_its_own_lease_id_and_worker() {
    let dir = ScratchDir::new("hardening-lease-binding");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
    let solution = solve(&lease, 0);

    let mut wrong_worker = lease.clone();
    wrong_worker["worker_id"] = serde_json::json!("someone-else");
    let mut wrong_lease = lease.clone();
    wrong_lease["lease_id"] = serde_json::json!(format!("{challenge_id}-0-ff"));
    for impostor in [wrong_worker, wrong_lease] {
        let (status, body) = prove(&state, &impostor, &solution).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{impostor}");
        assert_eq!(
            body,
            serde_json::json!("Invalid, expired, or mismatched work lease")
        );
        assert!(
            state.leases.lock().await.contains_key(&challenge_id),
            "the lease is kept"
        );
    }
    let (status, granted) = prove(&state, &lease, &solution).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
}

#[actix_web::test]
async fn a_lease_is_live_until_its_expiry_and_not_at_it() {
    let dir = ScratchDir::new("hardening-lease-boundary");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
    let expires_at = state
        .leases
        .lock()
        .await
        .get(&challenge_id)
        .unwrap()
        .expires_at;
    let just_before = expires_at - chrono::TimeDelta::nanoseconds(1);
    let proof = ProofRequest {
        challenge_id: challenge_id.clone(),
        lease_id: lease["lease_id"].as_str().unwrap().to_string(),
        worker_id: "worker".to_string(),
        candidates: Vec::new(),
        hashes_attempted: 0,
        elapsed_ms: 0,
    };

    let mut leases = state.leases.lock().await;
    assert!(has_live_lease(&leases, &challenge_id, just_before));
    assert!(!has_live_lease(&leases, &challenge_id, expires_at));
    let taken = take_proof_lease(&mut leases, &proof, just_before).expect("live just before");
    leases
        .insert(challenge_id.clone(), taken, just_before)
        .unwrap();
    assert_eq!(
        take_proof_lease(&mut leases, &proof, expires_at).err(),
        Some("Invalid, expired, or mismatched work lease"),
        "at its expiry the lease is spent no more"
    );
    assert!(
        !leases.contains_key(&challenge_id),
        "an expired lease is dropped"
    );
}

#[actix_web::test]
async fn a_proof_without_1_to_32_candidates_does_not_spend_its_lease() {
    let dir = ScratchDir::new("hardening-candidate-count");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
    let solutions = solve(&lease, 0);
    let too_many: Vec<_> = solutions.iter().cycle().take(33).copied().collect();
    for refused in [Vec::new(), too_many] {
        let count = refused.len();
        let (status, body) = prove(&state, &lease, &refused).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{count} candidates: {body}"
        );
        assert_eq!(
            body,
            serde_json::json!("Provide between 1 and 32 verified candidates")
        );
        assert!(
            state.leases.lock().await.contains_key(&challenge_id),
            "{count} candidates leave the lease in place"
        );
    }
    // 32 candidates are allowed: the 16 solutions, each sent twice.
    let most: Vec<_> = solutions.iter().cycle().take(32).copied().collect();
    let (status, granted) = prove(&state, &lease, &most).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
}

#[actix_web::test]
async fn a_challenge_gets_at_most_eight_leases() {
    let dir = ScratchDir::new("hardening-leases-per-challenge");
    let state = replay_state(&dir).await;
    let challenge_id = new_challenge_id(&state).await;
    for issued in 0..8 {
        let (status, lease) = lease_for(&state, &challenge_id, "worker").await;
        assert_eq!(status, StatusCode::OK, "lease {issued}: {lease}");
        // A candidate whose hash does not match its header uses the lease up.
        let (status, body) = prove(&state, &lease, &[(0, [0u8; 32])]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let (status, body) = lease_for(&state, &challenge_id, "worker").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body,
        serde_json::json!("This challenge has had its 8 work leases; request a new challenge")
    );
    assert_eq!(
        state.stratum_pool.lock().await.next_extranonce_2,
        Some(8),
        "the refused lease took no extranonce2"
    );
    let other = new_challenge_id(&state).await;
    let (status, lease) = lease_for(&state, &other, "worker").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "other challenges still lease: {lease}"
    );
}

#[actix_web::test]
async fn a_full_spent_set_answers_503_and_keeps_the_challenge() {
    let dir = ScratchDir::new("hardening-spent-set");
    let state = replay_state(&dir).await;
    // Room for one proof's sixteen solutions.
    state.stratum_pool.lock().await.spent_access_proof_capacity = 16;
    let first = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &first, "worker").await;
    assert_eq!(
        prove(&state, &lease, &solve(&lease, 0)).await.0,
        StatusCode::OK
    );

    let second = new_challenge_id(&state).await;
    let (_, lease) = lease_for(&state, &second, "worker").await;
    let (status, body) = prove(&state, &lease, &solve(&lease, 0)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, serde_json::json!(AT_CAPACITY));
    assert!(
        state.challenges.lock().await.contains_key(&second),
        "the challenge is kept for a retry"
    );
    assert_eq!(
        state.access_tokens.lock().await.len(),
        1,
        "the refused proof holds no token slot"
    );

    state.stratum_pool.lock().await.spent_access_proof_capacity = 32;
    let (_, retry) = lease_for(&state, &second, "worker").await;
    let (status, retried) = prove(&state, &retry, &solve(&retry, 0)).await;
    assert_eq!(status, StatusCode::OK, "{retried}");
}

#[actix_web::test]
async fn a_proof_holds_its_token_slot_from_before_its_work_is_spent() {
    let dir = ScratchDir::new("hardening-token-slot");
    let (state, gate) = crate::test_support::gated_test_state(&dir);
    state.pool_runtime_config.write().await.required_work_units = 8;
    serve_job(&state, 1, true).await;
    *state.access_tokens.lock().await = ExpiringTable::new(1);
    // One ledger group each for the challenge and the lease.
    gate.release_one();
    let challenge_id = new_challenge_id(&state).await;
    gate.release_one();
    let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
    let solutions = solve(&lease, 0);

    let proof = prove(&state, &lease, &solutions);
    tokio::pin!(proof);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut proof)
            .await
            .is_err(),
        "the proof waits for the held ledger writer"
    );
    // Another grant arrives while the accepted proof is being recorded.
    let filler = state.access_tokens.lock().await.insert(
        "another-token".to_string(),
        AccessGrant {
            resource: "/forms/contact".to_string(),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
            challenge_id: "another-challenge".to_string(),
            work_units: 8,
        },
        Utc::now(),
    );
    assert!(filler.is_err(), "the proof already holds the last slot");

    drop(gate);
    let (status, body) = proof.await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].is_string(), "{body}");
}

#[actix_web::test]
async fn a_pool_search_proof_is_checked_and_recorded_but_earns_no_token() {
    let dir = ScratchDir::new("hardening-pool-search");
    let state = replay_state(&dir).await;
    let accepted = || state.analytics.proofs_accepted.load(Ordering::Relaxed);
    for resource in ["/pool/share-search", "/pool/share-search?batch=2"] {
        let (status, challenge) = challenge_status(&state, resource, false, None).await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        let challenge_id = challenge["challenge_id"].as_str().unwrap().to_string();
        let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
        let accepted_before = accepted();

        let (status, body) = prove(&state, &lease, &solve(&lease, 0)).await;
        assert_eq!(status, StatusCode::OK, "{resource}: {body}");
        assert!(body["token"].is_null(), "{resource}: {body}");
        assert!(body["expiry"].is_null(), "{resource}: {body}");
        assert_eq!(body["credits_remaining"], 0, "{resource}: {body}");
        assert_eq!(body["pool_share"], "not_pool_qualified");
        assert_eq!(accepted(), accepted_before + 1, "the proof is recorded");
        assert!(
            !state.challenges.lock().await.contains_key(&challenge_id),
            "the challenge is used up"
        );
        assert_eq!(
            state.access_tokens.lock().await.len(),
            0,
            "no grant holds a slot"
        );
    }

    let (_, form_lease) = lease_for(&state, &new_challenge_id(&state).await, "worker").await;
    let (status, form) = prove(&state, &form_lease, &solve(&form_lease, 0)).await;
    assert_eq!(status, StatusCode::OK, "{form}");
    assert!(
        form["token"].is_string(),
        "a form proof still earns a token: {form}"
    );
}

#[actix_web::test]
async fn a_header_hash_that_is_not_32_bytes_is_refused_as_such() {
    let dir = ScratchDir::new("hardening-hash-length");
    let state = replay_state(&dir).await;
    for length in [31, 33] {
        let challenge_id = new_challenge_id(&state).await;
        let (_, lease) = lease_for(&state, &challenge_id, "worker").await;
        let mut sent = candidates(&lease, &solve(&lease, 0));
        sent[0].header_hash = "ab".repeat(length);
        let response = proof_endpoint(
            state.clone(),
            web::Json(ProofRequest {
                challenge_id,
                lease_id: lease["lease_id"].as_str().unwrap().to_string(),
                worker_id: "worker".to_string(),
                candidates: sent,
                hashes_attempted: 0,
                elapsed_ms: 0,
            }),
        )
        .await
        .unwrap();
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{length} bytes: {body}");
        assert_eq!(body, serde_json::json!("header_hash must be 32-byte hex"));
    }
}
