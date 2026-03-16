use super::{super::*, support::*};
use apt_types::Mode;
use serde_json::json;
use std::future::ready;

#[test]
fn runtime_bridge_drives_api_sync_hidden_upgrade_round_trip() {
    let surface = ApiSyncSurface::starter();
    let (mut server, server_static_public_key) = test_server();
    let now_secs = 1_700_100_000;
    let persistent_state = ClientPersistentState::default();
    let mut client_config = test_client_config();
    client_config.server_static_public_key = server_static_public_key;

    let prepared_ug1 =
        prepare_api_sync_ug1_request(&client_config, &persistent_state, &surface, now_secs)
            .unwrap();
    let response_ug2 = respond_api_sync_ug1_request(
        &mut server,
        &surface,
        &prepared_ug1.request,
        "h2-client-a",
        now_secs,
    )
    .unwrap()
    .expect("expected UG2 response");
    let prepared_ug3 = handle_api_sync_ug2_response(
        &surface,
        &prepared_ug1.authority,
        &response_ug2,
        prepared_ug1.state,
    )
    .unwrap();
    let (response_ug4, server_session) = respond_api_sync_ug3_request(
        &mut server,
        &surface,
        &prepared_ug3.request,
        "h2-client-a",
        now_secs + 1,
    )
    .unwrap()
    .expect("expected UG4 response");
    let client_session =
        handle_api_sync_ug4_response(&surface, &response_ug4, prepared_ug3.state).unwrap();

    assert_eq!(client_session.session_id, server_session.session_id);
    assert_eq!(
        client_session.chosen_carrier,
        CarrierBinding::S1EncryptedStream
    );
    assert!(client_session.masked_fallback_ticket.is_some());
    assert!(server_session.masked_fallback_ticket.is_some());
}

#[test]
fn runtime_bridge_returns_none_for_plain_public_requests() {
    let surface = ApiSyncSurface::starter();
    let (mut server, _) = test_server();
    let public_request = surface.build_state_push_request(
        "api.example.com",
        "device-a",
        json!({ "mode": Mode::STEALTH.value() }),
    );
    let reply = respond_api_sync_ug1_request(
        &mut server,
        &surface,
        &public_request,
        "h2-client-a",
        1_700_100_000,
    )
    .unwrap();
    assert!(reply.is_none());
}

#[tokio::test]
async fn client_driver_and_request_handler_complete_api_sync_hidden_upgrade() {
    let surface = ApiSyncSurface::starter();
    let driver = ApiSyncH2ClientDriver::new(surface.clone());
    let handler = ApiSyncH2RequestHandler::new(surface);
    let now_secs = 1_700_200_000;
    let (mut admission, server_static_public_key) = test_server();
    let persistent_state = ClientPersistentState::default();
    let mut client_config = test_client_config();
    client_config.server_static_public_key = server_static_public_key;
    let mut public_service = public_service_response;
    let mut server_session = None;

    let client_session = driver
        .establish_hidden_upgrade(
            &client_config,
            &persistent_state,
            |request| {
                let handled = handler
                    .handle_request(
                        &mut admission,
                        &mut public_service,
                        &request,
                        "h2-client-a",
                        now_secs,
                    )
                    .unwrap();
                if let Some(session) = handled.established_session().cloned() {
                    server_session = Some(session);
                }
                ready(Ok(handled.into_response()))
            },
            now_secs,
        )
        .await
        .unwrap();

    let server_session = server_session.expect("server should establish the same session");
    assert_eq!(client_session.session_id, server_session.session_id);
    assert_eq!(
        client_session.chosen_carrier,
        CarrierBinding::S1EncryptedStream
    );
    assert!(client_session.masked_fallback_ticket.is_some());
    assert!(server_session.masked_fallback_ticket.is_some());
}

#[test]
fn request_handler_preserves_public_service_for_plain_requests() {
    let surface = ApiSyncSurface::starter();
    let handler = ApiSyncH2RequestHandler::new(surface.clone());
    let (mut admission, _) = test_server();
    let request =
        surface.build_state_push_request("api.example.com", "device-a", json!({ "mode": 7 }));
    let mut public_service = public_service_response;

    let handled = handler
        .handle_request(
            &mut admission,
            &mut public_service,
            &request,
            "h2-client-a",
            1_700_200_000,
        )
        .unwrap();

    match handled {
        ApiSyncHandledRequest::Public(response) => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body["state"]["battery"], 91);
            assert_eq!(response.body["state"]["accepted_mode"], 7);
            assert_eq!(response.body["state"]["authority"], "api.example.com");
            assert!(response.body["server_hints"]["next_cursor"].is_null());
        }
        other => panic!("expected public-only response, got {other:?}"),
    }
}

#[test]
fn request_handler_treats_malformed_probe_slots_as_public_requests() {
    let surface = ApiSyncSurface::starter();
    let handler = ApiSyncH2RequestHandler::new(surface.clone());
    let (mut admission, _) = test_server();
    let mut request =
        surface.build_state_push_request("api.example.com", "device-a", json!({ "mode": 7 }));
    request.body["metadata"]["sync_hint"] = json!("not-valid-base64!!!");
    let mut public_service = public_service_response;

    let handled = handler
        .handle_request(
            &mut admission,
            &mut public_service,
            &request,
            "h2-client-a",
            1_700_200_000,
        )
        .unwrap();

    match handled {
        ApiSyncHandledRequest::Public(response) => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body["state"]["battery"], 91);
            assert_eq!(response.body["state"]["accepted_mode"], 7);
            assert_eq!(response.body["state"]["authority"], "api.example.com");
            assert!(response.body["server_hints"]["next_cursor"].is_null());
        }
        other => panic!("expected public-only response, got {other:?}"),
    }
}
