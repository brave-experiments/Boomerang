#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::await_holding_lock)]

use axum::{
    body::{self, Body},
    extract::Host,
    handler::HandlerWithoutStateExt,
    http::{StatusCode, Uri},
    response::{Redirect, Response},
    routing::get,
    BoxError, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Mutex;
use std::{net::SocketAddr, path::PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ark_ec::CurveConfig;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;

use boomerang::client::{
    CollectionM2, CollectionM4, IssuanceM1, IssuanceM3, SpendVerifyM2, SpendVerifyM4,
};
use boomerang::server::{CollectionStateS, IssuanceStateS, ServerKeyPair, SpendVerifyStateS};
use t256::Config;

use rand_core::OsRng;

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

type SBKP = ServerKeyPair<Config>;
type IBSM = IssuanceStateS<Config>;
type IBCM1 = IssuanceM1<Config>;
type IBCM3 = IssuanceM3<Config>;

type CBSM = CollectionStateS<Config>;
type CBCM2 = CollectionM2<Config>;
type CBCM4 = CollectionM4<Config>;

type SBSM = SpendVerifyStateS<Config>;
type SBCM2 = SpendVerifyM2<Config>;
type SBCM4 = SpendVerifyM4<Config>;

#[derive(Serialize, Deserialize)]
enum MessageType {
    M1,
    M3,
    M6,
    M10,
    M13,
    M14,
}

#[derive(Serialize, Deserialize)]
struct Message {
    msg_type: MessageType,
    data: Vec<u8>, // Serialized data
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_tls_rustls=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let ports = Ports {
        http: 7878,
        https: 3000,
    };
    tokio::spawn(redirect_http_to_https(ports));

    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("e2e")
            .join("cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("e2e")
            .join("key.pem"),
    )
    .await
    .unwrap();

    let app = Router::new().route("/", get(handler).post(post_handler));

    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[allow(dead_code)]
async fn handler() -> &'static str {
    "Hello, Client!"
}

lazy_static! {
    static ref SKP: Mutex<Option<SBKP>> = Mutex::new({
        let mut rng = OsRng;
        Some(SBKP::generate(&mut rng))
    });
    static ref IBSM_DEFAULT: Mutex<IBSM> = Mutex::new(IBSM::default());
    static ref CBSM_DEFAULT: Mutex<CBSM> = Mutex::new(CBSM::default());
    static ref SBSM_DEFAULT: Mutex<SBSM> = Mutex::new(SBSM::default());
}

async fn post_handler(body: Body) -> Result<Response, Infallible> {
    let bytes = body::to_bytes(body, usize::MAX).await.unwrap();
    let message: Message = bincode::deserialize(&bytes).expect("Failed to deserialize message");

    let mut rng = OsRng;
    // Access shared SKP and IBSM instances
    let skp_lock = SKP.lock().unwrap();
    let skp = skp_lock
        .as_ref()
        .expect("ServerKeyPair should be initialized");

    let mut ibsm_lock = IBSM_DEFAULT.lock().unwrap();
    let mut s_state = ibsm_lock.clone();

    let mut cbsm_lock = CBSM_DEFAULT.lock().unwrap();
    let mut col_state = cbsm_lock.clone();

    let mut sbsm_lock = SBSM_DEFAULT.lock().unwrap();
    let mut spend_state = sbsm_lock.clone();

    match message.msg_type {
        MessageType::M1 => {
            println!("Received m1 message, processing...");
            let m1: IBCM1 = IBCM1::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Issuance M1");

            let m2 =
                IssuanceStateS::<Config>::generate_issuance_m2(&m1, skp, &mut s_state, &mut rng);
            let mut m2_bytes = Vec::new();
            m2.serialize_compressed(&mut m2_bytes)
                .expect("Failed to serialize Issuance M2");
            println!("Bytes sent issuance (m2_message_bytes): {}", m2_bytes.len());

            *ibsm_lock = s_state;

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(m2_bytes))
                .expect("Failed to create response"))
        }
        MessageType::M3 => {
            println!("Received m3 message, processing...");

            let m3: IBCM3 = IBCM3::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Issuance M3");

            let m4 = IssuanceStateS::<Config>::generate_issuance_m4(&m3, &mut s_state, skp);
            let mut m4_bytes = Vec::new();
            m4.serialize_compressed(&mut m4_bytes)
                .expect("Failed to serialize Issuance M4");
            println!("Bytes sent issuance (m4_message_bytes): {}", m4_bytes.len());

            // Serialize SKP
            let mut skp_bytes = Vec::new();
            skp.serialize_compressed(&mut skp_bytes)
                .expect("Failed to serialize ServerKeyPair");

            // Also send the collection-procedure first message
            let collection_m1 =
                CollectionStateS::<Config>::generate_collection_m1(&mut rng, &mut col_state);
            *cbsm_lock = col_state;

            let mut m1_c_bytes = Vec::new();
            collection_m1
                .serialize_compressed(&mut m1_c_bytes)
                .expect("Failed to serialize Collection M1");
            println!(
                "Bytes sent collection: (m1_message_bytes): {}",
                m1_c_bytes.len()
            );

            let mut response_bytes = Vec::new();
            response_bytes.extend_from_slice(&m4_bytes);
            response_bytes.extend_from_slice(&skp_bytes);
            response_bytes.extend_from_slice(&m1_c_bytes);

            println!("Sending M4 and first of Collection...");

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_bytes))
                .expect("Failed to create response"))
        }
        MessageType::M6 => {
            println!("Received m2 message of collection, processing...");

            let m7: CBCM2 = CBCM2::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Collection M2");

            let v = <Config as CurveConfig>::ScalarField::one();
            let m8 = CollectionStateS::<Config>::generate_collection_m3(
                &mut rng,
                &m7,
                &mut col_state,
                skp,
                v,
            );

            *cbsm_lock = col_state;

            let mut m8_bytes = Vec::new();
            m8.serialize_compressed(&mut m8_bytes)
                .expect("Failed to serialize Collection M3");
            println!(
                "Bytes sent collection: (m3_message_bytes): {}",
                m8_bytes.len()
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(m8_bytes))
                .expect("Failed to create response"))
        }
        MessageType::M10 => {
            println!("Received m4 message of collection, processing...");

            let m10: CBCM4 = CBCM4::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Collection M4");

            let m11 = CBSM::generate_collection_m5(&m10, &mut col_state, skp);
            *cbsm_lock = col_state;

            let mut m11_bytes = Vec::new();
            m11.serialize_compressed(&mut m11_bytes)
                .expect("Failed to serialize Collection M5");
            println!(
                "Bytes sent collection: (m5_message_bytes): {}",
                m11_bytes.len()
            );

            // Also send the spend/verify-procedure first message
            let spendverify_m1 =
                SpendVerifyStateS::<Config>::generate_spendverify_m1(&mut rng, &mut spend_state);
            *sbsm_lock = spend_state;

            let mut m1_s_bytes = Vec::new();
            spendverify_m1
                .serialize_compressed(&mut m1_s_bytes)
                .expect("Failed to serialize Spend Verify M1");
            println!(
                "Bytes sent spend-verify: (m1_message_bytes): {}",
                m1_s_bytes.len()
            );

            let mut response_bytes = Vec::new();
            response_bytes.extend_from_slice(&m11_bytes);
            response_bytes.extend_from_slice(&m1_s_bytes);

            println!("Sending M5 and first of SpendVerify...");

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_bytes))
                .expect("Failed to create response"))
        }
        MessageType::M13 => {
            println!("Received m2 message of spend-verify, processing...");

            let m14: SBCM2 = SBCM2::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Spend-verify M2");

            let policy_state: Vec<<Config as CurveConfig>::ScalarField> =
                vec![<Config as CurveConfig>::ScalarField::from(2)];
            let m15 = SBSM::generate_spendverify_m3(
                &mut rng,
                &m14,
                &mut spend_state,
                skp,
                policy_state.clone(),
            );
            *sbsm_lock = spend_state;

            let mut m15_bytes = Vec::new();
            m15.serialize_compressed(&mut m15_bytes)
                .expect("Failed to serialize Spend-Verify M3");
            println!(
                "Bytes sent spend-verify: (m3_message_bytes): {}",
                m15_bytes.len()
            );

            println!("Sending M3 of SpendVerify...");

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(m15_bytes))
                .expect("Failed to create response"))
        }
        MessageType::M14 => {
            println!("Received m4 message of spend-verify, processing...");

            let m15: SBCM4 = SBCM4::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Spend-verify M4");

            let m16 = SBSM::generate_spendverify_m5(&m15, &mut spend_state, skp);
            *sbsm_lock = spend_state;

            let mut m16_bytes = Vec::new();
            m16.serialize_compressed(&mut m16_bytes)
                .expect("Failed to serialize Spend-Verify M6");
            println!(
                "Bytes sent spend-verify: (m5_message_bytes): {}",
                m16_bytes.len()
            );

            println!("Sending M5 of SpendVerify...");

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(m16_bytes))
                .expect("Failed to create response"))
        }
    }
}

// Function to redirect HTTP requests to HTTPS
#[allow(dead_code)]
async fn redirect_http_to_https(ports: Ports) {
    fn make_https(host: String, uri: Uri, ports: Ports) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
        }

        let https_host = host.replace(&ports.http.to_string(), &ports.https.to_string());
        parts.authority = Some(https_host.parse()?);

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(host, uri, ports) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}
