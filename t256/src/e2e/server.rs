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

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use boomerang::client::{IssuanceM1, IssuanceM3, IssuanceStateC};
use boomerang::server::ServerKeyPair;
use boomerang::server::{IssuanceM2, IssuanceStateS};
use t256::Config;

use rand_core::OsRng;

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

type SBKP = ServerKeyPair<Config>;
type IBCM = IssuanceStateC<Config>;
type IBSM = IssuanceStateS<Config>;
type IBCM1 = IssuanceM1<Config>;
type IBSM2 = IssuanceM2<Config>;
type IBCM3 = IssuanceM3<Config>;

#[derive(Serialize, Deserialize)]
enum MessageType {
    M1,
    M3,
}

#[derive(Serialize, Deserialize)]
struct Message {
    msg_type: MessageType,
    data: Vec<u8>, // Serialized data for IBCM or other relevant data
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

    let ibsm_lock = IBSM_DEFAULT.lock().unwrap();
    let mut s_state = ibsm_lock.clone();

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
            println!("Bytes sent (m2_message_bytes): {}", m2_bytes.len());

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
            println!("Bytes sent (m4_message_bytes): {}", m4_bytes.len());

            // Serialize SKP
            let mut skp_bytes = Vec::new();
            skp.serialize_compressed(&mut skp_bytes)
                .expect("Failed to serialize ServerKeyPair");

            let mut response_bytes = Vec::new();
            response_bytes.extend_from_slice(&m4_bytes);
            response_bytes.extend_from_slice(&skp_bytes);
            println!("Sending M4...");

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_bytes))
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
