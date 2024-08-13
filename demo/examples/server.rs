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
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use boomerang::client::IssuanceC;
use boomerang::server::IssuanceS;
use boomerang::server::ServerKeyPair;
use t256::Config;

use rand_core::OsRng;

#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

type SBKP = ServerKeyPair<Config>;
type IBCM = IssuanceC<Config>;
type IBSM = IssuanceS<Config>;

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let ports = Ports {
        http: 7878,
        https: 3000,
    };
    tokio::spawn(redirect_http_to_https(ports));

    tracing::debug!("generating tls config");
    let subject_alt_names = vec![
        "boomerang.example".to_string(),
        "localhost".to_string(),
    ];
    // Use a self-signed cert for easier demonstration
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    let config = RustlsConfig::from_pem(cert_pem, key_pem).await?;

    let app = Router::new().route("/", get(handler).post(post_handler));

    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
    tracing::info!("listening for https on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn handler() -> &'static str {
    "Hello, Client!"
}

lazy_static! {
    static ref M2_BYTES_C: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static ref SKP: Mutex<Option<SBKP>> = Mutex::new(None);
}

async fn post_handler(body: Body) -> Result<Response, Infallible> {
    let bytes = body::to_bytes(body, usize::MAX).await.unwrap();
    let message: Message = bincode::deserialize(&bytes).expect("Failed to deserialize message");
    let mut rng = OsRng;
    {
        let mut skp_lock = SKP.lock().unwrap();
        if skp_lock.is_none() {
            *skp_lock = Some(SBKP::generate(&mut rng));
        }
    }

    let skp_lock = SKP.lock().unwrap();
    let skp = skp_lock.as_ref().unwrap();

    match message.msg_type {
        MessageType::M1 => {
            println!("Received m1 message, processing...");
            let m1: IBCM = IBCM::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Issuance M1");

            let m2 = IssuanceS::<Config>::generate_issuance_m2(m1, skp, &mut rng);
            let mut m2_bytes = Vec::new();
            m2.serialize_compressed(&mut m2_bytes)
                .expect("Failed to serialize Issuance M2");

            let mut m2_bytes_c = M2_BYTES_C.lock().unwrap();
            m2_bytes_c.clone_from(&m2_bytes);

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(m2_bytes))
                .expect("Failed to create response"))
        }
        MessageType::M3 => {
            println!("Received m3 message, processing...");

            let m3: IBCM = IBCM::deserialize_compressed(&mut message.data.as_slice())
                .expect("Failed to deserialize compressed Issuance M3");

            let m2_bytes_c = M2_BYTES_C.lock().unwrap();
            let m2: IBSM = IBSM::deserialize_compressed::<&[u8]>(m2_bytes_c.as_ref())
                .expect("Failed to deserialize compressed Issuance M2");

            let m4 = IssuanceS::<Config>::generate_issuance_m4(m3.clone(), m2.clone(), skp);
            let mut m4_bytes = Vec::new();
            m4.serialize_compressed(&mut m4_bytes)
                .expect("Failed to serialize Issuance M4");

            println!("Sending M4...");

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(m4_bytes))
                .expect("Failed to create response"))
        }
    }
}

// Function to redirect HTTP requests to HTTPS
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
    tracing::info!("listening for  http on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}
