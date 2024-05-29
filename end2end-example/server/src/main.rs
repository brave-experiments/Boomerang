use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use boomerang::{
    client::IssuanceC,
    server::{IssuanceS, ServerKeyPair},
};
use rand::rngs::OsRng;
use serde_json::json;
use std::sync::{Arc, Mutex};
use t256::Config;

async fn boomerang_issuance_m4(data: web::Data<Arc<AppState>>, req_body: String) -> impl Responder {
    println!("Boomerang Issunance M4...");
    // Deserialize issuance_m1 from client
    let issuance_m3_bytes: Vec<u8> = serde_json::from_str(&req_body).unwrap();
    let issuance_m3 = IssuanceC::<Config>::deserialize_compressed(&*issuance_m3_bytes).unwrap();

    let issuance_s = data.issuance_s.lock().unwrap().clone();

    let issuance_m4 = IssuanceS::<Config>::generate_issuance_m4(
        issuance_m3,
        issuance_s.unwrap(),
        data.skp.clone(),
    );

    // Serialize issuance_m4
    let mut issuance_m4_bytes = Vec::new();
    issuance_m4
        .serialize_compressed(&mut issuance_m4_bytes)
        .unwrap();
    let issuance_m4_json = json!(issuance_m4_bytes).to_string();

    // send response
    println!("Boomerang Issuance M4 - Send response...");
    HttpResponse::Ok().body(issuance_m4_json)
}

async fn boomerang_issuance_m2(data: web::Data<Arc<AppState>>, req_body: String) -> impl Responder {
    println!("Boomerang Issunance M2...");
    // Deserialize issuance_m1 from client
    let issuance_m1_bytes: Vec<u8> = serde_json::from_str(&req_body).unwrap();
    let issuance_m1 = IssuanceC::<Config>::deserialize_compressed(&*issuance_m1_bytes).unwrap();

    let issuance_m2 =
        IssuanceS::<Config>::generate_issuance_m2(issuance_m1, data.skp.clone(), &mut OsRng);
    let mut issuance_s = data.issuance_s.lock().unwrap();
    *issuance_s = Some(issuance_m2.clone());

    // Serialize issuance_m2
    let mut issuance_m2_bytes = Vec::new();
    issuance_m2
        .serialize_compressed(&mut issuance_m2_bytes)
        .unwrap();
    let issuance_m2_json = json!(issuance_m2_bytes).to_string();

    // send response
    println!("Boomerang Issuance M2 - Send response...");
    HttpResponse::Ok().body(issuance_m2_json)
}

async fn server_keypair(data: web::Data<Arc<AppState>>) -> impl Responder {
    // Serialize server key pair
    let mut server_key_bytes: Vec<u8> = Vec::new();
    data.skp
        .serialize_compressed(&mut server_key_bytes)
        .unwrap();
    let server_key_json = json!(server_key_bytes).to_string();

    HttpResponse::Ok().body(server_key_json)
}

// Shared state struct between all routes
struct AppState {
    skp: ServerKeyPair<Config>,
    issuance_s: Mutex<Option<IssuanceS<Config>>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Initializing server...");

    // Generate server key pair
    let skp = ServerKeyPair::<Config>::generate(&mut OsRng);
    let app_state = Arc::new(AppState {
        skp: skp,
        issuance_s: Mutex::new(None),
    });

    println!("Start HTTP server. Wait for requests...");
    // Start the HTTP server
    HttpServer::new(move || {
        App::new()
            // share the app state between the routes
            .app_data(web::Data::new(app_state.clone()))
            // configure routes
            .route(
                "/boomerang_issuance_m2",
                web::post().to(boomerang_issuance_m2),
            )
            .route(
                "/boomerang_issuance_m4",
                web::post().to(boomerang_issuance_m4),
            )
            .route("/server_keypair", web::get().to(server_keypair))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
