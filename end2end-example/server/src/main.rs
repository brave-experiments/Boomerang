use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ark_ec::models::CurveConfig;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;
use boomerang::{
    client::{CollectionC, IssuanceC, SpendVerifyC},
    server::{CollectionS, IssuanceS, ServerKeyPair, SpendVerifyS},
};
use rand::rngs::OsRng;
use serde_json::json;
use t256::Config;

type SF = <Config as CurveConfig>::ScalarField;

async fn boomerang_spending_m5(data: web::Data<AppState>, req_body: String) -> impl Responder {
    println!("Boomerang Spending M5...");

    let parameters: Vec<Vec<u8>> = serde_json::from_str(&req_body).unwrap();

    // Deserialize spending_m4 from client
    let spending_m3_bytes: Vec<u8> = parameters[0].clone();
    let spending_m3 =
        SpendVerifyS::<Config>::deserialize_compressed(spending_m3_bytes.as_slice()).unwrap();

    // Deserialize spending_m4 from client
    let spending_m4_bytes: Vec<u8> = parameters[1].clone();
    let spending_m4 =
        SpendVerifyC::<Config>::deserialize_compressed(spending_m4_bytes.as_slice()).unwrap();

    let spending_m5 =
        SpendVerifyS::<Config>::generate_spendverify_m5(spending_m4, spending_m3, &data.skp);

    // Serialize spending_m3
    let mut spending_m5_bytes = Vec::new();
    spending_m5
        .serialize_compressed(&mut spending_m5_bytes)
        .unwrap();
    let spending_m5_json = json!(spending_m5_bytes).to_string();

    // send response
    println!("Boomerang Spending M5 - Send response...");
    HttpResponse::Ok().body(spending_m5_json)
}

async fn boomerang_spending_m3(data: web::Data<AppState>, req_body: String) -> impl Responder {
    println!("Boomerang Spending M3...");

    //println!("body: {req_body}");

    let parameters: Vec<Vec<u64>> = serde_json::from_str(&req_body).unwrap();

    // Deserialize spending_m2 from client
    let spending_m1_bytes: Vec<u8> = parameters[0]
        .clone()
        .into_iter()
        .map(|x: u64| x as u8)
        .collect();
    let spending_m1 =
        SpendVerifyS::<Config>::deserialize_compressed(spending_m1_bytes.as_slice()).unwrap();

    // Deserialize spending_m2 from client
    let spending_m2_bytes: Vec<u8> = parameters[1]
        .clone()
        .into_iter()
        .map(|x: u64| x as u8)
        .collect();
    let spending_m2 =
        SpendVerifyC::<Config>::deserialize_compressed(spending_m2_bytes.as_slice()).unwrap();

    let v: SF = SF::one();
    let state_vector = &parameters[2];
    let policy_vector = &parameters[3];

    let spending_m3 = SpendVerifyS::<Config>::generate_spendverify_m3(
        &mut OsRng,
        spending_m2,
        spending_m1,
        &data.skp,
        v,
        state_vector.to_vec(),
        policy_vector.to_vec(),
    );

    // Serialize spending_m3
    let mut spending_m3_bytes = Vec::new();
    spending_m3
        .serialize_compressed(&mut spending_m3_bytes)
        .unwrap();
    let spending_m3_json = json!(spending_m3_bytes).to_string();

    // send response
    println!("Boomerang Spending M3 - Send response...");
    HttpResponse::Ok().body(spending_m3_json)
}

async fn boomerang_spending_m1() -> impl Responder {
    println!("Boomerang Spending M1...");
    let spending_m1 = SpendVerifyS::<Config>::generate_spendverify_m1(&mut OsRng);

    // Serialize server key pair
    let mut spending_m1_bytes = Vec::new();
    spending_m1
        .serialize_compressed(&mut spending_m1_bytes)
        .unwrap();
    let spending_m1_json = json!(spending_m1_bytes).to_string();

    println!("Boomerang Spending M1 - Send response...");
    HttpResponse::Ok().body(spending_m1_json)
}

async fn boomerang_collection_m5(data: web::Data<AppState>, req_body: String) -> impl Responder {
    println!("Boomerang Collection M5...");

    let body: Vec<Vec<u8>> = serde_json::from_str(&req_body).unwrap();

    // Deserialize collection_m4 from client
    let collection_m3_bytes: Vec<u8> = body[0].clone();
    let collection_m3 =
        CollectionS::<Config>::deserialize_compressed(collection_m3_bytes.as_slice()).unwrap();

    // Deserialize collection_m4 from client
    let collection_m4_bytes: Vec<u8> = body[1].clone();
    let collection_m4 =
        CollectionC::<Config>::deserialize_compressed(collection_m4_bytes.as_slice()).unwrap();

    let collection_m5 =
        CollectionS::<Config>::generate_collection_m5(collection_m4, collection_m3, &data.skp);

    // Serialize collection_m3
    let mut collection_m5_bytes = Vec::new();
    collection_m5
        .serialize_compressed(&mut collection_m5_bytes)
        .unwrap();
    let collection_m5_json = json!(collection_m5_bytes).to_string();

    // send response
    println!("Boomerang Collection M5 - Send response...");
    HttpResponse::Ok().body(collection_m5_json)
}

async fn boomerang_collection_m3(data: web::Data<AppState>, req_body: String) -> impl Responder {
    println!("Boomerang Collection M3...");

    let body: Vec<Vec<u8>> = serde_json::from_str(&req_body).unwrap();

    // Deserialize collection_m2 from client
    let collection_m1_bytes: Vec<u8> = body[0].clone();
    let collection_m1 =
        CollectionS::<Config>::deserialize_compressed(collection_m1_bytes.as_slice()).unwrap();

    // Deserialize collection_m2 from client
    let collection_m2_bytes: Vec<u8> = body[1].clone();
    let collection_m2 =
        CollectionC::<Config>::deserialize_compressed(collection_m2_bytes.as_slice()).unwrap();

    let v: SF = SF::one();
    let collection_m3 = CollectionS::<Config>::generate_collection_m3(
        &mut OsRng,
        collection_m2,
        collection_m1,
        &data.skp,
        v,
    );

    // Serialize collection_m3
    let mut collection_m3_bytes = Vec::new();
    collection_m3
        .serialize_compressed(&mut collection_m3_bytes)
        .unwrap();
    let collection_m3_json = json!(collection_m3_bytes).to_string();

    // send response
    println!("Boomerang Collection M3 - Send response...");
    HttpResponse::Ok().body(collection_m3_json)
}

async fn boomerang_collection_m1() -> impl Responder {
    println!("Boomerang Collection M1...");
    let collection_m1 = CollectionS::<Config>::generate_collection_m1(&mut OsRng);

    // Serialize server key pair
    let mut collection_m1_bytes = Vec::new();
    collection_m1
        .serialize_compressed(&mut collection_m1_bytes)
        .unwrap();
    let collection_m1_json = json!(collection_m1_bytes).to_string();

    println!("Boomerang Collection M1 - Send response...");
    HttpResponse::Ok().body(collection_m1_json)
}

async fn boomerang_issuance_m4(data: web::Data<AppState>, req_body: String) -> impl Responder {
    println!("Boomerang Issuance M4...");

    let body: Vec<Vec<u8>> = serde_json::from_str(&req_body).unwrap();

    // Deserialize issuance_m2 from client
    let issuance_m2_bytes: Vec<u8> = body[0].clone();
    let issuance_m2 =
        IssuanceS::<Config>::deserialize_compressed(issuance_m2_bytes.as_slice()).unwrap();

    // Deserialize issuance_m3 from client
    let issuance_m3_bytes: Vec<u8> = body[1].clone();
    let issuance_m3 =
        IssuanceC::<Config>::deserialize_compressed(issuance_m3_bytes.as_slice()).unwrap();

    let issuance_m4 =
        IssuanceS::<Config>::generate_issuance_m4(issuance_m3, issuance_m2, &data.skp);

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

async fn boomerang_issuance_m2(data: web::Data<AppState>, req_body: String) -> impl Responder {
    println!("Boomerang Issuance M2...");
    // Deserialize issuance_m1 from client
    let issuance_m1_bytes: Vec<u8> = serde_json::from_str(&req_body).unwrap();
    let issuance_m1 = IssuanceC::<Config>::deserialize_compressed(&*issuance_m1_bytes).unwrap();

    let issuance_m2 = IssuanceS::<Config>::generate_issuance_m2(issuance_m1, &data.skp, &mut OsRng);

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

async fn server_keypair(data: web::Data<AppState>) -> impl Responder {
    println!("Boomerang Get Server KeyPair...");
    // Serialize server key pair
    let mut server_key_bytes = Vec::new();
    data.skp
        .serialize_compressed(&mut server_key_bytes)
        .unwrap();
    let server_key_json = json!(server_key_bytes).to_string();

    println!("Boomerang Get Server KeyPair - Send response...");
    HttpResponse::Ok().body(server_key_json)
}

// Shared state struct between all routes
struct AppState {
    skp: ServerKeyPair<Config>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Initializing server...");

    // Generate server key pair
    let app_state = web::Data::new(AppState {
        skp: ServerKeyPair::<Config>::generate(&mut OsRng),
    });

    println!("Start HTTP server. Wait for requests...");
    // Start the HTTP server
    HttpServer::new(move || {
        App::new()
            // share the app state between the routes
            .app_data(app_state.clone())
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
            .route(
                "/boomerang_collection_m1",
                web::get().to(boomerang_collection_m1),
            )
            .route(
                "/boomerang_collection_m3",
                web::post().to(boomerang_collection_m3),
            )
            .route(
                "/boomerang_collection_m5",
                web::post().to(boomerang_collection_m5),
            )
            .route(
                "/boomerang_spending_m1",
                web::get().to(boomerang_spending_m1),
            )
            .route(
                "/boomerang_spending_m3",
                web::post().to(boomerang_spending_m3),
            )
            .route(
                "/boomerang_spending_m5",
                web::post().to(boomerang_spending_m5),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
