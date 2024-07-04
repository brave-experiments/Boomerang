
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use acl::verify::SigVerify;
use ark_ec::models::CurveConfig;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use boomerang::{
    client::{CollectionC, IssuanceC, SpendVerifyC, UKeyPair},
    config::State,
    server::{CollectionS, IssuanceS, ServerKeyPair, SpendVerifyS},
};
use rand::rngs::OsRng;
use serde_json::json;
use t256::Config; // use arksecp256r1

use tokio::task;

type SF = <Config as CurveConfig>::ScalarField;

// functions to benchmark
async fn boomerang_protocol() {
    // Generate user keys
    let ckp = UKeyPair::<Config>::generate(&mut OsRng);
    // Get server key from server
    let skp = get_server_keypair_from_server().await;

    let issuance_state: State<Config> = issuance_protocol(ckp.clone(), skp.clone()).await;
    let collection_state = collection_protocol(ckp.clone(), skp.clone(), issuance_state).await;
    spending_protocol(ckp, skp, collection_state).await;
}

async fn issuance_protocol(ckp: UKeyPair<Config>, skp: ServerKeyPair<Config>) -> State<Config> {
    // issuance m1
    let issuance_m1 = IssuanceC::<Config>::generate_issuance_m1(ckp.clone(), &mut OsRng);

    // send to server get m2
    let issuance_m2 = crate::issuance_send_message_to_server_and_await_response(
        issuance_m1.clone(),
        "http://localhost:8080/boomerang_issuance_m2".to_string(),
    )
    .await;

    // issuance m3
    let issuance_m3 =
        IssuanceC::<Config>::generate_issuance_m3(issuance_m1.clone(), issuance_m2, &mut OsRng);

    // send to server get m4
    let issuance_m4 = issuance_send_message_to_server_and_await_response(
        issuance_m3.clone(),
        "http://localhost:8080/boomerang_issuance_m4".to_string(),
    )
    .await;

    // populate state
    let issuance_state =
        IssuanceC::<Config>::populate_state(issuance_m3, issuance_m4, skp.clone(), ckp.clone());

    let sig = &issuance_state.sig_state[0];

    let check = SigVerify::<Config>::verify(
        skp.s_key_pair.verifying_key,
        skp.s_key_pair.tag_key,
        sig.clone(),
        "message",
    );
    assert!(check);

    issuance_state
}

async fn collection_protocol(
    ckp: UKeyPair<Config>,
    skp: ServerKeyPair<Config>,
    issuance_state: State<Config>,
) -> State<Config> {
    // collection m1 - request from server
    let collection_m1 = get_collection_m1().await;

    // collection m2
    let collection_m2 = CollectionC::<Config>::generate_collection_m2(
        &mut OsRng,
        issuance_state,
        collection_m1.clone(),
        skp.clone(),
    );

    // send to server get m3
    let collection_m3 = collection_send_message_to_server_and_await_response(
        collection_m2.clone(),
        "http://localhost:8080/boomerang_collection_m3".to_string(),
    )
    .await;

    // m4
    let collection_m4 = CollectionC::<Config>::generate_collection_m4(
        &mut OsRng,
        collection_m2.clone(),
        collection_m3.clone(),
    );

    // send to server get m5
    let collection_m5 = collection_send_message_to_server_and_await_response(
        collection_m4.clone(),
        "http://localhost:8080/boomerang_collection_m5".to_string(),
    )
    .await;

    // populate state
    let collection_state = CollectionC::<Config>::populate_state(
        collection_m4.clone(),
        collection_m5.clone(),
        skp.clone(),
        ckp.clone(),
    );

    // signature
    let sig_n = &collection_state.sig_state[0];

    let check = SigVerify::<Config>::verify(
        skp.s_key_pair.verifying_key,
        skp.s_key_pair.tag_key,
        sig_n.clone(),
        "message",
    );
    assert!(check);

    collection_state
}

async fn spending_protocol(
    ckp: UKeyPair<Config>,
    skp: ServerKeyPair<Config>,
    collection_state: State<Config>,
) -> State<Config> {
    // spending m1 - request from server
    let spendverify_m1 = get_spending_m1().await;

    // spending m2
    let spendverify_m2 = SpendVerifyC::<Config>::generate_spendverify_m2(
        &mut OsRng,
        collection_state,
        spendverify_m1,
        skp.clone(),
    );


    let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
    let state_vector = vec![5u64; 64];

    // send to server get m3
    let spendverify_m3 = spending_send_message_to_server_and_await_response(
        spendverify_m2.clone(),
        "http://localhost:8080/boomerang_spending_m3".to_string(),
        Some(vec![policy_vector.clone(), state_vector]),
    )
    .await;

    // m4
    let spendverify_m4 = SpendVerifyC::<Config>::generate_spendverify_m4(
        &mut OsRng,
        spendverify_m2.clone(),
        spendverify_m3.clone(),
        policy_vector,
    );

    // send to server get m5
    let spendverify_m5 = spending_send_message_to_server_and_await_response(
           spendverify_m4.clone(),
           "http://localhost:8080/boomerang_spending_m5".to_string(),
           None,
    )
    .await;

    // populate state
    let spending_state = SpendVerifyC::<Config>::populate_state(
           spendverify_m4,
           spendverify_m5,
           skp.clone(),
           ckp.clone(),
    );

    let sig_n = &spending_state.sig_state[0];

    let check = SigVerify::<Config>::verify(
        skp.s_key_pair.verifying_key,
        skp.s_key_pair.tag_key,
        sig_n.clone(),
        "message",
    );
    assert!(check);

    spending_state
}

// helper functions
async fn get_server_keypair_from_server() -> ServerKeyPair<Config> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8080/server_keypair")
        .send()
        .await;

    let response_body = response.unwrap().text().await;

    // deserialize server keypair
    let server_keypair_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    ServerKeyPair::<Config>::deserialize_compressed(&*server_keypair_bytes).unwrap()
}

async fn get_collection_m1() -> CollectionS<Config> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8080/boomerang_collection_m1")
        .send()
        .await;

    let response_body = response.unwrap().text().await;

    // deserialize message m1
    let collection_m1_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    CollectionS::<Config>::deserialize_compressed(&*collection_m1_bytes).unwrap()
}

async fn get_spending_m1() -> SpendVerifyS<Config> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8080/boomerang_spending_m1")
        .send()
        .await;

    let response_body = response.unwrap().text().await;

    // deserialize message m1
    let spending_m1_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    SpendVerifyS::<Config>::deserialize_compressed(&*spending_m1_bytes).unwrap()
}

async fn issuance_send_message_to_server_and_await_response(
    issuance_c: IssuanceC<Config>,
    endpoint: String,
) -> IssuanceS<Config> {
    // serialize issuance_m1 as json string
    let mut issuance_c_bytes = Vec::new();
    issuance_c
        .serialize_compressed(&mut issuance_c_bytes)
        .unwrap();
    let issuance_c_json = json!(issuance_c_bytes).to_string();

    // send issuance_m1 as json string to server
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(issuance_c_json)
        .send()
        .await;

    let response_body = response.unwrap().text().await;
    //println!("Response body:\n{}", response_body.unwrap());

    // deserialize issuance_m2 response from server
    let issuance_s_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    IssuanceS::<Config>::deserialize_compressed(&*issuance_s_bytes).unwrap()
}

async fn collection_send_message_to_server_and_await_response(
    collection_c: CollectionC<Config>,
    endpoint: String,
) -> CollectionS<Config> {
    // serialize issuance_m* as json string
    let mut collection_c_bytes = Vec::new();
    collection_c
        .serialize_compressed(&mut collection_c_bytes)
        .unwrap();
    let collection_c_json = json!(collection_c_bytes).to_string();

    // send collection_m* as json string to server
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(collection_c_json)
        .send()
        .await;

    let response_body = response.unwrap().text().await;
    //println!("Response body:\n{}", response_body.unwrap());

    // deserialize collection_m2 response from server
    let collection_s_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    CollectionS::<Config>::deserialize_compressed(&*collection_s_bytes).unwrap()
}

async fn spending_send_message_to_server_and_await_response(
    spending_c: SpendVerifyC<Config>,
    endpoint: String,
    additional_parameters: Option<Vec<Vec<u64>>>,
) -> SpendVerifyS<Config> {
    // serialize spending_m* as json string
    let mut spending_c_bytes = Vec::new();
    spending_c
        .serialize_compressed(&mut spending_c_bytes)
        .unwrap();

    // if there are additional parameters, then add it to the body
    let body: String;
    if let Some(mut params) = additional_parameters {
        let spending_c_u64 = spending_c_bytes.into_iter().map(u64::from).collect();
        params.push(spending_c_u64);
        body = serde_json::to_string(&params).unwrap();
    } else {
        body = json!(spending_c_bytes).to_string();
    }

    // send spending_m* as json string to server
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await;

    let response_body = response.unwrap().text().await;
    //println!("Response body:\n{}", response_body.unwrap());

    // deserialize spending_m* response from server
    let spending_s_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    SpendVerifyS::<Config>::deserialize_compressed(&*spending_s_bytes).unwrap()
}

// Benchmarking functions
// This function runs an entire boomerang protocol for multiple users
fn benchmark_boomerang_mult_users(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let number_of_users = 1;

    // customize sample count
    let mut c_custom = Criterion::default().sample_size(10);

    c_custom.bench_function("boomerang-mult-user", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate multiple users by spawning multiple tasks
            let tasks: Vec<_> = (0..number_of_users).map(|_| {
                task::spawn(async move {
                    boomerang_protocol().await
                })
            }).collect();

            // Await all tasks
            for task in tasks {
                task.await.unwrap();
            }
        });
    });
}

criterion_group!(benches, benchmark_boomerang_mult_users);
criterion_main!(benches);
