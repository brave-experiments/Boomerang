use acl::verify::SigVerify;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use boomerang::{
    client::{CollectionC, IssuanceC, SpendVerifyC, UKeyPair},
    server::{CollectionS, IssuanceS, ServerKeyPair, SpendVerifyS},
};
use bytes::Bytes;
use rand::rngs::OsRng;
use serde_json::json;
use t256::Config; // use arksecp256r1

static SERVER_ENDPOINT: &str = "localhost:8080";

async fn get_server_keypair_from_server() -> ServerKeyPair<Config> {
    let client = reqwest::Client::new();
    let endpoint = format!("http://{}{}", SERVER_ENDPOINT, "/server_keypair");

    let request = client
        .get(endpoint)
        .header("Content-Type", "application/json")
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize server keypair
    let server_keypair_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    ServerKeyPair::<Config>::deserialize_compressed(&*server_keypair_bytes).unwrap()
}

async fn get_collection_m1() -> CollectionS<Config> {
    let client = reqwest::Client::new();
    let endpoint = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_collection_m1");

    let request = client
        .get(endpoint)
        .header("Content-Type", "application/json")
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize message m1
    let collection_m1_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    CollectionS::<Config>::deserialize_compressed(&*collection_m1_bytes).unwrap()
}

async fn get_spending_m1() -> SpendVerifyS<Config> {
    let client = reqwest::Client::new();
    let endpoint = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_spending_m1");

    let request = client
        .get(endpoint)
        .header("Content-Type", "application/json")
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize message m1
    let spending_m1_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    SpendVerifyS::<Config>::deserialize_compressed(&*spending_m1_bytes).unwrap()
}

async fn issuance_send_m1_get_m2(
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

    let request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(issuance_c_json)
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize issuance_m2 response from server
    let issuance_s_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    IssuanceS::<Config>::deserialize_compressed(&*issuance_s_bytes).unwrap()
}

async fn issuance_send_m2m3_get_m4(
    issuance_m2: IssuanceS<Config>,
    issuance_m3: IssuanceC<Config>,
    endpoint: String,
) -> IssuanceS<Config> {
    // serialize issuance_m1 as json string
    let mut issuance_m2_bytes = Vec::new();
    issuance_m2
        .serialize_compressed(&mut issuance_m2_bytes)
        .unwrap();
    let mut issuance_m3_bytes = Vec::new();
    issuance_m3
        .serialize_compressed(&mut issuance_m3_bytes)
        .unwrap();

    let body_vec = vec![issuance_m2_bytes, issuance_m3_bytes];
    let body = serde_json::to_string(&body_vec).unwrap();

    // send issuance_m1 as json string to server
    let client = reqwest::Client::new();

    let request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body)
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize issuance_m4 response from server
    let issuance_m4_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    IssuanceS::<Config>::deserialize_compressed(&*issuance_m4_bytes).unwrap()
}

async fn collection_send_m1m2_get_m3(
    collection_m1: CollectionS<Config>,
    collection_m2: CollectionC<Config>,
    endpoint: String,
) -> CollectionS<Config> {
    // serialize collection_m1 as json string
    let mut collection_m1_bytes = Vec::new();
    collection_m1
        .serialize_compressed(&mut collection_m1_bytes)
        .unwrap();

    // serialize collection_m1 as json string
    let mut collection_m2_bytes = Vec::new();
    collection_m2
        .serialize_compressed(&mut collection_m2_bytes)
        .unwrap();

    let body_vec = vec![collection_m1_bytes, collection_m2_bytes];
    let body = serde_json::to_string(&body_vec).unwrap();

    // send collection_m* as json string to server
    let client = reqwest::Client::new();

    let request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body)
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize collection_m3 response from server
    let collection_s_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    CollectionS::<Config>::deserialize_compressed(&*collection_s_bytes).unwrap()
}

async fn collection_send_m3m4_get_m5(
    collection_m3: CollectionS<Config>,
    collection_m4: CollectionC<Config>,
    endpoint: String,
) -> CollectionS<Config> {
    // serialize collection_m3 as json string
    let mut collection_m3_bytes = Vec::new();
    collection_m3
        .serialize_compressed(&mut collection_m3_bytes)
        .unwrap();

    // serialize collection_m4 as json string
    let mut collection_m4_bytes = Vec::new();
    collection_m4
        .serialize_compressed(&mut collection_m4_bytes)
        .unwrap();

    let body_vec = vec![collection_m3_bytes, collection_m4_bytes];
    let body = serde_json::to_string(&body_vec).unwrap();

    // send collection_m* as json string to server
    let client = reqwest::Client::new();

    let request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body)
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize collection_m5 response from server
    let collection_s_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    CollectionS::<Config>::deserialize_compressed(&*collection_s_bytes).unwrap()
}

async fn spending_send_m1m2_get_m3(
    spending_m1: SpendVerifyS<Config>,
    spending_m2: SpendVerifyC<Config>,
    endpoint: String,
    policy_vector: Vec<u64>,
    state_vector: Vec<u64>,
) -> SpendVerifyS<Config> {
    // serialize spending_m* as json string
    let mut spending_m1_bytes = Vec::new();
    spending_m1
        .serialize_compressed(&mut spending_m1_bytes)
        .unwrap();
    // serialize spending_m* as json string
    let mut spending_m2_bytes = Vec::new();
    spending_m2
        .serialize_compressed(&mut spending_m2_bytes)
        .unwrap();

    let spending_m1_u64: Vec<u64> = spending_m1_bytes.into_iter().map(u64::from).collect();
    let spending_m2_u64: Vec<u64> = spending_m2_bytes.into_iter().map(u64::from).collect();
    let body_vec: Vec<Vec<u64>> = vec![
        spending_m1_u64,
        spending_m2_u64,
        state_vector,
        policy_vector,
    ];
    let body = serde_json::to_string(&body_vec).unwrap();

    // send spending_m* as json string to server
    let client = reqwest::Client::new();

    let request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body)
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize spending_m* response from server
    let spending_s_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    SpendVerifyS::<Config>::deserialize_compressed(&*spending_s_bytes).unwrap()
}

async fn spending_send_m3m4_get_m5(
    spending_m3: SpendVerifyS<Config>,
    spending_m4: SpendVerifyC<Config>,
    endpoint: String,
) -> SpendVerifyS<Config> {
    // serialize spending_m* as json string
    let mut spending_m3_bytes = Vec::new();
    spending_m3
        .serialize_compressed(&mut spending_m3_bytes)
        .unwrap();
    // serialize spending_m* as json string
    let mut spending_m4_bytes = Vec::new();
    spending_m4
        .serialize_compressed(&mut spending_m4_bytes)
        .unwrap();

    let body_vec = vec![spending_m3_bytes, spending_m4_bytes];
    let body = serde_json::to_string(&body_vec).unwrap();

    // send spending_m* as json string to server
    let client = reqwest::Client::new();

    let request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body)
        .build()
        .unwrap();

    // Calculate request size
    let request_size = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + request
            .body()
            .map_or(0, |body| body.as_bytes().map_or(0, |b| b.len()));

    let response = client.execute(request).await.unwrap();

    let headers = response.headers().clone();
    let response_body = response.text().await.unwrap();

    // Calculate response size
    let response_size = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        + Bytes::from(response_body.clone()).len();

    println!("Request size: {} bytes", request_size);
    println!("Response size: {} bytes", response_size);
    println!(
        "Total data consumption: {} bytes",
        request_size + response_size
    );

    // deserialize spending_m* response from server
    let spending_s_bytes: Vec<u8> = serde_json::from_str(&response_body).unwrap();
    SpendVerifyS::<Config>::deserialize_compressed(&*spending_s_bytes).unwrap()
}

#[tokio::main]
async fn main() {
    // Generate user keys
    let ckp = UKeyPair::<Config>::generate(&mut OsRng);

    // Get server key from server
    let skp = get_server_keypair_from_server().await;

    println!("Client: Start issuing protocol...");
    // start issuance protocol
    let issuance_state = {
        // issuance m1
        println!("Client: Generate M1");
        let issuance_m1 = IssuanceC::<Config>::generate_issuance_m1(ckp.clone(), &mut OsRng);

        // send to server get m2
        println!("Client: Send M1 to server and retrieve M2");
        let endpoint = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_issuance_m2");
        let issuance_m2 = issuance_send_m1_get_m2(issuance_m1.clone(), endpoint).await;
        // check some properties
        assert!(issuance_m2.m2.verifying_key.is_on_curve());
        assert!(issuance_m2.m2.tag_key.is_on_curve());

        // issuance m3
        println!("Client: Generate M3");
        let issuance_m3 = IssuanceC::<Config>::generate_issuance_m3(
            issuance_m1.clone(),
            issuance_m2.clone(),
            &mut OsRng,
        );

        // send to server get m4
        println!("Client: Send M3 to server and retrieve M4");
        let endpoint2 = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_issuance_m4");
        let issuance_m4 =
            issuance_send_m2m3_get_m4(issuance_m2.clone(), issuance_m3.clone(), endpoint2).await;

        // populate state
        let issuance_state =
            IssuanceC::<Config>::populate_state(issuance_m3, issuance_m4, skp.clone(), ckp.clone());

        let sig = &issuance_state.sig_state[0];

        println!("Client: Verify Signature");
        let check = SigVerify::<Config>::verify(
            skp.s_key_pair.verifying_key,
            skp.s_key_pair.tag_key,
            &sig,
            "message",
        );
        assert!(check);
        println!("Client: Issuance Signature check passed!");
        issuance_state
    };

    // start collection protocol
    println!("Client: Start collection protocol...");
    let collection_state = {
        // collection m1 - request from server
        println!("Client: Request M1 from server");
        let collection_m1 = get_collection_m1().await;

        // collection m2
        println!("Client: Generate M2");
        let collection_m2 = CollectionC::<Config>::generate_collection_m2(
            &mut OsRng,
            issuance_state,
            collection_m1.clone(),
            skp.clone(),
        );
        assert!(collection_m2.m2.comm.comm.is_on_curve());

        // send to server get m3
        println!("Client: Send M2 to server and retrieve M3");
        let endpoint = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_collection_m3");
        let collection_m3 =
            collection_send_m1m2_get_m3(collection_m1.clone(), collection_m2.clone(), endpoint)
                .await;

        // m4
        println!("Client: Generate M4");
        let collection_m4 = CollectionC::<Config>::generate_collection_m4(
            &mut OsRng,
            collection_m2.clone(),
            collection_m3.clone(),
        );

        // send to server get m5
        println!("Client: Send M4 to server and retrieve M5");
        let endpoint2 = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_collection_m5");
        let collection_m5 =
            collection_send_m3m4_get_m5(collection_m3.clone(), collection_m4.clone(), endpoint2)
                .await;

        // populate state
        let collection_state = CollectionC::<Config>::populate_state(
            collection_m4.clone(),
            collection_m5.clone(),
            skp.clone(),
            ckp.clone(),
        );
        assert!(collection_state.sig_state[0].sigma.zeta.is_on_curve());
        assert!(collection_state.sig_state[0].sigma.zeta1.is_on_curve());

        // signature
        let sig_n = &collection_state.sig_state[0];

        println!("Client: Verify Signature");
        let check = SigVerify::<Config>::verify(
            skp.s_key_pair.verifying_key,
            skp.s_key_pair.tag_key,
            &sig_n,
            "message",
        );
        assert!(check);
        println!("Client: Collection Signature check passed!");

        collection_state
    };

    println!("Client: Start spending protocol...");
    let spending_state = {
        // spending m1 - request from server
        println!("Client: Request M1 from server");
        let spendverify_m1 = get_spending_m1().await;

        // spending m2
        println!("Client: Generate M2");
        let spendverify_m2 = SpendVerifyC::<Config>::generate_spendverify_m2(
            &mut OsRng,
            collection_state,
            spendverify_m1.clone(),
            skp.clone(),
        );
        assert!(spendverify_m2.m2.comm.comm.is_on_curve());

        // create policy vector
        // This policy vector defines how each incentive is rewarded.
        // For this proof of concept, we just assign a static value for
        // each incenitve.
        let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
        // This state vector defines the interactions with the incentive
        // system. For the proof of concept we simple assign a static value.
        let state_vector = vec![5u64; 64];

        // send to server get m3
        println!("Client: Send M2 to server and retrieve M3");
        let endpoint = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_spending_m3");
        let spendverify_m3 = spending_send_m1m2_get_m3(
            spendverify_m1.clone(),
            spendverify_m2.clone(),
            endpoint,
            policy_vector.clone(),
            state_vector,
        )
        .await;

        // m4
        println!("Client: Generate M4");
        let spendverify_m4 = SpendVerifyC::<Config>::generate_spendverify_m4(
            &mut OsRng,
            spendverify_m2.clone(),
            spendverify_m3.clone(),
            policy_vector,
        );

        // send to server get m5
        println!("Client: Send M4 to server and retrieve M5");
        let endpoint2 = format!("http://{}{}", SERVER_ENDPOINT, "/boomerang_spending_m5");
        let spendverify_m5 =
            spending_send_m3m4_get_m5(spendverify_m3.clone(), spendverify_m4.clone(), endpoint2)
                .await;

        // populate state
        let spending_state = SpendVerifyC::<Config>::populate_state(
            spendverify_m4,
            spendverify_m5,
            skp.clone(),
            ckp.clone(),
        );
        assert!(spending_state.sig_state[0].sigma.zeta.is_on_curve());
        assert!(spending_state.sig_state[0].sigma.zeta1.is_on_curve());

        spending_state
    };

    let sig_n = &spending_state.sig_state[0];

    println!("Client: Verify Signature");
    let check = SigVerify::<Config>::verify(
        skp.s_key_pair.verifying_key,
        skp.s_key_pair.tag_key,
        &sig_n,
        "message",
    );
    assert!(check);
    println!("Client: Spending Signature check passed!");
}
