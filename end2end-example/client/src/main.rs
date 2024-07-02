use acl::verify::SigVerify;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use boomerang::{
    client::{CollectionC, IssuanceC, SpendVerifyC, UKeyPair},
    server::{CollectionS, IssuanceS, ServerKeyPair},
};
use rand::rngs::OsRng;
use serde_json::json;
use t256::Config; // use arksecp256r1

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
    println!("Send issuance_m1 to server");
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
    println!("deserialize response");
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
    println!("Send collection_m* to server");
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
    println!("deserialize response");
    let collection_s_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    CollectionS::<Config>::deserialize_compressed(&*collection_s_bytes).unwrap()
}

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

#[tokio::main]
async fn main() {
    // Generate user keys
    let ckp = UKeyPair::<Config>::generate(&mut OsRng);

    // Get server key from server
    let skp = get_server_keypair_from_server().await;

    // start issuance protocol
    let issuance_state = {
        // issuance m1
        let issuance_m1 = IssuanceC::<Config>::generate_issuance_m1(ckp.clone(), &mut OsRng);

        // send to server get m2
        let issuance_m2 = issuance_send_message_to_server_and_await_response(
            issuance_m1.clone(),
            "http://localhost:8080/boomerang_issuance_m2".to_string(),
        )
        .await;
        // check some properties
        println!("check some properties");
        assert!(issuance_m2.m2.verifying_key.is_on_curve());
        assert!(issuance_m2.m2.tag_key.is_on_curve());
        println!("fin");

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
        println!("Signature check passed!");
        issuance_state
    };

    // start collection protocol
    let collection_state = {
        // collection m1 - request from server
        let collection_m1 = get_collection_m1().await;

        // collection m2
        let collection_m2 = CollectionC::<Config>::generate_collection_m2(
            &mut OsRng,
            issuance_state,
            collection_m1.clone(),
            skp.clone(),
        );
        assert!(collection_m2.m2.comm.comm.is_on_curve());

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
        assert!(collection_state.sig_state[0].sigma.zeta.is_on_curve());
        assert!(collection_state.sig_state[0].sigma.zeta1.is_on_curve());

        // signature
        let sig_n = &collection_state.sig_state[0];

        let check = SigVerify::<Config>::verify(
            skp.s_key_pair.verifying_key,
            skp.s_key_pair.tag_key,
            sig_n.clone(),
            "message",
        );
        assert!(check);
        println!("Signature check passed!");

        collection_state
    };
}
