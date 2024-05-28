use boomerang::{
    client::{UKeyPair, IssuanceC},
    //client::{CollectionC, SpendVerifyC},
    server::IssuanceS,
};
use rand::rngs::OsRng;
use serde_json::json;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use t256::Config;   // use arksecp256r1

#[tokio::main]
async fn main() {

    // Generate user keys
    let ckp = UKeyPair::<Config>::generate(&mut OsRng);

    // start issuance protocol
    let issuance_m1 = IssuanceC::<Config>::generate_issuance_m1(ckp.clone(), &mut OsRng);

    // serialize issuance_m1 as json string
    let mut issuance_m1_bytes = Vec::new();
    issuance_m1.serialize_compressed(&mut issuance_m1_bytes).unwrap();
    let issuance_m1_json = json!(issuance_m1_bytes).to_string();

    // send issuance_m1 as json string to server
    println!("Send issuance_m1 to server");
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:8080/boomerang_issuance_m2")
        .header("Content-Type", "application/json")
        .body(issuance_m1_json)
        .send()
        .await;

    let response_body = response.unwrap().text().await;
    //println!("Response body:\n{}", response_body.unwrap());

    // deserialize issuance_m2 response from server
    println!("deserialize response");
    let issuance_m2_bytes: Vec<u8> = serde_json::from_str(&response_body.unwrap()).unwrap();
    let issuance_m2 = IssuanceS::<Config>::deserialize_compressed(&*issuance_m2_bytes).unwrap();

    println!("check some properties");
    assert!(issuance_m2.m2.verifying_key.is_on_curve());
    assert!(issuance_m2.m2.tag_key.is_on_curve());
    println!("fin");
}
