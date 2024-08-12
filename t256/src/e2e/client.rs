#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::await_holding_lock)]

use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use boomerang::client::IssuanceC;
use boomerang::client::UKeyPair;
use boomerang::server::IssuanceS;
use boomerang::server::ServerKeyPair;
use lazy_static::lazy_static;
use std::sync::Mutex;
use t256::Config;

type CBKP = UKeyPair<Config>;
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
    data: Vec<u8>,
}

lazy_static! {
    static ref M3_BYTES_C: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a Reqwest client
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Accept self-signed certificates
        .build()?;

    let mut rng = OsRng;
    let kp = CBKP::generate(&mut rng);
    let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut rng);
    let mut m1_bytes = Vec::new();
    m1.serialize_compressed(&mut m1_bytes).unwrap();

    let m1_message = Message {
        msg_type: MessageType::M1,
        data: m1_bytes,
    };
    let m1_message_bytes = bincode::serialize(&m1_message).unwrap();

    let http_response = client
        .post("http://127.0.0.1:7878")
        .body(m1_message_bytes.clone())
        .send()
        .await?;

    if http_response.status().is_success() {
        let m2_bytes = http_response.bytes().await?;
        let m2: IBSM = IBSM::deserialize_compressed(&mut m2_bytes.as_ref())
            .expect("Failed to deserialize compressed Issuance M2");

        let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut rng);
        let mut m3_bytes = Vec::new();
        m3.serialize_compressed(&mut m3_bytes).unwrap();

        let m3_message = Message {
            msg_type: MessageType::M3,
            data: m3_bytes,
        };
        let m3_message_bytes = bincode::serialize(&m3_message).unwrap();

        let m3_response = client
            .post("http://127.0.0.1:7878")
            .body(m3_message_bytes)
            .send()
            .await?;

        if m3_response.status().is_success() {
            println!("Successfully sent m3 to the server.");

            let m4_bytes = m3_response.bytes().await?;
            let _m4: IBSM = IBSM::deserialize_compressed(&mut m4_bytes.as_ref())
                .expect("Failed to deserialize Issuance M4");
            println!("Successfully received m4 from the server.");
        } else {
            println!("Failed to send m3. Status: {}", m3_response.status());
        }
    } else {
        println!("HTTP Error: {}", http_response.status());
    }

    let https_response = client
        .post("https://127.0.0.1:3000")
        .body(m1_message_bytes.clone())
        .send()
        .await?;

    if https_response.status().is_success() {
        let m2_bytes = https_response.bytes().await?;
        let m2: IBSM = IBSM::deserialize_compressed(&mut m2_bytes.as_ref())
            .expect("Failed to deserialize compressed Issuance M2");

        let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut rng);
        let mut m3_bytes = Vec::new();
        m3.serialize_compressed(&mut m3_bytes).unwrap();

        let mut m3_bytes_c = M3_BYTES_C.lock().unwrap();
        m3_bytes_c.clone_from(&m3_bytes);

        let m3_message = Message {
            msg_type: MessageType::M3,
            data: m3_bytes,
        };
        let m3_message_bytes = bincode::serialize(&m3_message).unwrap();

        let m3_response = client
            .post("http://127.0.0.1:7878")
            .body(m3_message_bytes)
            .send()
            .await?;

        if m3_response.status().is_success() {
            println!("Successfully sent m3 to the server.");

            let m4_bytes = m3_response.bytes().await?;
            let _m4: IBSM = IBSM::deserialize_compressed(&mut m4_bytes.as_ref())
                .expect("Failed to deserialize Issuance M4");
            println!("Successfully received m4 from the server.");

            let _m3: IBCM = IBCM::deserialize_compressed::<&[u8]>(&mut m3_bytes_c.as_ref())
                .expect("Failed to deserialize compressed Issuance M2");

            //let skp = SBKP::generate(&mut rng); // FIX
            //let state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());

            println!("Issuance state fullfilled!");
        } else {
            println!("Failed to send m3. Status: {}", m3_response.status());
        }
    } else {
        println!("HTTPS Error: {}", https_response.status());
    }

    Ok(())
}
