#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::await_holding_lock)]

use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use boomerang::client::UKeyPair;
use boomerang::client::{CollectionM4, CollectionStateC, IssuanceM3, IssuanceStateC};
use boomerang::server::ServerKeyPair;
use boomerang::server::{
    CollectionM1, CollectionM3, CollectionM5, IssuanceM2, IssuanceM4, IssuanceStateS,
};
use t256::Config;

type CBKP = UKeyPair<Config>;
type SBKP = ServerKeyPair<Config>;
type IBCM = IssuanceStateC<Config>;
type IBSM = IssuanceStateS<Config>;
type IBSM2 = IssuanceM2<Config>;
type IBCM3 = IssuanceM3<Config>;
type IBSM4 = IssuanceM4<Config>;

type CBSM1 = CollectionM1<Config>;
type CBCM4 = CollectionM4<Config>;
type CBSM3 = CollectionM3<Config>;
type CBSM5 = CollectionM5<Config>;
type CBCM = CollectionStateC<Config>;

#[derive(Serialize, Deserialize)]
enum MessageType {
    M1,
    M3,
    M6,
    M10,
}

#[derive(Serialize, Deserialize)]
struct Message {
    msg_type: MessageType,
    data: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a Reqwest client
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Accept self-signed certificates
        .build()?;

    let mut rng = OsRng;
    let kp = CBKP::generate(&mut rng);
    let mut state = IBCM::default();
    let mut col_state = CBCM::default();

    let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut rng);
    let mut m1_bytes = Vec::new();
    m1.serialize_compressed(&mut m1_bytes).unwrap();

    let m1_message = Message {
        msg_type: MessageType::M1,
        data: m1_bytes,
    };
    let m1_message_bytes = bincode::serialize(&m1_message).unwrap();
    println!("Bytes sent (m1_message_bytes): {}", m1_message_bytes.len());

    let http_response = client
        .post("http://127.0.0.1:7878")
        .body(m1_message_bytes.clone())
        .send()
        .await?;

    if http_response.status().is_success() {
        let m2_bytes = http_response.bytes().await?;
        let m2: IBSM2 = IBSM2::deserialize_compressed(&mut m2_bytes.as_ref())
            .expect("Failed to deserialize compressed Issuance M2");

        let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut rng);
        let mut m3_bytes = Vec::new();
        m3.serialize_compressed(&mut m3_bytes).unwrap();

        let m3_message = Message {
            msg_type: MessageType::M3,
            data: m3_bytes,
        };
        let m3_message_bytes = bincode::serialize(&m3_message).unwrap();
        println!("Bytes sent (m3_message_bytes): {}", m3_message_bytes.len());

        let m3_response = client
            .post("http://127.0.0.1:7878")
            .body(m3_message_bytes)
            .send()
            .await?;

        if m3_response.status().is_success() {
            println!("Successfully sent m3 to the server.");

            let m4_bytes = m3_response.bytes().await?;
            let mut m4_slice = &m4_bytes[..];
            let m4: IBSM4 = IBSM4::deserialize_compressed(&mut m4_slice)
                .expect("Failed to deserialize Issuance M4");
            println!("Successfully received m4 from the server.");

            let remaining_bytes = m4_slice;

            // Deserialize the SKP part from the remaining bytes
            let skp = ServerKeyPair::<Config>::deserialize_compressed(&mut &remaining_bytes[..])
                .expect("Failed to deserialize server's KeyPair");

            println!("Successfully received m4 and skp from the server.");

            let _p_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());

            println!("Issuance protocol sucessful!");
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
        let m2: IBSM2 = IBSM2::deserialize_compressed(&mut m2_bytes.as_ref())
            .expect("Failed to deserialize compressed Issuance M2");

        let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut rng);
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
            println!("Successfully received m4 from the server.");

            let m4_bytes = m3_response.bytes().await?;
            let mut m4_slice = &m4_bytes[..];
            let m4: IBSM4 = IBSM4::deserialize_compressed(&mut m4_slice)
                .expect("Failed to deserialize Issuance M4");
            println!("Successfully received m4 from the server.");

            let remaining_bytes = m4_slice;

            // Deserialize the SKP part from the remaining bytes
            let skp = ServerKeyPair::<Config>::deserialize_compressed(&mut &remaining_bytes[..])
                .expect("Failed to deserialize server's KeyPair");

            println!("Successfully received m4 and skp from the server.");

            let p_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());

            println!("Issuance protocol sucessful!");
            println!("Successfully received m4 from the server.");

            let mut m5_slice = remaining_bytes;
            let m5: CBSM1 = CBSM1::deserialize_compressed(&mut m5_slice)
                .expect("Failed to deserialize Collection M1");

            println!("Successfully received collection m1 from the server.");

            let m6 = CBCM::generate_collection_m2(&mut rng, p_state, &m5, &mut col_state, &skp);
            let mut m6_bytes = Vec::new();
            m6.serialize_compressed(&mut m6_bytes).unwrap();

            let m6_message = Message {
                msg_type: MessageType::M6,
                data: m6_bytes,
            };
            let m6_message_bytes = bincode::serialize(&m6_message).unwrap();

            let m6_response = client
                .post("http://127.0.0.1:7878")
                .body(m6_message_bytes)
                .send()
                .await?;

            if m6_response.status().is_success() {
                let m9_bytes = m6_response.bytes().await?;
                let mut m9_slice = &m9_bytes[..];
                let m9: CBSM3 = CBSM3::deserialize_compressed(&mut m9_slice)
                    .expect("Failed to deserialize Collection M3");

                println!("Successfully received m3 collection from the server.");

                let m10 = CBCM::generate_collection_m4(&mut rng, &mut col_state, &m9);
                let mut m10_bytes = Vec::new();
                m10.serialize_compressed(&mut m10_bytes).unwrap();

                let m10_message = Message {
                    msg_type: MessageType::M10,
                    data: m10_bytes,
                };
                let m10_message_bytes = bincode::serialize(&m10_message).unwrap();

                let m10_response = client
                    .post("http://127.0.0.1:7878")
                    .body(m10_message_bytes)
                    .send()
                    .await?;

                if m10_response.status().is_success() {
                    let m11_bytes = m10_response.bytes().await?;
                    let mut m11_slice = &m11_bytes[..];
                    let m11: CBSM5 = CBSM5::deserialize_compressed(&mut m11_slice)
                        .expect("Failed to deserialize Collection M5");

                    println!("Successfully received m5 collection from the server.");

                    let _c_col_state = CBCM::populate_state(&mut col_state, &m11, &skp, kp.clone());
                    println!("Collection protocol sucessful!");
                } else {
                    println!(
                        "Failed parsing m5 of collection. Status: {}",
                        m10_response.status()
                    );
                }
            } else {
                println!(
                    "Failed parsing m6 of collection. Status: {}",
                    m6_response.status()
                );
            }
        } else {
            println!("Failed parsing m3. Status: {}", m3_response.status());
        }
    } else {
        println!("HTTPS Error: {}", https_response.status());
    }

    Ok(())
}
