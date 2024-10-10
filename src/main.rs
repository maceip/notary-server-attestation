use pem::Pem;
use reqwest;

use base64::{engine::general_purpose::STANDARD, Engine};
use k256::{
    elliptic_curve::pkcs8, elliptic_curve::sec1::ToEncodedPoint, EncodedPoint as EP, PublicKey,
};

use k256::ecdsa::{SigningKey, VerifyingKey as VK};
use mc_sgx_core_sys_types::sgx_report_body_t;
use mc_sgx_core_types::{Attributes, MrEnclave, MrSigner, ReportBody, ReportData};
use mc_sgx_dcap_types::{CertificationData, Quote3};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use serde_json;
use std::collections::HashMap;
use x509_cert::{der::DecodePem, Certificate};

use hyper_util::{client::legacy::Client, rt::TokioExecutor, rt::TokioIo};
use hyper::{body::Bytes, body::Buf, Request, StatusCode};
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::{env, str};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use utils::range::RangeSet;
//use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use serde::Deserialize;
use tokio::net::TcpStream;

use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig};
use tlsn_prover::{Prover, ProverConfig};



// Setting of the application server
const SERVER_DOMAIN: &str = "discord.com";

// Setting of the notary server — make sure these are the same with the config
// in ../../notary/server
const NOTARY_HOST: &str = "localhost";
const NOTARY_PORT: u16 = 7047;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const URL1: &str = "http://localhost:7047/info";
    match reqwest::get(URL1).await {
        Ok(resp) => {
            let whois: NotaryInfo = resp.json().await?;

            let quote_bytes = hex::decode(whois.quote.rawQuote.clone()).expect("hex err");

            let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
            let signature_data = quote.signature_data();
            let cert_chain = match signature_data.certification_data() {
                CertificationData::PckCertificateChain(cert_chain) => cert_chain,
                _ => panic!("expected a PckCertChain"),
            };
            let leaf_pem = cert_chain.into_iter().collect::<Vec<_>>()[0];

            let certificate = Certificate::from_pem(leaf_pem).expect("failed to parse PEM");
            let key = VerifyingKey::from_sec1_bytes(
                certificate
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .expect("Failed to parse public key"),
            )
            .expect("Failed to decode public key");

            let verify = quote.verify(&key).expect("bad quote!");
            let report_data = quote.app_report_body().report_data();
            let report_data_bytes: &[u8] = report_data.as_ref();
            let mut new_array: [u8; 33] = [0; 33];

            new_array.copy_from_slice(&report_data_bytes[..33]);

            let encoded_point = EncodedPoint::from_bytes(new_array).expect("Invalid encoded point");

            let quote_vk = VK::from_encoded_point(&encoded_point).expect("vk err");

            let pem = pem::parse(whois.publicKey).expect("Failed to parse PEM");

            let encoded_pointz =
                EncodedPoint::from_bytes(pem.contents).expect("Invalid encoded point");


            let info_vk = VK::from_encoded_point(&encoded_pointz).expect("vk err");
	    //"pub parsed from intel signed quote:\n 
            println!("{:?}", quote_vk.to_sec1_bytes());
		//pub parsed from /info
            println!("{:?}", info_vk.to_sec1_bytes());

            assert!(quote_vk.to_sec1_bytes() == info_vk.to_sec1_bytes());

            println!("{:?}", quote.app_report_body().mr_enclave());
        }
        Err(err) => {
            println!("Reqwest Error: {}", err)
        }
    }

    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();
    let channel_id = env::var("CHANNEL_ID").unwrap();
    let auth_token = env::var("AUTHORIZATION").unwrap();
    let user_agent = env::var("USER_AGENT").unwrap();

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        .path_prefix("v0.1.0-alpha.7")
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(true)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    println!("init!");
    // Set up protocol configuration for prover.
    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(protocol_config)
        .build()
        .unwrap();
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    // Open a new socket to the application server.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!(
            "https://{SERVER_DOMAIN}/api/v9/channels/{channel_id}/messages?limit=2"
        ))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "identity")
        .header("User-Agent", user_agent)
        .header("Authorization", &auth_token)
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .unwrap();

    debug!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization
    let mut prover = prover.start_notarize();

    // Identify the ranges in the transcript that contain secrets
    let sent_transcript = prover.transcript().sent();
    let recv_transcript = prover.transcript().received();

    // Identify the ranges in the outbound data which contain data which we want to
    // disclose
    let (sent_public_ranges, _) = find_ranges(sent_transcript, &[auth_token.as_bytes()]);
    #[allow(clippy::single_range_in_vec_init)]
    let recv_public_ranges = RangeSet::from([0..recv_transcript.len()]);

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // Commit to public ranges
    builder.commit_sent(&sent_public_ranges).unwrap();
    builder.commit_recv(&recv_public_ranges).unwrap();

    let config = builder.build().unwrap();

    prover.transcript_commit(config);

    // Finalize, returning the notarized session
    let request_config = RequestConfig::default();
    let (attestation, secrets) = prover.finalize(&request_config).await.unwrap();

    debug!("Notarization complete!");

    tokio::fs::write(
        "discord.attestation.tlsn",
        bincode::serialize(&attestation).unwrap(),
    )
    .await
    .unwrap();

    tokio::fs::write(
        "discord.secrets.tlsn",
        bincode::serialize(&secrets).unwrap(),
    )
    .await
    .unwrap();
    Ok(())
}


/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (RangeSet<usize>, RangeSet<usize>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (
        RangeSet::from(public_ranges),
        RangeSet::from(private_ranges),
    )
}




#[derive(Deserialize, Debug)]
struct Quote {
    rawQuote: String,
    mrsigner: String,
    mrenclave: String,
    error: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NotaryInfo {
    version: String,
    publicKey: String,
    gitCommitHash: String,
    gitCommitTimestamp: String,
    quote: Quote,
}
