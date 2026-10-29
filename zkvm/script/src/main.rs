//! xproof host — generates and verifies REAL SP1 proofs for the BIP32 ownership-link statement.
//!
//! Subcommands:
//!   vkey                          print the program's verifying-key hash
//!   execute  <witness args>       run the guest, report cycle count (no proof)
//!   prove    <witness args>       generate a Groth16 proof (zero-knowledge), write hex to --out
//!   serve    --port N             HTTP API + serves the web demo
//!
//! Only zero-knowledge proofs are produced: the SP1 STARK is always wrapped in Groth16.
//! (A bare SP1 STARK is not zero-knowledge and would expose the witness.)
//! Witness args: --parent-pub HEX(33B) --chain-code HEX(32B) --path-a 0/1 --path-b 1/3
//!               --context STR --expires-at MS
//! Paths are relative to the hidden xpub, non-hardened only ("m/" prefix optional).

use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sp1_sdk::{
    blocking::{EnvProver, EnvProvingKey, ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};

/// The guest ELF, built by build.rs.
const XPROOF_ELF: Elf = include_elf!("xproof-program");

#[derive(Parser)]
#[command(about = "xproof SP1 host: execute, prove, verify, serve")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Vkey,
    Execute(WitnessArgs),
    Prove(ProveArgs),
    Serve(ServeArgs),
}

#[derive(clap::Args)]
struct WitnessArgs {
    #[arg(long)] parent_pub: String,
    #[arg(long)] chain_code: String,
    #[arg(long)] path_a: String,
    #[arg(long)] path_b: String,
    #[arg(long)] context: String,
    #[arg(long)] expires_at: u64,
}

#[derive(clap::Args)]
struct ProveArgs {
    #[command(flatten)]
    w: WitnessArgs,
    #[arg(long)] out: Option<String>,
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, default_value = "0.0.0.0")] bind: String,
    #[arg(long, default_value = "10778")] port: u16,
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))] static_dir: String,
}

fn context_hash_of(context: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha2::Sha256::digest(context.as_bytes()));
    out
}

/// Parse "m/0/1", "0/1" or "0" into non-hardened indices (validated like the guest does).
fn parse_path(s: &str) -> Result<Vec<u32>, String> {
    let s = s.trim();
    let s = s.strip_prefix("m/").or_else(|| s.strip_prefix("M/")).unwrap_or(s);
    let path = s
        .split('/')
        .map(|p| {
            let p = p.trim();
            if p.ends_with('\'') || p.ends_with('h') || p.ends_with('H') {
                return Err(format!("hardened step '{p}' cannot be derived from an xpub"));
            }
            match p.parse::<u32>() {
                Ok(i) if i < 0x8000_0000 => Ok(i),
                _ => Err(format!("bad path step '{p}'")),
            }
        })
        .collect::<Result<Vec<u32>, String>>()?;
    if path.len() > xproof_lib::MAX_DEPTH {
        return Err(format!("path deeper than {}", xproof_lib::MAX_DEPTH));
    }
    Ok(path)
}

fn build_stdin(w: &WitnessArgs) -> Result<SP1Stdin, String> {
    let parent_pub = hex::decode(&w.parent_pub).map_err(|e| format!("parent_pub hex: {e}"))?;
    let chain_code = hex::decode(&w.chain_code).map_err(|e| format!("chain_code hex: {e}"))?;
    let context_hash = context_hash_of(&w.context);
    if parent_pub.len() != 33 { return Err("parent pubkey must be 33 bytes".into()); }
    if chain_code.len() != 32 { return Err("chain code must be 32 bytes".into()); }
    let path_a = parse_path(&w.path_a)?;
    let path_b = parse_path(&w.path_b)?;
    if path_a == path_b { return Err("paths must differ".into()); }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(parent_pub);
    stdin.write_vec(chain_code);
    stdin.write(&path_a);
    stdin.write(&path_b);
    stdin.write_vec(context_hash.to_vec());
    stdin.write(&w.expires_at);
    Ok(stdin)
}

fn setup() -> (EnvProver, EnvProvingKey) {
    if std::env::var("SP1_PROVER").is_err() {
        std::env::set_var("SP1_PROVER", "cpu");
    }
    let client = ProverClient::from_env();
    let pk = client.setup(XPROOF_ELF).expect("setup");
    (client, pk)
}

/// Prove + immediately verify (so we never hand out a bad proof).
///
/// Returns `(proof_bytes, journal_hex)`. The SP1 STARK is recursively wrapped in a BN254
/// Groth16 proof: zero-knowledge, 356 bytes, verifiable with just (bytes, journal, vk hash).
fn do_prove(client: &EnvProver, pk: &EnvProvingKey, w: &WitnessArgs) -> Result<(Vec<u8>, String), String> {
    let stdin = build_stdin(w)?;
    let proof = client.prove(pk, stdin).groth16().run().map_err(|e| e.to_string())?;
    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| e.to_string())?;
    let journal = proof.public_values.as_slice().to_vec();
    let bytes = proof.bytes();
    // Belt and braces: the standalone verifier must accept exactly what we hand out.
    verify_groth16(&bytes, &journal, &pk.verifying_key().bytes32())?;
    Ok((bytes, hex::encode(journal)))
}

/// Standalone Groth16 check — the same thing a smart contract or a third party would run.
/// Needs nothing from the prover: just the proof bytes, the public values and the vk hash.
fn verify_groth16(proof: &[u8], journal: &[u8], vk_hex: &str) -> Result<(), String> {
    sp1_verifier::Groth16Verifier::verify(proof, journal, vk_hex, &sp1_verifier::GROTH16_VK_BYTES)
        .map_err(|e| e.to_string())
}

fn execute(w: &WitnessArgs) {
    let (client, _pk) = setup();
    let stdin = build_stdin(w).unwrap_or_else(|e| {
        eprintln!("bad witness: {e}");
        std::process::exit(2);
    });
    let req = client.execute(XPROOF_ELF, stdin);
    let (public, report) = req.run().expect("execute failed");
    println!("journal: {}", hex::encode(public.as_slice()));
    println!("cycles: {}", report.total_instruction_count());
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    match &cli.cmd {
        Cmd::Vkey => {
            let (_client, pk) = setup();
            println!("vk: {}", pk.verifying_key().bytes32());
        }
        Cmd::Execute(w) => execute(w),
        Cmd::Prove(a) => {
            let (client, pk) = setup();
            let t0 = Instant::now();
            match do_prove(&client, &pk, &a.w) {
                Ok((blob, journal_hex)) => {
                    println!("journal: {journal_hex}");
                    println!("proof_bytes: {}", blob.len());
                    println!("elapsed_ms: {}", t0.elapsed().as_millis());
                    if let Some(path) = &a.out {
                        std::fs::write(path, hex::encode(&blob)).expect("write");
                        println!("wrote {path}");
                    }
                }
                Err(e) => {
                    eprintln!("proving failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Serve(s) => serve(s),
    }
}

// ---------------------------------------------------------------------------
// HTTP service
// ---------------------------------------------------------------------------

struct AppState {
    client: EnvProver,
    pk: EnvProvingKey,
    vk_hex: String,
}

#[derive(Deserialize)]
struct ProveReq {
    parent_pub: String,
    chain_code: String,
    /// Derivation paths below the hidden xpub, e.g. "0/1" and "1/3".
    path_a: Option<String>,
    path_b: Option<String>,
    /// Legacy depth-1 form (used if the paths are absent).
    index_a: Option<u32>,
    index_b: Option<u32>,
    context: String,
    expires_at: u64,
    /// Must be "groth16" if present (the only mode; kept for API compatibility).
    mode: Option<String>,
}

fn req_path(path: Option<String>, index: Option<u32>, which: &str) -> Result<String, String> {
    path.or_else(|| index.map(|i| i.to_string()))
        .ok_or_else(|| format!("missing path_{which}"))
}

#[derive(Serialize)]
struct ProveResp {
    ok: bool,
    mode: String,
    proof_hex: Option<String>,
    journal_hex: Option<String>,
    vk_hex: String,
    elapsed_ms: u128,
    error: Option<String>,
}

/// Groth16 proof bytes + the claimed journal.
#[derive(Deserialize)]
struct VerifyReq {
    groth16_hex: String,
    journal_hex: String,
}

#[derive(Serialize)]
struct VerifyResp {
    ok: bool,
    journal_hex: Option<String>,
    vk_hex: String,
    error: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn serve(s: &ServeArgs) {
    use axum::{http::StatusCode, routing::post, Json, Router};
    use tower_http::services::ServeDir;

    let (client, pk) = tokio::task::spawn_blocking(setup)
        .await
        .expect("setup task panicked");
    let vk_hex = pk.verifying_key().bytes32();
    tracing::info!("xproof guest vk: {vk_hex}");
    let state = Arc::new(AppState { client, pk, vk_hex });

    let app = Router::new()
        .route("/api/info", axum::routing::get({
            let st = state.clone();
            move || {
                let st = st.clone();
                async move {
                    Json(serde_json::json!({
                        "vk_hex": st.vk_hex,
                        "backend": "SP1 zkVM → Groth16, CPU prover (Rust)",
                        "max_depth": xproof_lib::MAX_DEPTH,
                        "modes": ["groth16"],
                    }))
                }
            }
        }))
        .route("/api/prove", post({
            let st = state.clone();
            move |Json(req): Json<ProveReq>| {
                let st = st.clone();
                async move {
                    let t0 = Instant::now();
                    let vk_hex = st.vk_hex.clone();
                    let st2 = st.clone();
                    let mode = "groth16".to_string();
                    let bad_mode = req.mode.as_deref().is_some_and(|m| m != "groth16");
                    let result = tokio::task::spawn_blocking(move || {
                        if bad_mode {
                            return Err("only mode \"groth16\" is supported (non-ZK proofs are disabled)".to_string());
                        }
                        let w = WitnessArgs {
                            parent_pub: req.parent_pub,
                            chain_code: req.chain_code,
                            path_a: req_path(req.path_a, req.index_a, "a")?,
                            path_b: req_path(req.path_b, req.index_b, "b")?,
                            context: req.context,
                            expires_at: req.expires_at,
                        };
                        do_prove(&st2.client, &st2.pk, &w)
                    })
                    .await
                    .map_err(|e| e.to_string());

                    match result {
                        Ok(Ok((blob, journal_hex))) => (
                            StatusCode::OK,
                            Json(ProveResp {
                                ok: true,
                                mode: mode.clone(),
                                proof_hex: Some(hex::encode(&blob)),
                                journal_hex: Some(journal_hex),
                                vk_hex: vk_hex.clone(),
                                elapsed_ms: t0.elapsed().as_millis(),
                                error: None,
                            }),
                        ),
                        Ok(Err(e)) | Err(e) => (
                            StatusCode::BAD_REQUEST,
                            Json(ProveResp {
                                ok: false, mode: mode.clone(), proof_hex: None, journal_hex: None,
                                vk_hex: vk_hex.clone(),
                                elapsed_ms: t0.elapsed().as_millis(),
                                error: Some(e),
                            }),
                        ),
                    }
                }
            }
        }))
        .route("/api/verify", post({
            let st = state.clone();
            move |Json(req): Json<VerifyReq>| {
                let st = st.clone();
                async move {
                    let vk_hex = st.vk_hex.clone();
                    let st2 = st.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let proof = hex::decode(&req.groth16_hex).map_err(|e| e.to_string())?;
                        let journal = hex::decode(&req.journal_hex).map_err(|e| e.to_string())?;
                        verify_groth16(&proof, &journal, &st2.vk_hex)?;
                        Ok::<String, String>(req.journal_hex)
                    })
                    .await
                    .map_err(|e| e.to_string());

                    match result {
                        Ok(Ok(journal_hex)) => (
                            StatusCode::OK,
                            Json(VerifyResp { ok: true, journal_hex: Some(journal_hex), vk_hex: vk_hex.clone(), error: None }),
                        ),
                        Ok(Err(e)) | Err(e) => (
                            StatusCode::OK,
                            Json(VerifyResp { ok: false, journal_hex: None, vk_hex: vk_hex.clone(), error: Some(e) }),
                        ),
                    }
                }
            }
        }))
        .fallback_service(ServeDir::new(&s.static_dir))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024));

    let addr = format!("{}:{}", s.bind, s.port);
    tracing::info!("xproof service on http://{addr} (static: {})", s.static_dir);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
