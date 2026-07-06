//! Minimal Iroh P2P direct connection test.
//! Run as server: cargo run --example iroh_direct_connect --features linux-pkg-config -- server
//! Run as client: cargo run --example iroh_direct_connect --features linux-pkg-config -- client <server_public_key>

use std::env;
use std::io::{Read, Write};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  Server: {} server", args[0]);
        eprintln!("  Client: {} client <server_public_key>", args[0]);
        std::process::exit(1);
    }
    
    let mode = &args[1];
    
    // Create Iroh endpoint
    let endpoint = iroh::Endpoint::builder()
        .alpns(vec![b"rustdesk/iroh/1".to_vec()])
        .bind()
        .await?;
    
    let node_id = endpoint.node_id();
    let node_id_str = node_id.to_string();
    println!("My Iroh Node ID (公钥): {}", node_id_str);
    println!("Node ID length: {} chars", node_id_str.len());
    
    match mode.as_str() {
        "server" => {
            println!("\n[Server] Waiting for incoming P2P connection...");
            println!("[Server] No hbbs server needed - direct P2P via Iroh");
            
            // Accept incoming connection
            while let Some(conn) = endpoint.accept().await {
                let conn = conn.await?;
                println!("[Server] Incoming connection from: {}", conn.remote_node_id()?);
                
                // Accept a bi-directional stream
                let (mut send, mut recv) = conn.accept_bi().await?;
                println!("[Server] Stream established!");
                
                // Read message from client
                let mut buf = [0u8; 1024];
                let n = recv.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    let msg = String::from_utf8_lossy(&buf[..n]);
                    println!("[Server] Received: {}", msg);
                }
                
                // Send response
                let response = format!("Hello from server! My ID is {}", node_id_str);
                send.write_all(response.as_bytes()).await?;
                send.finish().await?;
                println!("[Server] Response sent");
            }
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Usage: {} client <server_public_key>", args[0]);
                std::process::exit(1);
            }
            let server_key = &args[2];
            println!("\n[Client] Connecting to server via public key: {}", server_key);
            println!("[Client] No ID server, no relay server - pure P2P");
            
            // Parse the public key
            let node_id: iroh::NodeId = server_key.parse()
                .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
            
            // Connect via Iroh
            println!("[Client] Establishing P2P connection...");
            let conn = endpoint.connect(node_id, vec![b"rustdesk/iroh/1".to_vec()]).await?;
            println!("[Client] Connected to: {}", conn.remote_node_id()?);
            
            // Open a bi-directional stream
            let (mut send, mut recv) = conn.open_bi().await?;
            println!("[Client] Stream established!");
            
            // Send message to server
            let msg = "Hello from client! P2P direct connection works!";
            send.write_all(msg.as_bytes()).await?;
            send.finish().await?;
            println!("[Client] Message sent: {}", msg);
            
            // Read response
            let mut buf = [0u8; 1024];
            let n = recv.read(&mut buf).await.unwrap_or(0);
            if n > 0 {
                let response = String::from_utf8_lossy(&buf[..n]);
                println!("[Client] Server response: {}", response);
            }
            
            println!("\n✓ P2P direct connection via public key SUCCESS!");
            println!("✓ No central server needed - truly decentralized");
        }
        _ => {
            eprintln!("Unknown mode: {}. Use 'server' or 'client'", mode);
            std::process::exit(1);
        }
    }
    
    // Keep endpoint alive
    println!("\nPress Ctrl+C to exit...");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
