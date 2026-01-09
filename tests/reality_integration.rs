use anyhow::Result;
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vless_reality_xhttp::transport::reality::server_rustls::RealityServerRustls;
use std::time::Duration;

#[tokio::test]
async fn test_reality_fallback() -> Result<()> {
    // 1. Setup a dummy "destination" server
    let dest_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dest_addr = dest_listener.local_addr()?;
    
    tokio::spawn(async move {
        let (mut stream, _) = dest_listener.accept().await.unwrap();
        // Fallback server just echoes "I am fallback"
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(b"I am fallback").await.unwrap();
    });

    // 2. Setup Reality server
    let private_key = vec![0x42; 32];
    let server = RealityServerRustls::new(
        private_key, 
        Some(dest_addr.to_string()),
        vec!["0123456789abcdef".to_string()]
    )?;
    
    // Pick a random port
    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    let server_port = server_addr.port();
    
    // Run server in background
    let server = std::sync::Arc::new(server);
    let listener = server_listener; // Transfer ownership
    
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let s = server.clone();
                tokio::spawn(async move {
                    // accept() handles Sniff-and-Dispatch.
                    // If fallback, it returns Err("Reality fallback handled").
                    // If success, it returns Ok(tls_stream). 
                    // We just let it run.
                    let _ = s.accept(stream).await;
                });
            }
        }
    });

    // Allow server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Connect as a "Normal" client (non-Reality)
    // Send random garbage, expect fallback response
    let mut client = TcpStream::connect(server_addr).await?;
    client.write_all(b"Hello non-TLS world").await?;
    
    let mut resp = [0u8; 1024];
    let n = client.read(&mut resp).await?;
    assert_eq!(&resp[..n], b"I am fallback");

    Ok(())
}
