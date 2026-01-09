/// Reality Authentication Demo
///
/// This program demonstrates how Reality authentication is injected
/// into ServerHello.random field.
use vless_reality_xhttp::transport::reality::server_rustls::RealityServerRustls;

fn main() {
    println!("=== Reality Authentication Demo ===\n");

    // 1. Create Reality server with a test private key
    let private_key = vec![0x42; 32]; // Test key: all bytes are 0x42
    println!("1. Creating Reality server...");
    println!("   Private key: {:02x?}...", &private_key[0..8]);

    let server = RealityServerRustls::new(
        private_key,
        Some("www.microsoft.com:443".to_string()),
        vec![],
    )
    .expect("Failed to create Reality server");
    println!("   ✓ Server created successfully\n");

    // 2. Simulate ServerHello.random generation
    let mut server_random = [0u8; 32];
    for (i, byte) in server_random.iter_mut().enumerate() {
        *byte = i as u8; // Fill with sequential values
    }
    println!("2. Original ServerHello.random:");
    println!("   {:02x?}", &server_random);
    println!("   First 20 bytes: {:02x?}", &server_random[0..20]);
    println!("   Last 12 bytes:  {:02x?}\n", &server_random[20..32]);

    // 3. Simulate ClientHello.random
    let client_random = [0x99; 32]; // Test client random: all bytes are 0x99
    println!("3. ClientHello.random:");
    println!("   {:02x?}\n", &client_random);

    // 4. Inject Reality authentication
    println!("4. Injecting Reality authentication...");
    server
        .test_inject_auth(&mut server_random, &client_random)
        .expect("Failed to inject Reality auth");
    println!("   ✓ Authentication injected\n");

    // 5. Show modified ServerHello.random
    println!("5. Modified ServerHello.random:");
    println!("   {:02x?}", &server_random);
    println!(
        "   First 20 bytes: {:02x?} (unchanged)",
        &server_random[0..20]
    );
    println!(
        "   Last 12 bytes:  {:02x?} (HMAC-SHA256)\n",
        &server_random[20..32]
    );

    // 6. Verify the modification
    println!("6. Verification:");
    let original_last_12 = [20u8, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
    if server_random[20..32] != original_last_12 {
        println!("   ✓ Last 12 bytes were modified (Reality auth injected)");
    } else {
        println!("   ✗ Last 12 bytes were NOT modified (ERROR)");
    }

    // 7. Demonstrate determinism
    println!("\n7. Testing determinism...");
    let mut server_random2 = [0u8; 32];
    for (i, byte) in server_random2.iter_mut().enumerate() {
        *byte = i as u8;
    }
    server
        .test_inject_auth(&mut server_random2, &client_random)
        .expect("Failed to inject Reality auth");

    if server_random == server_random2 {
        println!("   ✓ HMAC is deterministic (same input → same output)");
    } else {
        println!("   ✗ HMAC is NOT deterministic (ERROR)");
    }

    println!("\n=== Demo Complete ===");
    println!("\nSummary:");
    println!("- Reality authentication uses HMAC-SHA256");
    println!("- Authentication is injected into ServerHello.random[20..32]");
    println!("- First 20 bytes of random remain unchanged");
    println!("- HMAC input: server_random[0..20] + client_random[0..32]");
    println!("- HMAC key: Reality private key (32 bytes)");
    println!("\nThis allows Reality clients to verify the server's identity");
    println!("without relying on traditional TLS certificates!");
}
