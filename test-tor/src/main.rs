fn main() {
    let hs = tor::HiddenService::new().unwrap();

    println!("Generated hostname: {}", hs.hostname);
    println!("With public key: {:?}", hs.keypair.pubkey);
}
