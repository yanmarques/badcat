pub mod stream;

///! Public API for rust_hs Tor's feature.

#[no_mangle]
pub extern "C" fn rust_hs_write_buf(global_id: u64, buf: *const u8, buf_len: usize) {
    stream::write_buf(global_id, buf, buf_len)
}

#[no_mangle]
pub extern "C" fn rust_hs_conn_matches_port(port: u16) -> i32 {
    stream::conn_matches_port(port)
}

#[no_mangle]
pub extern "C" fn rust_hs_read_buf(global_id: u64) -> *const u8 {
    stream::read_buf(global_id)
}

#[no_mangle]
pub extern "C" fn rust_hs_register_conn(global_id: u64, port: u16) -> i32 {
    stream::register_conn(global_id, port)
}

use std::error::Error;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};

const HS_SERVICE_ADDR_LEN_BASE32: usize = 56;
const HS_SERVICE_VERSION: u8 = 3;
const HS_SERVICE_KEY_TAG: &str = "type0";
const ED25519_PUBKEY_LEN: usize = 32;
const ED25519_SECKEY_LEN: usize = 64;

extern "C" {
    fn tor_main(argc: usize, argv: *const *const i8);
    fn tor_shutdown_event_loop_and_exit(exit_code: usize);

    fn ed25519_keypair_generate(keypair_out: *mut u8, extra_strong: isize) -> isize;
    fn init_logging(disable_startup_queue: isize);
    fn hs_build_address(pubkey: *const u8, version: u8, addr_out: *mut u8);

    fn ed25519_pubkey_write_to_file(
        pubkey: *const u8,
        filename: *const i8,
        tag: *const i8,
    ) -> isize;

    fn ed25519_seckey_write_to_file(
        seckey: *const u8,
        filename: *const i8,
        tag: *const i8,
    ) -> isize;
}

pub struct Tor {
    inner: JoinHandle<()>,
}

pub struct Ed25519Keypair {
    pub pubkey: [u8; ED25519_PUBKEY_LEN],
    pub seckey: [u8; ED25519_SECKEY_LEN],
}

pub struct HiddenService {
    pub hostname: String,
    pub keypair: Ed25519Keypair,
}

fn copy_buf(dst: &mut [u8], src: &[u8]) {
    let mut index = 0;

    for value in src {
        dst[index] = *value;
        index += 1;
    }
}

fn init_from_rc(torrc: &str) {
    let argv1 = CString::new("tor").unwrap();
    let argv2 = CString::new("-f").unwrap();
    let argv3 = CString::new(torrc).unwrap();

    let argv = vec![argv1.as_ptr(), argv2.as_ptr(), argv3.as_ptr()];

    unsafe {
        tor_main(argv.len(), argv.as_ptr());
    }
}

fn shutdown_with_code(exit_code: usize) {
    unsafe {
        tor_shutdown_event_loop_and_exit(exit_code);
    }
}

#[allow(dead_code)]
impl Tor {
    /// Spawn Tor in a Thread.
    pub fn new(torrc: &PathBuf) -> Self {
        let torrc = String::from(torrc.to_str().unwrap());

        let inner = thread::spawn(move || {
            init_from_rc(&torrc);
        });

        Tor { inner }
    }

    /// Stop Tor gracefully and wait for the Thread to exit.
    pub fn stop(self) -> Result<(), Box<dyn std::error::Error>> {
        shutdown_with_code(0);
        self.inner.join().unwrap();
        Ok(())
    }
}

impl HiddenService {
    /// Generate a new Hidden Service key pair and hostname.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let keypair = Ed25519Keypair::new()?;
        let hostname = keypair.build_hs_address()?;

        let hs = HiddenService { hostname, keypair };

        Ok(hs)
    }

    /// Save information to directory in Tor's format.
    pub fn to_fs(&self, to_dir: PathBuf) -> Result<(), Box<dyn Error>> {
        let tag = CString::new(HS_SERVICE_KEY_TAG).unwrap();

        let pubkey_filename = to_dir.join("hs_ed25519_public_key");
        let seckey_filename = to_dir.join("hs_ed25519_secret_key");
        let address_filename = to_dir.join("hostname");

        let filename_c_str = CString::new(pubkey_filename.to_str().unwrap()).unwrap();

        unsafe {
            let result = ed25519_pubkey_write_to_file(
                self.keypair.pubkey.as_ptr(),
                filename_c_str.as_ptr(),
                tag.as_ptr(),
            );

            if result < 0 {
                return Err(String::from("problem writing pubkey to file").into());
            }
        };

        let filename_c_str = CString::new(seckey_filename.to_str().unwrap()).unwrap();

        unsafe {
            let result = ed25519_seckey_write_to_file(
                self.keypair.seckey.as_ptr(),
                filename_c_str.as_ptr(),
                tag.as_ptr(),
            );

            if result < 0 {
                return Err(String::from("problem writing seckey to file").into());
            }
        };

        fs::write(address_filename, self.hostname.as_bytes())?;

        Ok(())
    }
}

impl Ed25519Keypair {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // The size of the buf will be 96 because this is the length of
        // the ed25519_keypair_t at src/lib/crypt_ops/crypto_ed25519.h
        let mut buf = [0; ED25519_PUBKEY_LEN + ED25519_SECKEY_LEN];

        unsafe {
            // Tor requires the logging subsystem to be initialized.
            init_logging(1);

            let result = ed25519_keypair_generate(buf.as_mut_ptr(), 1);

            if result < 0 {
                return Err(String::from("problem generating keypair").into());
            }
        };

        let mut pubkey = [0; ED25519_PUBKEY_LEN];
        copy_buf(&mut pubkey, &buf[0..ED25519_PUBKEY_LEN]);

        let mut seckey = [0; ED25519_SECKEY_LEN];
        copy_buf(&mut seckey, &buf[ED25519_PUBKEY_LEN..ED25519_SECKEY_LEN]);

        let kp = Ed25519Keypair { pubkey, seckey };

        Ok(kp)
    }

    pub fn build_hs_address(&self) -> Result<String, Box<dyn Error>> {
        // Length is the hidden service address + null byte at the end.
        let mut addr_out = [0; HS_SERVICE_ADDR_LEN_BASE32 + 1];

        unsafe {
            hs_build_address(
                self.pubkey.as_ptr(),
                HS_SERVICE_VERSION,
                addr_out.as_mut_ptr(),
            );
        }

        let c_str = CStr::from_bytes_with_nul(&addr_out)?;
        let mut address = c_str.to_str()?.to_owned();

        address.push_str(".onion");

        Ok(address)
    }
}
