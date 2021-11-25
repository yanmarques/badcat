extern crate base64;
extern crate rand;

use std::vec::Vec;

#[allow(dead_code)]
pub fn random_bytes(length: u8) -> Vec<u8> {
    (0..length).map(|_| {
        rand::random::<u8>()
    }).collect::<Vec<u8>>()
}

#[allow(dead_code)]
pub fn new_key(length: u8) -> String {
    let buf = random_bytes(length);
    base64::encode(buf)
}