extern crate base64;
extern crate rand;

use std::vec::Vec;
use std::error;

pub fn random_bytes(length: u8) -> Vec<u8> {
    (0..length).map(|_| {
        rand::random::<u8>()
    }).collect::<Vec<u8>>()
}

pub fn secret_key() -> String {
    let buf = random_bytes(48);
    base64::encode(buf)
}

pub fn xor(key: &String, input: &String) -> Vec<u8> {    
    let key_chars: Vec<char> = key.chars().collect();
    let key_length = key.len();

    input.chars().enumerate().map(|(index, c)| {
        (c as u8) ^ ((key_chars[index % key_length]) as u8)
    }).collect::<Vec<u8>>()
}

pub fn encode(key: &String, input: &String) -> String {
    let buf = xor(key, input);
    base64::encode(buf)
}

pub fn decode(key: &String, input: &String) -> Result<String, Box<dyn error::Error>> {
    let buf = base64::decode(input)?;
    let utf8_buf = String::from_utf8(buf)?;

    let buf = xor(key, &utf8_buf);
    let original = String::from_utf8(buf)?;

    Ok(original)
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: &str = "a random whatever key";

    #[test]
    fn test_xor_twice_get_original() {
        let expected = String::from("foo bar awesome");
        let original = expected.as_bytes();

        let first_buf = xor(&String::from(KEY), &expected);
        let utf8_buf = String::from_utf8(first_buf).unwrap();

        let last_buf = xor(&String::from(KEY), &utf8_buf);

        assert_eq!(original, last_buf);
    }

    #[test]
    fn test_xor_strings() {
        let expected = String::from("foo bar awesome");
        
        let cipher = encode(&String::from(KEY), &expected);

        let result = decode(&String::from(KEY), &cipher).unwrap();

        assert_eq!(expected, result);
    }
}
