extern crate base64;
extern crate rand;

use std::vec::Vec;
use std::error;

#[allow(dead_code)]
pub fn xor(key: &String, input: &String) -> Vec<u8> {    
    xor_bytes(key, &input.chars().map(|c| c as u8).collect::<Vec<u8>>())
}

pub fn xor_bytes(key: &String, input: &Vec<u8>) -> Vec<u8> {    
    let key_chars: Vec<char> = key.chars().collect();
    let key_length = key.len();

    input.iter().enumerate().map(|(index, b)| {
        b ^ ((key_chars[index % key_length]) as u8)
    }).collect::<Vec<u8>>()
}

#[allow(dead_code)]
pub fn encode(key: &String, input: &String) -> String {
    let buf = xor(key, input);
    base64::encode(buf)
}

#[allow(dead_code)]
pub fn encode_bytes(key: &String, input: &Vec<u8>) -> String {
    let buf = xor_bytes(key, input);
    base64::encode(buf)
}

pub fn decode(key: &String, input: &String) -> Result<String, Box<dyn error::Error>> {
    let bytes = decode_bytes(key, input)?;
    let original = String::from_utf8(bytes)?;

    Ok(original)
}

pub fn decode_bytes(key: &String, input: &String) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let buf = base64::decode(input)?;
    let buf = xor_bytes(key, &buf);

    Ok(buf)
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
