extern crate base64;

use std::vec::Vec;
use std::str;
use std::error;

pub fn xor(key: &str, input: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut index = 0;
    
    let input_chars: Vec<char> = input.chars().collect();
    let key_chars: Vec<char> = key.chars().collect();
    let key_length = key.len();

    for c in input_chars {
        let num = (c as u8) ^ ((key_chars[index % key_length]) as u8);
        buf.push(num);
        index += 1;
    }

    buf
}

pub fn encode(key: &str, input: &str) -> String {
    let buf = xor(key, input);
    base64::encode(&buf)
}

pub fn decode(key: &str, input: &str) -> Result<String, Box<dyn error::Error>> {
    let buf = base64::decode(input)?;
    let utf8_buf = str::from_utf8(&buf)?;

    let buf = xor(key, utf8_buf);
    let original = str::from_utf8(&buf)?;

    Ok(String::from(original))
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: &str = "a random whatever key";

    #[test]
    fn test_xor_twice_get_original() {
        let expected = "foo bar awesome";
        let original = expected.as_bytes();

        let first_buf = xor(KEY, &expected);
        let utf8_buf = str::from_utf8(&first_buf).unwrap();

        let last_buf = xor(KEY, &utf8_buf);

        assert_eq!(original, last_buf);
    }

    #[test]
    fn test_xor_strings() {
        let expected = "foo bar awesome";
        
        let cipher = encode(KEY, &expected);

        let result = decode(KEY, &cipher).unwrap();

        assert_eq!(expected, result);
    }
}
