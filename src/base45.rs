use std::convert::TryInto;
const ALPHABET_LEN: u16 = 45;
const ALPHABET_LEN_SQUARED: u16 = ALPHABET_LEN * ALPHABET_LEN;

pub const ALPHABET: [char; ALPHABET_LEN as usize] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '$',
    '%', '*', '+', '-', '.', '/', ':',
];


const fn reverse_alphabet(c: char) -> Result<u8, InvalidCharacter> {
    match c {
        '0' => Ok(0),
        '1' => Ok(1),
        '2' => Ok(2),
        '3' => Ok(3),
        '4' => Ok(4),
        '5' => Ok(5),
        '6' => Ok(6),
        '7' => Ok(7),
        '8' => Ok(8),
        '9' => Ok(9),
        'A' => Ok(10),
        'B' => Ok(11),
        'C' => Ok(12),
        'D' => Ok(13),
        'E' => Ok(14),
        'F' => Ok(15),
        'G' => Ok(16),
        'H' => Ok(17),
        'I' => Ok(18),
        'J' => Ok(19),
        'K' => Ok(20),
        'L' => Ok(21),
        'M' => Ok(22),
        'N' => Ok(23),
        'O' => Ok(24),
        'P' => Ok(25),
        'Q' => Ok(26),
        'R' => Ok(27),
        'S' => Ok(28),
        'T' => Ok(29),
        'U' => Ok(30),
        'V' => Ok(31),
        'W' => Ok(32),
        'X' => Ok(33),
        'Y' => Ok(34),
        'Z' => Ok(35),
        ' ' => Ok(36),
        '$' => Ok(37),
        '%' => Ok(38),
        '*' => Ok(39),
        '+' => Ok(40),
        '-' => Ok(41),
        '.' => Ok(42),
        '/' => Ok(43),
        ':' => Ok(44),
        _ => Err(InvalidCharacter),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidCharacter;

/// encode a byte array to base45 according to [draft-faltstrom-base45-03 Section 4.3](https://tools.ietf.org/html/draft-faltstrom-base45-03#section-4.3)
pub fn encode(bytes: &[u8]) -> String {
    //SAFETY check: we know that our string is valid utf8 since we only allow characters from our alphabet which all are valid utf8
    unsafe {
        String::from_utf8_unchecked(
            bytes
                .chunks(2)
                .flat_map(|b| {
                    let val = u16::from_be_bytes(b.try_into().unwrap_or([0, b[0]]));
                    let a = val % ALPHABET_LEN;
                    let b = val / ALPHABET_LEN % ALPHABET_LEN;
                    let c = val / ALPHABET_LEN_SQUARED % ALPHABET_LEN;
                    // let a = 0;
                    // let b = 0;
                    // let c  = 0;

                    // if we only have one byte in the last chunk, it is encoded with two bytes instead of three
                    if val <= u8::MAX as u16 {
                        vec![ALPHABET[a as usize] as u8, ALPHABET[b as usize] as u8]
                    } else {
                        vec![
                            ALPHABET[a as usize] as u8,
                            ALPHABET[b as usize] as u8,
                            ALPHABET[c as usize] as u8,
                        ]
                    }
                })
                .collect::<Vec<u8>>(),
        )
    }
}

/// decode a base45 string to a byte array ignoring unknown characters
pub fn decode(base45_string: &str) -> Result<Vec<u8>, InvalidCharacter> {
    Ok(base45_string
        .as_bytes()
        .chunks(3)
        .flat_map(|c| {
            let val = match c.len() {
                1 => {
                    if let Ok(c) = reverse_alphabet(c[0] as char) {
                        c as u16
                    } else {
                        return vec![];
                    }
                }
                2 => {
                    if let (Ok(a), Ok(b)) = (
                        reverse_alphabet(c[0] as char),
                        reverse_alphabet(c[1] as char),
                    ) {
                        b as u16 * ALPHABET_LEN + a as u16
                    } else {
                        return vec![];
                    }
                }
                3 => {
                    if let (Ok(a), Ok(b), Ok(c)) = (
                        reverse_alphabet(c[0] as char),
                        reverse_alphabet(c[1] as char),
                        reverse_alphabet(c[2] as char),
                    ) {
                        c as u16 * ALPHABET_LEN_SQUARED + b as u16 * ALPHABET_LEN + a as u16
                    } else {
                        return vec![];
                    }
                }
                _ => panic!(),
            };
            let bytes = val.to_be_bytes();
            if c.len() < 3 {
                vec![bytes[1]]
            } else {
             bytes.to_vec()
            }
        })
        .collect::<Vec<u8>>())
}

#[cfg(test)]
mod tests {
    #[test]
    pub fn test_encoding() {
        let sample_1 = "AB";
        let result = super::encode(sample_1.as_bytes());
        assert_eq!(result, "BB8");

        let sample_2 = "Hello!!";
        let result = super::encode(sample_2.as_bytes());
        assert_eq!(result, "%69 VD92EX0");

        let sample_3 = "base-45";
        let result = super::encode(sample_3.as_bytes());
        assert_eq!(result, "UJCLQE7W581");
    }
    #[test]
    pub fn test_decoding() {
        let sample_1 = "QED8WEX0";
        let result = String::from_utf8(super::decode(sample_1).unwrap()).unwrap();
        assert_eq!(result, "ietf!");

        let sample_2 = "BB8";
        let result = String::from_utf8(super::decode(sample_2).unwrap()).unwrap();
        assert_eq!(result, "AB");

        let sample_3 = "%69 VD92EX0";
        let result = String::from_utf8(super::decode(sample_3).unwrap()).unwrap();
        assert_eq!(result, "Hello!!");

        let sample_4 = "UJCLQE7W581";
        let result = String::from_utf8(super::decode(sample_4).unwrap()).unwrap();
        assert_eq!(result, "base-45");
    }
}
