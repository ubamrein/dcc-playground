const ALPHABET_LEN: u16 = 45;
const ALPHABET_LEN_SQUARED: u16 = ALPHABET_LEN * ALPHABET_LEN;

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
                        let c = c as u32 * ALPHABET_LEN_SQUARED as u32 + b as u32 * ALPHABET_LEN as u32 + a as u32;
                        if c > u16::MAX as u32{
                            return vec![]
                        }
                        c as u16
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
    #[test]
    pub fn invalid_base45() {
        let base45 = "HC1:NCFTW2C9QJPOPS3PFBJAHDA8VWTNS28D45YVL7J0S80 T1%L.9J4+ES.NPUTP.N1:D.WE974QVABH7/A4L.RRLUB94G9TQI4OZ2K:VO ESVNWJSLIG8YSZ.VGTDU E M:EVU N1.8BSDK89RODMRAN+DNP1 *5SZ0C KGFP.:JOZ67$N5Z8NOPVP9LF23*TC40Z80M9F-3S:447R8U7F04KR-9D$DC04N%7K32.RKL54XHNQ1MZVOKCB8WOLPO2H5.68P9IU+SDJC8OO886%E8$OKTEB+-1O3T*%OI32FVMHUQ-P2QA4Q9FE44.FHERSRFF.JQCIND8PHZA:PQ/BH4N6/54TWJ$66OFAKOLNGB5HN1VE.*GMBLH.K7$SQ*9WRCGG6.79MSNX2NZFRDPBT%FSWL6G7-GDCFM+Q3UUUQP28KCL91%S3ZUPTIMRTK+8DOUO+9I7.V5LT$ZKTS8NLVHICA2BIG5%39D4U-W6*.DULFL1KW V:LLK.M1FRQ3N MVKINLGB-1TU8N6HU.XT05K27IB:KSOSS/2KEWGBFBAN47WB%FVUS:.1O9DT2";

        let result = super::decode(base45);
        println!("{:?}", result);
    }
}
