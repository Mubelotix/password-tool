use sha3::{Digest, Sha3_512};

pub fn generate_password(
    master_password: &str,
    domain: &str,
    big: bool,
    only_numbers: bool,
    special_chars: bool,
) -> String {
    let password_size = if big { 50 } else { 16 };

    let mut hasher = Sha3_512::new();

    let mut generated_password = master_password.to_string();
    generated_password.push_str("35Pqfs6FeEf545fD54");
    generated_password.push_str(domain);
    hasher.update(generated_password);
    let generated_password = hasher.finalize();

    let mut generated_password: String = if !only_numbers {
        if special_chars && !big {
            hex::encode(generated_password[..password_size / 2 - 2].to_vec())
        } else {
            hex::encode(generated_password[..password_size / 2 - 3].to_vec())
        }
    } else {
        let mut generated_password2 = String::new();
        for n in generated_password {
            generated_password2.push_str(&n.to_string());
        }
        let generated_password = generated_password2[..password_size].to_string();
        return generated_password;
    };

    if special_chars {
        if big {
            generated_password.push_str("@*_BQF");
        } else {
            generated_password.push_str("*_BQ");
        }
    } else {
        generated_password.push_str("943SOD");
    }

    generated_password
}

#[cfg(test)]
mod test {
    use super::generate_password;

    #[test]
    fn test_different_passwords_for_different_domains() {
        assert_ne!(
            generate_password("testing", "example.com", true, false, true),
            generate_password("testing", "google.com", true, false, true),
        );

        assert_ne!(
            generate_password("testing", "amazon.com", true, false, true),
            generate_password("testing", "amazon.fr", true, false, true),
        );
    }

    #[test]
    fn test_different_passwords_for_different_master_passwords() {
        assert_ne!(
            generate_password("testing", "google.com", true, false, true),
            generate_password("testing2", "google.com", true, false, true),
        );

        assert_ne!(
            generate_password("testing", "amazon.com", true, false, true),
            generate_password("testing2", "amazon.com", true, false, true),
        );
    }

    #[test]
    fn test_backward_compatibility() {
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, false, false),
            "2a9d1e0453943SOD"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, false, true),
            "2a9d1e0453d7*_BQ"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, true, false),
            "4215730483215144"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", false, true, true),
            "4215730483215144"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, false, false),
            "2a9d1e0453d79086120bc2326d0e16b5fbcccb27b8d2943SOD"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, false, true),
            "2a9d1e0453d79086120bc2326d0e16b5fbcccb27b8d2@*_BQF"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, true, false),
            "42157304832151441341811194501091422181251204203391"
        );
        assert_eq!(
            &generate_password("test", "unknown.unknown", true, true, true),
            "42157304832151441341811194501091422181251204203391"
        );
    }
}
