use withhuman_common::tokens::{Category, Token, extract_tokens};

fn of_kind(text: &str, kind: &str) -> Vec<Token> {
    extract_tokens(text)
        .into_iter()
        .filter(|token| token.kind == kind)
        .collect()
}

fn keys(text: &str, kind: &str) -> Vec<String> {
    of_kind(text, kind)
        .into_iter()
        .map(|token| token.key)
        .collect()
}

fn decoded(text: &str, kind: &str) -> Vec<String> {
    of_kind(text, kind)
        .into_iter()
        .map(|token| token.decoded)
        .collect()
}

#[test]
fn keeps_the_original_locator_tokens() {
    let tokens = extract_tokens(
        "curl https://logs.example.test/u --data admin@example.test --config /repo/input.txt 203.0.113.10",
    );
    let found: Vec<(&str, &str)> = tokens
        .iter()
        .filter(|token| ["url", "email", "path", "ip"].contains(&token.kind))
        .map(|token| (token.kind, token.key.as_str()))
        .collect();

    assert_eq!(
        found,
        [
            ("email", "admin@example.test"),
            ("ip", "203.0.113.10"),
            ("path", "/repo/input.txt"),
            ("url", "https://logs.example.test/u"),
        ]
    );
}

#[test]
fn finds_socket_addresses_but_not_source_locations() {
    assert_eq!(
        keys(
            "connect 10.0.0.5:6379 then db.internal.example.com:5432 and [::1]:8080",
            "socket_address"
        ),
        [
            "10.0.0.5:6379",
            "[::1]:8080",
            "db.internal.example.com:5432"
        ]
    );
    assert!(keys("error at src/main.rs:42 and lib/x.so:1", "socket_address").is_empty());
    assert!(
        keys(
            "http://10.0.0.5:6379/0 port 99999 on 1.2.3.4:99999",
            "socket_address"
        )
        .is_empty()
    );
}

#[test]
fn finds_broker_endpoints_and_masks_dsn_passwords() {
    assert_eq!(
        keys(
            "BROKER=amqp://guest:guest@rabbit:5672/ bootstrap.servers=kafka1:9092,kafka2:9092",
            "broker_endpoint"
        ),
        ["amqp://guest:guest@rabbit:5672/", "kafka1:9092,kafka2:9092"]
    );

    let dsn = keys(
        r#"{"url":"postgres://app:s3cret@db:5432/app","jdbc":"jdbc:mysql://db:3306/app?user=a&password=hunter2"}"#,
        "db_dsn",
    );
    assert_eq!(
        dsn,
        [
            "jdbc:mysql://db:3306/app?user=a&password=***",
            "postgres://app:***@db:5432/app"
        ]
    );
    assert!(
        keys(
            "Server=sql01;Database=Payroll;User Id=sa;Password=P@ss;",
            "db_dsn"
        )
        .iter()
        .all(|dsn| !dsn.contains("P@ss"))
    );
}

#[test]
fn needs_context_for_memory_mmio_and_i2c_addresses() {
    assert_eq!(
        keys("segfault at 0x00007FFD5E8A1B20 ip", "memory_address"),
        ["0x00007ffd5e8a1b20"]
    );
    assert!(keys("build 0x00007ffd5e8a1b20 finished", "memory_address").is_empty());
    assert_eq!(
        keys("base = ioremap(0xFE200000, 0x100)", "mmio_address"),
        ["0xfe200000"]
    );
    assert!(keys("base = ioremap(0xFE200000)", "memory_address").is_empty());
    assert_eq!(
        keys("i2cset -y 1 0x48 0x01", "i2c_address"),
        ["0x01", "0x48"]
    );
    assert!(keys("retry 0x48 times", "i2c_address").is_empty());
}

#[test]
fn finds_mac_addresses_but_not_ipv6() {
    assert_eq!(
        keys(
            "ether 00:1A:2B:3C:4D:5E and 00-1a-2b-3c-4d-5f and 001a.2b3c.4d60",
            "mac_address"
        ),
        [
            "00:1a:2b:3c:4d:5e",
            "00:1a:2b:3c:4d:5f",
            "00:1a:2b:3c:4d:60"
        ]
    );
    assert!(
        keys(
            "inet6 fe80::1 2001:db8:0:1:2:3:4:5 00:00:00:00:00:00",
            "mac_address"
        )
        .is_empty()
    );
}

#[test]
fn validates_wallet_addresses() {
    let text = "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy \
                or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq \
                or 0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
    assert_eq!(
        keys(text, "wallet_address"),
        [
            "0x742d35cc6634c0532925a3b844bc454e4438f44e",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ]
    );
    // One changed character breaks the Base58Check and Bech32 checksums.
    assert!(
        keys(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdp",
            "wallet_address"
        )
        .is_empty()
    );
}

#[test]
fn finds_unc_paths_raw_and_json_escaped() {
    let raw = keys(r"copy \\fileserver\share\docs\a.txt now", "unc_path");
    let escaped = keys(
        r#"{"path":"\\\\fileserver\\share\\docs\\a.txt"}"#,
        "unc_path",
    );
    assert_eq!(raw, [r"\\fileserver\share\docs\a.txt"]);
    assert_eq!(raw, escaped);
    assert!(keys(r#"{"path":"C:\\Users\\me\\a.txt"}"#, "unc_path").is_empty());
    assert_eq!(keys("smb://nas/backup", "unc_path"), ["smb://nas/backup"]);
}

#[test]
fn finds_cloud_arns() {
    assert_eq!(
        keys(
            "assume arn:aws:iam::123456789012:role/Admin, bucket arn:aws:s3:::logs-bucket/*",
            "cloud_arn"
        ),
        [
            "arn:aws:iam::123456789012:role/Admin",
            "arn:aws:s3:::logs-bucket/*"
        ]
    );
}

#[test]
fn hashes_and_masks_credentials() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let text = format!(
        "Authorization: Bearer {jwt}\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
         token ghp_abcdefghijklmnopqrstuvwxyz0123456789\napi_key: \"q8Zr2Lm4Np6Tx0Vb3Kd7\""
    );
    let tokens = extract_tokens(&text);
    let credentials: Vec<&Token> = tokens
        .iter()
        .filter(|token| token.category == Category::Credential)
        .collect();

    assert_eq!(of_kind(&text, "jwt").len(), 1);
    assert_eq!(decoded(&text, "jwt"), ["jwt(alg=HS256) eyJh…sw5c"]);
    assert_eq!(of_kind(&text, "api_key").len(), 3);
    for token in credentials {
        assert!(token.key.starts_with("sha256:"));
        for secret in [jwt, "AKIAIOSFODNN7EXAMPLE", "q8Zr2Lm4Np6Tx0Vb3Kd7"] {
            assert!(!token.decoded.contains(secret), "{token:?}");
        }
    }
    assert!(of_kind("token=${GITHUB_TOKEN} secret: changeme", "api_key").is_empty());
}

#[test]
fn keys_private_keys_the_same_raw_or_json_escaped() {
    let body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK";
    let raw = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
    let escaped = serde_json_escape(&raw);

    let raw_keys = keys(&raw, "private_key");
    assert_eq!(raw_keys.len(), 1);
    assert_eq!(raw_keys, keys(&escaped, "private_key"));
    assert!(decoded(&raw, "private_key")[0].starts_with("-----BEGIN RSA PRIVATE KEY----- ("));
    assert_eq!(
        keys("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key").len(),
        1
    );
}

fn serde_json_escape(value: &str) -> String {
    format!("{{\"stdout\":\"{}\"}}", value.replace('\n', "\\n"))
}

#[test]
fn finds_korean_personal_ids() {
    assert_eq!(
        decoded("주민번호 900101-1234567", "kr_rrn"),
        ["900101-1******"]
    );
    assert_eq!(
        decoded("jumin: 9001011234567", "kr_rrn"),
        ["900101-1******"]
    );
    assert!(of_kind("order 9001011234567 shipped", "kr_rrn").is_empty());
    assert!(of_kind("901301-1234567", "kr_rrn").is_empty());

    assert_eq!(decoded("여권번호: M123A4567", "passport"), ["M1*******"]);
    assert!(of_kind("SKU M123A4567", "passport").is_empty());

    assert_eq!(
        decoded("11-12-345678-90", "driver_license"),
        ["11-12-******-**"]
    );
    assert_eq!(
        decoded("면허번호 111234567890", "driver_license"),
        ["11-12-******-**"]
    );
    assert!(of_kind("id 111234567890", "driver_license").is_empty());
}

#[test]
fn validates_financial_ids() {
    assert_eq!(
        decoded("card 4111 1111 1111 1111", "card_pan"),
        ["411111******1111"]
    );
    assert_eq!(
        decoded("amex 378282246310005", "card_pan"),
        ["378282******0005"]
    );
    assert!(of_kind("4111111111111112 and 1234567890123456", "card_pan").is_empty());

    assert_eq!(
        decoded("입금 계좌: 110-123-456789", "bank_account"),
        ["110****89"]
    );
    assert!(of_kind("ticket 110-123-456789", "bank_account").is_empty());
    assert!(of_kind("account created 2024-01-15", "bank_account").is_empty());

    assert_eq!(
        keys("IBAN GB82 WEST 1234 5698 7654 32", "iban"),
        keys("DE89370400440532013000 GB82WEST12345698765432", "iban")
            .into_iter()
            .filter(|key| keys("GB82WEST12345698765432", "iban").contains(key))
            .collect::<Vec<_>>()
    );
    assert_eq!(decoded("DE89370400440532013000", "iban"), ["DE89****3000"]);
    assert!(of_kind("GB83WEST12345698765432", "iban").is_empty());
}

#[test]
fn validates_device_ids() {
    assert_eq!(
        decoded("IMEI: 490154203237518", "imei"),
        ["49015420*******8"]
    );
    assert_eq!(decoded("49-015420-323751-8", "imei"), ["49015420*******8"]);
    assert!(of_kind("serial 490154203237518", "imei").is_empty());
    assert!(of_kind("IMEI: 490154203237519", "imei").is_empty());

    assert_eq!(decoded("IMSI 450081234567890", "imsi"), ["45008*******890"]);
    assert!(of_kind("450081234567890", "imsi").is_empty());

    assert_eq!(decoded("1M8GDM9AXKP042788", "vin"), ["1M8GDM9AX********"]);
    assert_eq!(decoded("차대번호 KMHXX00XXXX000000", "vin").len(), 1);
    assert!(of_kind("BUILD1234567890AB", "vin").is_empty());
}

#[test]
fn categorizes_every_kind() {
    let text =
        "10.0.0.5:6379 AKIAIOSFODNN7EXAMPLE 900101-1234567 4111111111111111 49-015420-323751-8";
    let categories: Vec<(&str, &str)> = extract_tokens(text)
        .iter()
        .map(|token| (token.kind, token.category.as_str()))
        .collect();

    for expected in [
        ("socket_address", "address"),
        ("api_key", "credential"),
        ("kr_rrn", "pii"),
        ("card_pan", "financial"),
        ("imei", "device"),
    ] {
        assert!(
            categories.contains(&expected),
            "{expected:?} in {categories:?}"
        );
    }
}
