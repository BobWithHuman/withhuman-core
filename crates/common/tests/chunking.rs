use withhuman_common::chunking::{MAX_CHARS, Profile, SHORT_CHARS, chunk_text, sha256};

fn texts(text: &str, profile: Profile) -> Vec<String> {
    chunk_text(text, profile)
        .into_iter()
        .map(|chunk| chunk.text)
        .collect()
}

fn sentence(index: usize) -> String {
    format!("Sentence number {index} explains one more detail about the deployment. ")
}

#[test]
fn short_paragraphs_absorb_the_following_paragraph() {
    let chunks = texts("Title\nfirst line\n\nsecond line", Profile::Prose);

    assert_eq!(chunks, ["Title\nfirst line\nsecond line"]);
}

#[test]
fn paragraphs_long_enough_stand_alone() {
    let first = "a".repeat(SHORT_CHARS);
    let second = "b".repeat(10);

    let chunks = texts(&format!("{first}\n{second}"), Profile::Prose);

    assert_eq!(chunks, [first, second]);
}

#[test]
fn merging_never_exceeds_the_limit() {
    let short = "s".repeat(SHORT_CHARS - 1);
    let long = "l ".repeat(250).trim().to_owned();

    let chunks = chunk_text(&format!("{short}\n{long}"), Profile::Prose);

    assert_eq!(chunks.len(), 2);
    assert!(chunks.iter().all(|chunk| !chunk.long_paragraph));
}

#[test]
fn windows_and_old_mac_line_breaks_split_like_unix_ones() {
    let first = "a".repeat(SHORT_CHARS);
    let second = "b".repeat(SHORT_CHARS);

    let chunks = texts(&format!("{first}\r\n\r\n{second}\r{first}"), Profile::Prose);

    assert_eq!(chunks, [first.clone(), second, first]);
}

#[test]
fn long_lines_are_cut_at_sentence_ends_and_labelled() {
    let line = (0..30).map(sentence).collect::<String>();

    let chunks = chunk_text(&line, Profile::Prose);

    assert!(chunks.len() > 1);
    for chunk in &chunks {
        assert!(chunk.long_paragraph);
        assert!(chunk.text.chars().count() <= MAX_CHARS);
        assert!(chunk.text.ends_with("deployment."), "{:?}", chunk.text);
    }
}

#[test]
fn lengths_are_counted_in_chars_not_bytes() {
    let line = "가나다라마바사아자차 ".repeat(100);

    let chunks = chunk_text(&line, Profile::Prose);

    assert!(chunks.len() > 1);
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.text.chars().count() <= MAX_CHARS)
    );
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.text.chars().count() > MAX_CHARS / 2)
    );
}

#[test]
fn a_value_without_whitespace_is_kept_whole_even_past_the_limit() {
    let blob = "QUJD".repeat(400);
    let line = format!("payload {blob} trailing words");

    let chunks = chunk_text(&line, Profile::ToolOutput);

    assert!(chunks.iter().any(|chunk| chunk.text.contains(&blob)));
    assert!(chunks.iter().all(|chunk| chunk.long_paragraph));
}

#[test]
fn addresses_are_never_split() {
    let addresses = [
        "https://example.com/a/b?query=value%20with%20space&next=%2Fhome#frag",
        "10.0.0.12:5432",
        "[2001:db8::1]:8443",
        "unix:///var/run/docker.sock",
        "kafka://broker-1.internal:9092",
        "PLAINTEXT://broker-2.internal:9093",
        "amqps://user:secret@mq.internal:5671/vhost",
        "postgres://app:secret@db.internal:5432/app?sslmode=require",
        "jdbc:mysql://db.internal:3306/app?useSSL=true",
        "mongodb+srv://user:secret@cluster0.mongodb.net/app",
        "redis://:secret@cache.internal:6379/0",
        "0x7ffd5e8c1a40",
        "7f3a2c000000-7f3a2c021000",
        "0xFE200000",
        "i2c-1:0x48",
        "00:1A:2B:3C:4D:5E",
        "00-1A-2B-3C-4D-5E",
        "001a.2b3c.4d5e",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "\\\\fileserver\\shared\\reports\\2026.xlsx",
        "arn:aws:iam::123456789012:role/service-role/Deploy",
        "arn:aws:s3:::bucket-name/path/to/object",
        "projects/acme/locations/us-central1/keyRings/ring/cryptoKeys/key",
        "/subscriptions/0000-1111/resourceGroups/rg/providers/Microsoft.Web/sites/app",
        "s3://bucket-name/path/to/object.parquet",
        "git@github.com:acme/withhuman-core.git",
        "ghcr.io/acme/app:1.2.3@sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "10.0.0.0/24",
        "user.name+tag@example.co.kr",
        "C:\\Program Files\\Withhuman Agent\\bin\\agent.exe",
        "host=db.internal port=5432 dbname=app user=app password='a b c'",
        "Server=db.internal;Initial Catalog=app;User Id=app;Password=secret;",
        "kafka-1:9092, kafka-2:9092, kafka-3:9092",
        "2026-10-23 12:34:56.789 +09:00",
        "de ad be ef 00 11 22 33 44 55",
        "[deployment guide for the payment service](https://docs.example.com/payments/deploy)",
        "`docker compose up --build generator`",
    ];
    for address in addresses {
        for offset in [0, 1, 7, 13, 29, 41, 57] {
            let filler = "word ".repeat(115 + offset);
            let line = format!("{filler}{address} {filler}");

            for profile in [Profile::Prose, Profile::ToolOutput] {
                let chunks = texts(&line, profile);

                assert!(
                    chunks.iter().any(|chunk| chunk.contains(address)),
                    "{address:?} was split at offset {offset}: {chunks:#?}"
                );
            }
        }
    }
}

#[test]
fn fenced_code_stays_together_across_blank_lines() {
    let text = "Run this:\n```rust\nfn main() {\n\n    println!(\"hi\");\n}\n```\nDone.";

    let chunks = texts(text, Profile::Prose);

    assert_eq!(
        chunks,
        ["Run this:\n```rust\nfn main() {\n\n    println!(\"hi\");\n}\n```\nDone."]
    );
}

#[test]
fn long_fenced_code_is_cut_between_lines() {
    let body = (0..40)
        .map(|index| format!("    let value_{index} = compute({index});"))
        .collect::<Vec<_>>()
        .join("\n");
    let text = format!("```rust\n{body}\n```");

    let chunks = chunk_text(&text, Profile::ToolOutput);

    assert!(chunks.len() > 1);
    for chunk in &chunks {
        assert!(chunk.long_paragraph);
        assert!(chunk.text.chars().count() <= MAX_CHARS);
        assert!(chunk.text.lines().all(|line| text.contains(line)));
    }
}

#[test]
fn pem_blocks_and_wrapped_base64_are_never_cut() {
    let body = (0..20)
        .map(|_| "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj")
        .collect::<Vec<_>>()
        .join("\n");
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\nAB==\n-----END PRIVATE KEY-----");
    let wrapped = format!("{body}\nAB==");

    for value in [pem, wrapped] {
        let chunks = chunk_text(
            &format!("Key follows:\n{value}\nThat was it."),
            Profile::ToolOutput,
        );

        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.text == value && chunk.long_paragraph)
        );
    }
}

#[test]
fn a_list_of_hex_hashes_is_not_treated_as_one_value() {
    let hash = sha256("x");
    let text = vec![hash.as_str(); 20].join("\n");

    let chunks = chunk_text(&text, Profile::ToolOutput);

    assert!(chunks.len() > 1);
    assert!(chunks.iter().all(|chunk| !chunk.long_paragraph));
}

#[test]
fn chunks_are_indexed_and_hashed_by_their_text() {
    let first = "a".repeat(SHORT_CHARS);

    let chunks = chunk_text(&format!("{first}\nsecond"), Profile::Prose);

    assert_eq!(chunks[0].index, 0);
    assert_eq!(chunks[1].index, 1);
    assert_eq!(chunks[1].hash, sha256("second"));
}

#[test]
fn blank_text_has_no_chunks() {
    assert!(chunk_text(" \n\r\n\t\n", Profile::Prose).is_empty());
}
