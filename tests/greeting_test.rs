use withhuman_core::greeting;

#[test]
fn returns_greeting_from_public_api() {
    assert_eq!(greeting("Rust"), "Hello, Rust!");
}
