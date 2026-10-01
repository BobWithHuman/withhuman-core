/// Returns a greeting for the given name.
pub fn greeting(name: &str) -> String {
    format!("Hello, {name}!")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_greeting_for_name() {
        assert_eq!(greeting("WithHuman"), "Hello, WithHuman!");
    }
}
