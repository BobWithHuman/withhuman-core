//! The viewer's login: it reads every table the schema lists, `api_keys` without its hash, and
//! writes nothing. Runs against `POSTGRES_INTEGRATION_URL`, like `postgres_integration.rs`.

use tokio_postgres::{Client, NoTls, error::SqlState};
use withhuman_generator::PgGraphRepository;

const READABLE: [&str; 26] = [
    "sessions",
    "event_commits",
    "nodes",
    "subgraphs",
    "paragraphs",
    "tokens",
    "token_mentions",
    "files",
    "file_refs",
    "cause_edges",
    "pending_paragraph_enrichments",
    "pending_request_continuations",
    "clients",
    "client_projects",
    "users",
    "key_events",
    "session_stops",
    "call_reviews",
    "call_review_latest",
    "stop_audit",
    "client_cwds",
    "client_seen_projects",
    "exceptions",
    "project_protection",
    "model_calls",
    "unprotected_model_calls",
];

#[tokio::test]
async fn the_viewer_reads_and_never_writes() {
    let Ok(url) = std::env::var("POSTGRES_INTEGRATION_URL") else {
        return;
    };
    // A quote in the password must reach the role as it is.
    let password = format!("viewer'it-{}", std::process::id());
    PgGraphRepository::connect_with_viewer(&url, 1, Some(&password))
        .await
        .unwrap();
    // A grant made outside the schema, such as an earlier viewer's DELETE, is taken back.
    let owner = connect(url.parse().unwrap()).await;
    owner
        .batch_execute("GRANT DELETE, INSERT ON sessions TO withhuman_viewer")
        .await
        .unwrap();
    PgGraphRepository::connect_with_viewer(&url, 1, Some(&password))
        .await
        .unwrap();

    let mut config: tokio_postgres::Config = url.parse().unwrap();
    config
        .user("withhuman_viewer")
        .password(password.as_bytes());
    let viewer = connect(config).await;
    for table in READABLE {
        viewer
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap_or_else(|error| panic!("{table}: {error}"));
    }
    viewer
        .query_one(
            "SELECT count(key_id), count(user_email), count(revoked_by), count(first_denied_at) \
             FROM api_keys",
            &[],
        )
        .await
        .unwrap();
    // Without the read-only default, the grants alone still refuse writes.
    viewer
        .batch_execute("SET default_transaction_read_only = off")
        .await
        .unwrap();
    for statement in [
        "SELECT hash FROM api_keys",
        "SELECT * FROM api_keys",
        "INSERT INTO sessions (session_id) VALUES ('v')",
        "DELETE FROM sessions",
        "UPDATE api_keys SET revoked_at = 1",
        "DELETE FROM key_events",
        "CREATE TABLE viewer_made (x int)",
    ] {
        let error = viewer.batch_execute(statement).await.unwrap_err();
        assert_eq!(
            error.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}: {error}"
        );
    }
    // A new session starts read-only.
    let mut config: tokio_postgres::Config = url.parse().unwrap();
    config
        .user("withhuman_viewer")
        .password(password.as_bytes());
    let fresh = connect(config).await;
    let row = fresh
        .query_one("SHOW default_transaction_read_only", &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "on");
}

async fn connect(config: tokio_postgres::Config) -> Client {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}
