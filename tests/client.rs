use std::{error::Error, time::Duration};

use papaleguas::{AcmeClient, OrderStatus, PrivateKey};
use rand::thread_rng;
use reqwest::Certificate;
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

async fn pebble_http_client() -> Result<reqwest::Client, Box<dyn Error>> {
    let cert = tokio::fs::read("./tests/pebble/pebble.minica.pem").await?;
    let cert = Certificate::from_pem(&cert)?;
    let http = reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()?;
    Ok(http)
}

async fn pebble_client() -> Result<AcmeClient, Box<dyn Error>> {
    let client = AcmeClient::builder()
        .http_client(pebble_http_client().await?)
        .build_with_directory_url("https://localhost:14000/dir")
        .await?;
    Ok(client)
}

#[tokio::test]
async fn test_directory_from_url() {
    let client = pebble_client().await;
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_create_account() {
    let acme = pebble_client().await.unwrap();

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await;

    assert!(account.is_ok());

    let rng = rand::thread_rng();
    let key = PrivateKey::random_ec_key(rng);
    let account = acme
        .new_account()
        .private_key(key.clone())
        .contact("example@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await;
    assert!(account.is_ok());
    let account = account.unwrap();

    let same_account = acme
        .new_account()
        .private_key(key.clone())
        .contact("example@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await;
    assert!(same_account.is_ok());

    assert_eq!(account.kid(), same_account.unwrap().kid());

    let same_account = acme.existing_account_from_private_key(key).await;
    assert!(same_account.is_ok());
    assert_eq!(account.kid(), same_account.unwrap().kid());
}

#[tokio::test]
async fn test_error() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .terms_of_service_agreed(false)
        .only_return_existing(false)
        .send()
        .await;

    assert!(account.is_err());

    Ok(())
}

#[tokio::test]
async fn test_retrive_account() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    let retrieved_account = acme
        .existing_account_from_private_key(account.key().clone())
        .await?;

    assert_eq!(account.kid(), retrieved_account.kid());

    Ok(())
}

#[tokio::test]
async fn test_order_list() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    for i in 1..=3 {
        account
            .new_order()
            .dns(format!("{i}.example.org"))
            .send()
            .await?;
    }

    assert_eq!(3, account.orders_urls().await?.len());

    Ok(())
}

#[tokio::test]
async fn test_create_order() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    let order = account
        .new_order()
        .dns("some-name.example.org")
        .send()
        .await;

    assert!(order.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_generate_certificate_via_http01() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    let order = account
        .new_order()
        .dns("acme-http.example.org")
        .send()
        .await?;

    let challenge = order
        .authorizations()
        .await?
        .first()
        .and_then(|auth| auth.http01_challenge())
        .ok_or("Http challenge not found")?;

    let challenge_test_client = reqwest::Client::new();

    challenge_test_client
        .post("http://localhost:8055/add-a")
        .json(&json!({
            "host": "acme.example.org",
            "addresses": ["10.30.50.3"],
        }))
        .send()
        .await?;

    challenge_test_client
        .post("http://localhost:8055/add-http01")
        .json(&json!({
            "token": challenge.token(),
            "content": challenge.key_authorization()?,
        }))
        .send()
        .await?;

    challenge.validate().await?;

    let _cert = loop {
        let order = account.find_order(order.url()).await?;

        match order.status() {
            OrderStatus::Pending => {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            OrderStatus::Ready => {
                let pkey = papaleguas::PrivateKey::random_ec_key(thread_rng());
                order.finalize(&pkey).await?;
            }
            OrderStatus::Processing => continue,
            OrderStatus::Valid => break order.certificate().await?,
            OrderStatus::Invalid => {
                return Err("Invalid order".into());
            }
        }
    };

    Ok(())
}

#[tokio::test]
async fn test_generate_certificate_via_tlsalpn01() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_ec_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    let order = account
        .new_order()
        .dns("acme-tls.example.org")
        .send()
        .await?;

    let challenge = order
        .authorizations()
        .await?
        .first()
        .and_then(|auth| auth.tls_alpn01_challenge())
        .ok_or("Challenge not found")?;

    let challenge_test_client = reqwest::Client::new();

    challenge_test_client
        .post("http://localhost:8055/add-a")
        .json(&json!({
            "host": "acme-tls.example.org",
            "addresses": ["10.30.50.3"],
        }))
        .send()
        .await?;

    challenge_test_client
        .post("http://localhost:8055/add-tlsalpn01")
        .json(&json!({
            "host": "acme-tls.example.org",
            "content": challenge.key_authorization()?,
        }))
        .send()
        .await?;

    challenge.validate().await?;

    let pkey = papaleguas::PrivateKey::random_ec_key(thread_rng());
    let _cert = loop {
        let order = account.find_order(order.url()).await?;

        match order.status() {
            OrderStatus::Pending => {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            OrderStatus::Ready => {
                order.finalize(&pkey).await?;
            }
            OrderStatus::Processing => continue,
            OrderStatus::Valid => break order.certificate().await?,
            OrderStatus::Invalid => {
                return Err("Invalid order".into());
            }
        }
    };

    Ok(())
}
