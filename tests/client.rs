use std::{error::Error, time::Duration};

use openssl::{pkey::PKey, rsa::Rsa};
use papaleguas::{AcmeClient, OrderStatus};
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
    let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

    let account = acme
        .new_account()
        .private_key(pkey)
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await;

    assert!(account.is_ok());
}

#[tokio::test]
async fn test_error() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_rsa_key()
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
    let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;

    let account = acme
        .new_account()
        .private_key(pkey.clone())
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    let retrieved_account = acme.account_from_private_key(pkey).await?;

    assert_eq!(account.kid(), retrieved_account.kid());

    Ok(())
}

#[tokio::test]
async fn test_order_list() -> TestResult {
    let acme = pebble_client().await?;

    let account = acme
        .new_account()
        .with_auto_generated_rsa_key()
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
        .with_auto_generated_rsa_key()
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
        .with_auto_generated_rsa_key()
        .contact("example@example.org")
        .contact("owner@example.org")
        .terms_of_service_agreed(true)
        .only_return_existing(false)
        .send()
        .await?;

    let key = account.key().clone();

    let order = account.new_order().dns("acme.example.org").send().await?;

    let http_challenge = order
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
        .json({
            let key = base64::encode_config(&key.jwk_digest()?, base64::URL_SAFE_NO_PAD);
            let token = http_challenge.token();

            &json!({
                "token": http_challenge.token(),
                "content": format!("{token}.{key}"),
            })
        })
        .send()
        .await?;

    http_challenge.validate().await?;

    let _cert = loop {
        let order = account.find_order(order.url()).await?;

        match order.status() {
            OrderStatus::Pending => {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            OrderStatus::Ready => {
                let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;
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
