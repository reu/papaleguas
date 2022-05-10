use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Name, X509Req, X509ReqBuilder},
};

use crate::error::AcmeResult;

pub fn generate_csr(private_key: &PKey<Private>, domains: &[&str]) -> AcmeResult<X509Req> {
    let mut csr = X509ReqBuilder::new()?;

    csr.set_pubkey(private_key)?;

    csr.set_subject_name({
        let domain = domains.get(0).ok_or("No domain informed")?;
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", domain)?;
        name.build().as_ref()
    })?;

    let mut stack = Stack::new()?;

    let san_extension = domains
        .iter()
        .fold(&mut SubjectAlternativeName::new(), |names, name| {
            names.dns(name)
        })
        .build(&csr.x509v3_context(None))?;

    stack.push(san_extension)?;

    csr.add_extensions(&stack)?;

    csr.sign(private_key, MessageDigest::sha256())?;

    Ok(csr.build())
}
