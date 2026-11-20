// Verifies the README's usage snippets compile and behave.
use secretmem::{harden_process, HardeningOptions, SecretKey, SecretString};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = harden_process(HardeningOptions::default())?;
    assert!(report.is_complete(), "some leak paths remain: {report:?}");

    let mut pw = SecretString::from_str("hunter2")?;
    assert_eq!(pw.expose(), "hunter2");
    pw.wipe();

    let key: SecretKey<32> = secretmem::derive_key(b"master-seed", &[b"session"])?;
    assert_eq!(key.expose().len(), 32);
    Ok(())
}
