//! Whole-payload age transforms for the external-storage adapter.
//!
//! This is separate from Git clean/smudge: no inline markers, whole-file buffers,
//! network operations, recipient creation, or changes to the Git filter's limits.

use anyhow::{bail, Context, Result};
use dracon_security_kit::WardenSecurity;
use std::io::{Read, Write};

const BUFFER_BYTES: usize = 64 * 1024;

fn copy_bounded(input: &mut dyn Read, output: &mut dyn Write, max_bytes: u64) -> Result<u64> {
    if max_bytes == 0 {
        bail!("payload byte budget must be positive");
    }
    let mut buffer = [0u8; BUFFER_BYTES];
    let mut bytes = 0u64;
    loop {
        let count = match input.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            value => value?,
        };
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("payload byte counter overflow")?;
        if bytes > max_bytes {
            bail!("payload exceeded configured byte budget");
        }
        output.write_all(&buffer[..count])?;
    }
    Ok(bytes)
}

pub(crate) fn encrypt(
    security: &WardenSecurity,
    input: &mut dyn Read,
    output: &mut dyn Write,
    max_bytes: u64,
) -> Result<u64> {
    if max_bytes == 0 {
        bail!("payload byte budget must be positive");
    }
    // Reuse the existing owner/authorized machine/team trust checks. Do not accept
    // untrusted repository recipients or arbitrary CLI-provided recipient keys.
    let recipients = security.gather_all_recipients()?;
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipients
        .into_iter()
        .map(|recipient| Box::new(recipient) as Box<dyn age::Recipient + Send>)
        .collect();
    let encryptor = age::Encryptor::with_recipients(recipients)
        .context("no authorized payload encryption recipients")?;
    let mut writer = encryptor.wrap_output(output)?;
    let bytes = copy_bounded(input, &mut writer, max_bytes)?;
    writer.finish()?;
    Ok(bytes)
}

pub(crate) fn decrypt(
    security: &WardenSecurity,
    input: &mut dyn Read,
    output: &mut dyn Write,
    max_bytes: u64,
) -> Result<u64> {
    if max_bytes == 0 {
        bail!("payload byte budget must be positive");
    }
    if security.master_identities().is_empty() {
        bail!("authorized local identity required for payload decryption");
    }
    let decryptor =
        age::Decryptor::new(input).map_err(|_| anyhow::anyhow!("invalid encrypted payload"))?;
    let age::Decryptor::Recipients(decryptor) = decryptor else {
        bail!("passphrase payloads are not supported");
    };
    let identities = security
        .master_identities()
        .iter()
        .map(|identity| identity as &dyn age::Identity);
    let mut reader = decryptor
        .decrypt(identities)
        .map_err(|_| anyhow::anyhow!("payload identity is not authorized"))?;
    // Authenticated chunks may be emitted before final authentication fails.
    // Callers must keep output private/unpublished until this returns success.
    copy_bounded(&mut reader, output, max_bytes)
        .map_err(|_| anyhow::anyhow!("payload decryption or output budget failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_copy_refuses_oversize_without_whole_file_buffering() {
        struct Source {
            remaining: u64,
            largest: usize,
        }
        impl Read for Source {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.largest = self.largest.max(buffer.len());
                let count = self.remaining.min(buffer.len() as u64) as usize;
                buffer[..count].fill(7);
                self.remaining -= count as u64;
                Ok(count)
            }
        }
        let mut source = Source {
            remaining: 101 * 1024 * 1024,
            largest: 0,
        };
        assert_eq!(
            copy_bounded(&mut source, &mut std::io::sink(), 101 * 1024 * 1024).unwrap(),
            101 * 1024 * 1024
        );
        assert_eq!(source.largest, BUFFER_BYTES);
        assert!(copy_bounded(&mut &[1u8; 20][..], &mut Vec::new(), 19).is_err());
        assert!(copy_bounded(&mut &b""[..], &mut Vec::new(), 0).is_err());
    }
}
