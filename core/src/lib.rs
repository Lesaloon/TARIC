pub struct VerifyingKey {
    pub algo: &'static str,
    pub key: Vec<u8>,
    pub key_id: Option<String>,
}

pub trait DeviceTrust: Send + Sync {
    fn get_key(&self, device_id: &str, key_id: Option<&str>) -> Option<VerifyingKey>;
    fn is_revoked(&self, _device_id: &str, _key_id: Option<&str>) -> bool { false }
}

pub trait AckSigner: Send + Sync {
    fn signer_id(&self) -> &'static str;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

// TODO: add chaining/storage/verify logic here.
pub fn version() -> &'static str { "taric-core 0.1.0" }
