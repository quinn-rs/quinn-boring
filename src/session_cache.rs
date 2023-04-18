use crate::error::Result;
use crate::{Error, QuicSslSession};
use boring::ssl::{SslContextRef, SslSession};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use lru::LruCache;
use quinn_proto::{transport_parameters::TransportParameters, Side};
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// A client-side Session cache for the BoringSSL crypto provider.
pub trait SessionCache: Send + Sync {
    /// Adds the given value to the session cache.
    fn put(&self, key: Bytes, value: Bytes);

    /// Returns the cached session, if it exists.
    fn get(&self, key: Bytes) -> Option<Bytes>;

    /// Removes the cached session, if it exists.
    fn remove(&self, key: Bytes);

    /// Removes all entries from the cache.
    fn clear(&self);
}

/// A utility for combining an [SslSession] and server [TransportParameters] as a
/// [SessionCache] entry.
pub struct Entry {
    pub session: SslSession,
    pub params: TransportParameters,
}

impl Entry {
    /// Encodes this [Entry] into a [SessionCache] value.
    pub fn encode(&self) -> Result<Bytes> {
        let mut out = BytesMut::with_capacity(2048);

        // Split the buffer in two: the length prefix buffer and the encoded session buffer.
        // This will be O(1) as both will refer to the same underlying buffer.
        let mut encoded = out.split_off(8);

        // Store the session in the second buffer.
        self.session.encode(&mut encoded)?;

        // Go back and write the length to the first buffer.
        out.put_u64(encoded.len() as u64);

        // Unsplit to merge the two buffers back together. This will be O(1) since
        // the buffers are already contiguous in memory.
        out.unsplit(encoded);

        // Now add the transport parameters.
        out.reserve(128);
        let mut encoded = out.split_off(out.len() + 8);
        self.params.write(&mut encoded);
        out.put_u64(encoded.len() as u64);
        out.unsplit(encoded);

        Ok(out.freeze())
    }

    /// Decodes a [SessionCache] value into an [Entry].
    pub fn decode(ctx: &SslContextRef, mut encoded: Bytes) -> Result<Self> {
        // Decode the session.
        let len = encoded.get_u64() as usize;
        let mut encoded_session = encoded.split_to(len);
        let session = SslSession::decode(ctx, &mut encoded_session)?;

        // Decode the transport parameters.
        let len = encoded.get_u64() as usize;
        let mut encoded_params = encoded.split_to(len);
        let params = TransportParameters::read(Side::Client, &mut encoded_params).map_err(|e| {
            Error::invalid_input(format!(
                "failed parsing cached transport parameters: {:?}",
                e
            ))
        })?;

        Ok(Self { session, params })
    }
}

/// A [SessionCache] implementation that will never cache anything. Requires no storage.
pub struct NoSessionCache;

impl SessionCache for NoSessionCache {
    fn put(&self, _: Bytes, _: Bytes) {}

    fn get(&self, _: Bytes) -> Option<Bytes> {
        None
    }

    fn remove(&self, _: Bytes) {}

    fn clear(&self) {}
}

pub struct SimpleCache {
    cache: Mutex<LruCache<Bytes, Bytes>>,
}

impl SimpleCache {
    pub fn new(num_entries: usize) -> Self {
        SimpleCache {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(num_entries).unwrap())),
        }
    }
}

impl SessionCache for SimpleCache {
    fn put(&self, key: Bytes, value: Bytes) {
        let _ = self.cache.lock().unwrap().put(key, value);
    }

    fn get(&self, key: Bytes) -> Option<Bytes> {
        self.cache.lock().unwrap().get(&key).cloned()
    }

    fn remove(&self, key: Bytes) {
        let _ = self.cache.lock().unwrap().pop(&key);
    }

    fn clear(&self) {
        self.cache.lock().unwrap().clear()
    }
}

#[cfg(test)]
mod tests {
    use crate::session_cache::Entry;
    use crate::ClientConfig;
    use bytes::{BufMut, BytesMut};
    use hex_literal::hex;

    #[test]
    fn entry_encoding() {
        let encoded = {
            // Captured output from integration tests.
            let encoded_session = hex!("30820412020101020203040402130104206ed381170bbf75"
                "7901238adcd0a96ee46d1642775001abf602f69484510419d904201f66fb5b215a4f3a5fb5251c9a9a"
                "17cad88582361f0042faf2a000eb303f42e4a106020463e53fbea205020302a300a382015630820152"
                "3081f9a003020102020900b06e4d934b5c5d0d300a06082a8648ce3d0403023021311f301d06035504"
                "030c16726367656e2073656c66207369676e656420636572743020170d373530313031303030303030"
                "5a180f34303936303130313030303030305a3021311f301d06035504030c16726367656e2073656c66"
                "207369676e656420636572743059301306072a8648ce3d020106082a8648ce3d030107034200047582"
                "ef451a59ecae9cb170d4959664eb5631696e553f20df7db5f7cb59f550d67b795738145cf4bcde0e45"
                "4d0f3bd8d6a2510c75cc66ccaedf4a1340d6166c4ea318301630140603551d11040d300b82096c6f63"
                "616c686f7374300a06082a8648ce3d0403020348003045022100a46020ca34d0e8b7d79e4894d5c97f"
                "0eb72962a42cce0d59b8e83817db2216e302205993ee4d874d6d94e32c001354d5ad17959561ac9856"
                "5fc58abcb1860d2ca3f8a4020400aa81b30481b05c0ece9d9fe026ff4d507ca869cac8734184a0b12e"
                "18c7551a8612b0de5e409a6f2c5f1fde44ca8ebf6db38e663584a0f9196fa420f38490edf53f553ff9"
                "cdeb010fb86bebe050289a9e2af41aa6046b5f82d835921f6cca8777085d5dc6c662201331d6ac40bb"
                "65f11436cf18f0da48e0049ea5aab7e43fc1ba8bb784cbb6248ed26aae2a3fb3d487a040660b7057b3"
                "a16dd517ce22f3d4d80f2d994520cf1016cf79dad8fb763319b61b9d7abd8278b20302011db3820171"
                "3082016d30820112a0030201020208383312a7a721d5a4300a06082a8648ce3d0403023021311f301d"
                "06035504030c16726367656e2073656c66207369676e656420636572743020170d3735303130313030"
                "303030305a180f34303936303130313030303030305a3021311f301d06035504030c16726367656e20"
                "73656c66207369676e656420636572743059301306072a8648ce3d020106082a8648ce3d0301070342"
                "000465ed18244bdfe0b42219d0277c4984a57723a5391d41b658ec6eb1c20d3fb4d0239835d163c158"
                "88a39e3791b738b24a1b47b35a3c16f9e06a2773495bcc43bca3323030301d0603551d0e04160414a4"
                "d521a7a7123338ed83272d04d60e50f4c39c1c300f0603551d130101ff040530030101ff300a06082a"
                "8648ce3d040302034900304602210082207a475582b6a2a48ffecea8dfe3aea6b84a19919a392ae779"
                "282bf6074e64022100aa5e1fd03607db29ff144d61815f6730f60d9fe4f227b2f093b93f3acb5cefa4"
                "b506040425b2131eb603010100b70402020403b9050203093a80ba050403666f6fbb030101ff");
            let encoded_params = hex!("01026710030245c80408ffffffffffffffff0504801312d00604801312d0"
                "0704801312d008024064090240640e010540b60020048000ffff0f0880145d492e958b6f6ab200");
            let mut out = BytesMut::new();
            out.put_u64(encoded_session.len() as u64);
            out.extend_from_slice(&encoded_session);
            out.put_u64(encoded_params.len() as u64);
            out.extend_from_slice(&encoded_params);
            out.freeze()
        };

        let cfg = ClientConfig::new().unwrap();
        let ctx = cfg.ctx().as_ref();
        let decoded = Entry::decode(ctx, encoded.clone()).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(&encoded, &re_encoded);
    }
}
