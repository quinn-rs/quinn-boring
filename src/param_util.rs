use boring::hash::{Hasher, MessageDigest};
use boring_sys as bffi;
use bytes::{BufMut, Bytes, BytesMut};
use quinn_proto::transport_parameters::TransportParameters;

pub(crate) fn encode_params(params: &TransportParameters) -> Bytes {
    let mut out = BytesMut::with_capacity(128);
    params.write(&mut out);
    out.freeze()
}

/// Encodes the transport parameters for use with 0-RTT packets. The logic was copied from
/// the Google Quiche library.
pub(crate) fn encode_early_data_context(
    params: &TransportParameters,
    application_state: &Option<Vec<u8>>,
) -> Bytes {
    let mut out = BytesMut::with_capacity(1 + bffi::SHA256_DIGEST_LENGTH as usize);
    let serialization_version = 0u8;
    out.put_u8(serialization_version);

    // The format of the input to the hash function is as follows:
    // - The application data, prefixed with a 64-bit length field.
    // - Transport parameters:
    //   - A 64-bit version field indicating which version of encoding is used
    //     for transport parameters.
    //   - A list of 64-bit integers representing the relevant parameters.
    //
    //   When changing which parameters are included, additional parameters can be
    //   added to the end of the list without changing the version field. New
    //   parameters that are variable length must be length prefixed. If
    //   parameters are removed from the list, the version field must be
    //   incremented.
    //
    // Integers happen to be written in host byte order, not network byte order.
    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();

    // Hash the application state.
    let application_state: &[u8] = if let Some(state) = application_state {
        state
    } else {
        &[]
    };
    hasher
        .update(&(application_state.len() as u64).to_ne_bytes())
        .unwrap();
    hasher.update(application_state).unwrap();

    // Hash the transport parameters, as specified by
    // https://datatracker.ietf.org/doc/html/rfc9000#section-7.4.1.
    let parameter_version = 0u64;
    hasher.update(&parameter_version.to_ne_bytes()).unwrap();
    hasher
        .update(&params.initial_max_data().to_ne_bytes())
        .unwrap();
    hasher
        .update(&params.initial_max_stream_data_bidi_local().to_ne_bytes())
        .unwrap();
    hasher
        .update(&params.initial_max_stream_data_bidi_remote().to_ne_bytes())
        .unwrap();
    hasher
        .update(&params.initial_max_stream_data_uni().to_ne_bytes())
        .unwrap();
    hasher
        .update(&params.initial_max_streams_bidi().to_ne_bytes())
        .unwrap();
    hasher
        .update(&params.initial_max_streams_uni().to_ne_bytes())
        .unwrap();
    hasher
        .update(&params.active_connection_id_limit().to_ne_bytes())
        .unwrap();

    let disable_active_migration: [u8; 1] = [params.disable_active_migration().into()];
    hasher.update(&disable_active_migration).unwrap();

    // Add the output of the hasher and return.
    out.extend_from_slice(&*hasher.finish().unwrap());
    out.freeze()
}
