//! Compile-time checks that the dependencies' `zeroize` features are on: each of these types
//! only implements [`ZeroizeOnDrop`] when its crate's `zeroize` feature is enabled, so turning
//! a feature off in `Cargo.toml` fails this module's build.

use zeroize::ZeroizeOnDrop;

fn wipes_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn block_ciphers_wipe_key_schedules() {
    wipes_on_drop::<aes::Aes128>();
    wipes_on_drop::<aes::Aes192>();
    wipes_on_drop::<aes::Aes256>();
    wipes_on_drop::<blowfish::Blowfish>();
    wipes_on_drop::<camellia::Camellia128>();
    wipes_on_drop::<cast5::Cast5>();
    wipes_on_drop::<des::TdesEde3>();
    wipes_on_drop::<idea::Idea>();
    wipes_on_drop::<twofish::Twofish>();
}

#[test]
fn modes_wipe_state() {
    wipes_on_drop::<cfb_mode::Encryptor<aes::Aes256>>();
    wipes_on_drop::<cfb_mode::Decryptor<aes::Aes256>>();
    wipes_on_drop::<ctr::Ctr32BE<aes::Aes256>>();
    wipes_on_drop::<cmac::CmacCore<aes::Aes256>>();
}

// Not checked here: the `zeroize` features of aes-gcm and ghash only wipe temporary key copies
// in `new`, which no type-level check can see. polyval 0.6's `zeroize` only helps its soft
// backend: on x86 the autodetect backend holds the state in a `ManuallyDrop` union and never
// drops it (`needs_drop::<polyval::Polyval>()` is false either way), and the aarch64 (pmull)
// backend has no wipe.

#[cfg(feature = "pqc")]
#[test]
fn shake_wipes_sponge_state() {
    wipes_on_drop::<shake::Shake256>();
}
