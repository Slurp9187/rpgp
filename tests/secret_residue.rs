//! Heap-residue tests: secret key material must not be left behind in freed memory.
//!
//! A recording global allocator scans every block before it is freed, and the old block of
//! every reallocation, for "needles": windows of the secret key material and the passphrase
//! of the key under test. The scan runs before anything is wiped, so a hit is a block rPGP
//! released without wiping it; a zeroizing allocator in the application is not relied on.
//!
//! After scanning, the allocator does wipe every block, armed or not. That is only for
//! attribution: residue left by the unarmed setup (key generation, serialization) would
//! otherwise sit in reused blocks and be blamed on the operation under test, and a leak would
//! be counted again each time its block is reused.
//!
//! Set `RESIDUE_BACKTRACE=1` to print a backtrace for every hit.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Mutex,
    },
};

use pgp::{
    composed::{
        Deserializable, DetachedSignature, EncryptionCaps, KeyType, MessageBuilder,
        SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    ser::Serialize,
    types::{
        KeyVersion, Password, PlainSecretParams, S2kParams, StringToKey,
    },
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

// ---------------------------------------------------------------------------------------------
// The recording allocator

const MAX_NEEDLES: usize = 8;
const NEEDLE_LEN: usize = 16;

struct Recording;

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static NEEDLE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU8 = AtomicU8::new(0);
static NEEDLES: [AtomicU8; MAX_NEEDLES * NEEDLE_LEN] = [ZERO; MAX_NEEDLES * NEEDLE_LEN];
static BACKTRACES: Mutex<Vec<String>> = Mutex::new(Vec::new());

thread_local! {
    static IN_SCAN: Cell<bool> = const { Cell::new(false) };
}

fn want_backtrace() -> bool {
    std::env::var_os("RESIDUE_BACKTRACE").is_some()
}

/// Scans a block that is about to be released.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes.
unsafe fn scan(ptr: *const u8, len: usize) {
    if !ARMED.load(Ordering::Acquire) || len < NEEDLE_LEN {
        return;
    }
    if IN_SCAN.with(|f| f.replace(true)) {
        return;
    }
    let block = unsafe { std::slice::from_raw_parts(ptr, len) };
    let count = NEEDLE_COUNT.load(Ordering::Acquire);
    for n in 0..count {
        let mut needle = [0u8; NEEDLE_LEN];
        for (i, b) in needle.iter_mut().enumerate() {
            *b = NEEDLES[n * NEEDLE_LEN + i].load(Ordering::Relaxed);
        }
        if contains(block, &needle) {
            HITS.fetch_add(1, Ordering::AcqRel);
            if want_backtrace() {
                let bt = std::backtrace::Backtrace::force_capture();
                BACKTRACES
                    .lock()
                    .unwrap()
                    .push(format!("needle {n} in a {len}-byte block:\n{bt}"));
            }
            needle.fill(0);
            break;
        }
        needle.fill(0);
    }
    IN_SCAN.with(|f| f.set(false));
}

fn contains(hay: &[u8], needle: &[u8; NEEDLE_LEN]) -> bool {
    let mut start = 0;
    while let Some(i) = memchr::memchr(needle[0], &hay[start..]) {
        let at = start + i;
        if hay.len() - at < NEEDLE_LEN {
            return false;
        }
        if &hay[at..at + NEEDLE_LEN] == needle {
            return true;
        }
        start = at + 1;
    }
    false
}

/// Wipes a block after it has been scanned (see the module docs for why).
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes.
unsafe fn wipe(ptr: *mut u8, len: usize) {
    unsafe {
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0);
        }
    }
}

unsafe impl GlobalAlloc for Recording {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            scan(ptr, layout.size());
            wipe(ptr, layout.size());
            System.dealloc(ptr, layout)
        }
    }

    /// Always moves, so the abandoned old block is scanned: an allocator may or may not move a
    /// growing block, and when it does the old copy is left behind unwiped.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new = System.alloc(new_layout);
            if !new.is_null() {
                std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                scan(ptr, layout.size());
                wipe(ptr, layout.size());
                System.dealloc(ptr, layout);
            }
            new
        }
    }
}

#[global_allocator]
static GLOBAL: Recording = Recording;

/// Serializes the tests: the needles and counters are global.
static LOCK: Mutex<()> = Mutex::new(());

/// Sets the needles: one 16-byte window from the middle of each secret.
fn set_needles(secrets: &[&[u8]]) {
    assert!(secrets.len() <= MAX_NEEDLES);
    for (n, s) in secrets.iter().enumerate() {
        assert!(s.len() >= NEEDLE_LEN, "secret {n} is too short for a needle");
        let off = (s.len() - NEEDLE_LEN) / 2;
        for i in 0..NEEDLE_LEN {
            NEEDLES[n * NEEDLE_LEN + i].store(s[off + i], Ordering::Relaxed);
        }
    }
    NEEDLE_COUNT.store(secrets.len(), Ordering::Release);
}

fn clear_needles() {
    for b in &NEEDLES {
        b.store(0, Ordering::Relaxed);
    }
    NEEDLE_COUNT.store(0, Ordering::Release);
}

/// Runs `op` armed, and returns how many freed blocks held a needle.
fn residue(op: impl FnOnce()) -> usize {
    BACKTRACES.lock().unwrap().clear();
    HITS.store(0, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    op();
    ARMED.store(false, Ordering::Release);
    let hits = HITS.load(Ordering::Acquire);
    for bt in BACKTRACES.lock().unwrap().drain(..) {
        eprintln!("{bt}");
    }
    hits
}

// ---------------------------------------------------------------------------------------------
// Keys under test

/// A passphrase long enough to make a unique needle.
const PASSPHRASE: &str = "residue-canary-passphrase-0123456789";

/// The session key of every message the tests encrypt (AES-256).
const SESSION_KEY: [u8; 32] = *b"residue-canary-session-key-01234";

/// Wipes on drop, so the test's own copies of the secrets are no residue.
struct Secrets(Vec<zeroize::Zeroizing<Vec<u8>>>);

/// The raw secret material of every key in `key`, read while unarmed.
fn secrets_of(key: &SignedSecretKey, pw: &Password) -> Secrets {
    let mut out = Vec::new();
    let mut take = |plain: &PlainSecretParams| {
        out.push(zeroize::Zeroizing::new(raw_secret(plain)));
        Ok(())
    };
    key.primary_key.unlock(pw, |_, p| take(p)).unwrap().unwrap();
    for sub in &key.secret_subkeys {
        sub.key.unlock(pw, |_, p| take(p)).unwrap().unwrap();
    }
    Secrets(out)
}

fn raw_secret(plain: &PlainSecretParams) -> Vec<u8> {
    use pgp::crypto::{ecdh, eddsa_legacy};
    match plain {
        PlainSecretParams::RSA(k) => k.to_bytes().1,
        PlainSecretParams::Ed25519(k) => k.as_bytes().to_vec(),
        PlainSecretParams::EdDSALegacy(eddsa_legacy::SecretKey::Ed25519(k)) => {
            k.as_bytes().to_vec()
        }
        PlainSecretParams::ECDH(ecdh::SecretKey::Curve25519Legacy(k)) => k.as_bytes().to_vec(),
        PlainSecretParams::ECDH(k) => k.to_bytes(),
        PlainSecretParams::X25519(k) => k.as_bytes().to_vec(),
        #[cfg(feature = "pqc")]
        PlainSecretParams::MlDsa65Ed25519(k) => {
            let (ed, ml) = k.as_bytes();
            [&ed[..], &ml[..]].concat()
        }
        #[cfg(feature = "pqc")]
        PlainSecretParams::MlKem768X25519(k) => {
            let (x, d, z) = k.as_bytes();
            [&x[..], &d[..], &z[..]].concat()
        }
        other => panic!("no needle extraction for {other:?}"),
    }
}

fn gen_key(version: KeyVersion, primary: KeyType, sub: KeyType) -> SignedSecretKey {
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    SecretKeyParamsBuilder::default()
        .version(version)
        .key_type(primary)
        .can_sign(true)
        .primary_user_id("residue <residue@example.com>".into())
        .passphrase(None)
        .subkey(
            SubkeyParamsBuilder::default()
                .version(version)
                .key_type(sub)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
        .generate(&mut rng)
        .unwrap()
}

/// How the serialized key is protected.
#[derive(Clone, Copy, Debug)]
enum Protection {
    None,
    /// Iterated and salted S2K, CFB (v4 style).
    Cfb,
    /// Argon2 S2K, AEAD (v6 style), with a small memory size to keep the test fast.
    Argon2Aead,
}

fn protect(key: &mut SignedSecretKey, how: Protection) {
    let rng = &mut ChaCha8Rng::seed_from_u64(9);
    let pw = Password::from(PASSPHRASE);
    let s2k = |rng: &mut ChaCha8Rng| match how {
        Protection::None => unreachable!(),
        Protection::Cfb => {
            let mut iv = vec![0u8; 16];
            rand::Rng::fill(rng, &mut iv[..]);
            S2kParams::Cfb {
                sym_alg: SymmetricKeyAlgorithm::AES256,
                s2k: StringToKey::new_iterated(&mut *rng, HashAlgorithm::Sha256, 96),
                iv: iv.into(),
            }
        }
        Protection::Argon2Aead => {
            let mut nonce = vec![0u8; 15];
            rand::Rng::fill(rng, &mut nonce[..]);
            S2kParams::Aead {
                sym_alg: SymmetricKeyAlgorithm::AES256,
                aead_mode: pgp::crypto::aead::AeadAlgorithm::Ocb,
                s2k: StringToKey::Argon2 {
                    salt: [3; 16],
                    t: 1,
                    p: 1,
                    m_enc: 3,
                },
                nonce: nonce.into(),
            }
        }
    };
    if matches!(how, Protection::None) {
        return;
    }
    let p = s2k(rng);
    key.primary_key
        .set_password_with_s2k(&pw, p)
        .expect("protect primary");
    for sub in &mut key.secret_subkeys {
        let p = s2k(rng);
        sub.key.set_password_with_s2k(&pw, p).expect("protect subkey");
    }
}

fn password(how: Protection) -> Password {
    match how {
        Protection::None => Password::empty(),
        _ => Password::from(PASSPHRASE),
    }
}

struct Case {
    key: SignedSecretKey,
    /// The serialized secret key, owned by the test.
    bytes: zeroize::Zeroizing<Vec<u8>>,
    how: Protection,
}

fn case(version: KeyVersion, primary: KeyType, sub: KeyType, how: Protection) -> Case {
    let mut key = gen_key(version, primary, sub);
    protect(&mut key, how);
    let bytes = zeroize::Zeroizing::new(key.to_bytes().unwrap());
    Case { key, bytes, how }
}

/// Arms the needles for `case`: its secrets, and the passphrase if it has one.
///
/// Not the session key: in a whole-message decryption the message reader's state can hold a
/// stale copy of it, and that has the same sensitivity as the message's plaintext, which the
/// reader's buffers and the caller hold too. The session key paths are tested on their own in
/// [`pkesk`] and [`skesk`].
fn arm_needles(case: &Case) -> Secrets {
    let secrets = secrets_of(&case.key, &password(case.how));
    let mut all: Vec<&[u8]> = secrets.0.iter().map(|s| &s[..]).collect();
    if !matches!(case.how, Protection::None) {
        all.push(PASSPHRASE.as_bytes());
    }
    set_needles(&all);
    secrets
}

// ---------------------------------------------------------------------------------------------
// Operations

const MESSAGE: &[u8] = b"residue test message\n";

/// Parses the serialized key and drops it.
fn op_parse(case: &Case) {
    let key = SignedSecretKey::from_bytes(&case.bytes[..]).unwrap();
    drop(key);
}

/// Parses the key, signs with the primary key, and drops everything.
fn op_sign(case: &Case) {
    let key = SignedSecretKey::from_bytes(&case.bytes[..]).unwrap();
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let sig = DetachedSignature::sign_binary_data(
        &mut rng,
        &*key,
        &password(case.how),
        HashAlgorithm::Sha256,
        MESSAGE,
    )
    .unwrap();
    drop(sig);
    drop(key);
}

/// Encrypts to the subkey (unarmed), then parses the key and decrypts (armed).
fn op_decrypt(case: &Case) -> impl FnOnce() + '_ {
    let mut rng = ChaCha8Rng::seed_from_u64(2);
    let pub_key = case.key.to_public_key();
    let mut builder =
        MessageBuilder::from_bytes("", MESSAGE).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.set_session_key(SESSION_KEY[..].into()).unwrap();
    builder
        .encrypt_to_key(&mut rng, &pub_key.public_subkeys[0])
        .unwrap();
    let encrypted = builder.to_vec(&mut rng).unwrap();
    move || {
        let key = SignedSecretKey::from_bytes(&case.bytes[..]).unwrap();
        let (msg, _) = pgp::composed::Message::from_bytes(&encrypted[..])
            .map(|m| (m, ()))
            .unwrap();
        let mut msg = msg.decrypt(&password(case.how), &key).unwrap();
        assert_eq!(msg.as_data_vec().unwrap(), MESSAGE);
        drop(msg);
        drop(key);
    }
}

/// Parses an unprotected key and protects it with the passphrase.
fn op_protect(case: &Case, how: Protection) {
    let mut key = SignedSecretKey::from_bytes(&case.bytes[..]).unwrap();
    protect(&mut key, how);
    let out = zeroize::Zeroizing::new(key.to_bytes().unwrap());
    drop(out);
    drop(key);
}

/// Runs one operation armed and records how many freed blocks held a needle.
fn run(results: &mut Vec<(String, usize)>, case: &Case, name: String, op: impl FnOnce()) {
    let _secrets = arm_needles(case);
    let hits = residue(op);
    clear_needles();
    eprintln!("{name}: {hits}");
    results.push((name, hits));
}

fn assert_clean(results: &[(String, usize)]) {
    let leaks: Vec<_> = results.iter().filter(|(_, h)| *h > 0).collect();
    assert!(
        leaks.is_empty(),
        "freed blocks held secret material: {leaks:?}"
    );
}

fn all_ops(version: KeyVersion, primary: KeyType, sub: KeyType) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut results = Vec::new();
    for how in [Protection::None, Protection::Cfb, Protection::Argon2Aead] {
        let case = case(version, primary.clone(), sub.clone(), how);
        run(&mut results, &case, format!("{primary:?} {how:?} parse"), || {
            op_parse(&case)
        });
        run(&mut results, &case, format!("{primary:?} {how:?} sign"), || {
            op_sign(&case)
        });
        let decrypt = op_decrypt(&case);
        run(&mut results, &case, format!("{sub:?} {how:?} decrypt"), decrypt);
    }
    let plain = case(version, primary.clone(), sub.clone(), Protection::None);
    for how in [Protection::Cfb, Protection::Argon2Aead] {
        run(&mut results, &plain, format!("{primary:?} protect {how:?}"), || {
            op_protect(&plain, how)
        });
    }
    assert_clean(&results);
}

// ---------------------------------------------------------------------------------------------
// The algorithms EFV uses

#[test]
fn rsa() {
    all_ops(KeyVersion::V4, KeyType::Rsa(2048), KeyType::Rsa(2048));
}

#[test]
fn ed25519_legacy_ecdh() {
    all_ops(
        KeyVersion::V4,
        KeyType::Ed25519Legacy,
        KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy),
    );
}

#[test]
fn ed25519_x25519() {
    all_ops(KeyVersion::V6, KeyType::Ed25519, KeyType::X25519);
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa65_ml_kem768() {
    all_ops(
        KeyVersion::V6,
        KeyType::MlDsa65Ed25519,
        KeyType::MlKem768X25519,
    );
}

/// Decrypting a PKESK with the key's encryption subkey leaves neither the key's secrets nor the
/// session key behind, for each EFV key type, unprotected and CFB-protected.
#[test]
fn pkesk() {
    use pgp::{
        composed::RawSessionKey, packet::PublicKeyEncryptedSessionKey, types::DecryptionKey,
        types::EskType,
    };

    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut results = Vec::new();
    let types: Vec<(KeyVersion, KeyType, KeyType)> = vec![
        (
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy),
        ),
        (KeyVersion::V6, KeyType::Ed25519, KeyType::X25519),
        (KeyVersion::V4, KeyType::Rsa(2048), KeyType::Rsa(2048)),
        #[cfg(feature = "pqc")]
        (
            KeyVersion::V6,
            KeyType::MlDsa65Ed25519,
            KeyType::MlKem768X25519,
        ),
    ];
    for (version, primary, sub) in types {
        for how in [Protection::None, Protection::Cfb] {
            let case = case(version, primary.clone(), sub.clone(), how);
            let public = case.key.to_public_key();
            let enc = &public.public_subkeys[0];
            let make = || {
                let mut rng = ChaCha8Rng::seed_from_u64(8);
                let sk = RawSessionKey::from(&SESSION_KEY[..]);
                if version == KeyVersion::V6 {
                    let p = PublicKeyEncryptedSessionKey::from_session_key_v6(&mut rng, &sk, enc);
                    (p.unwrap(), EskType::V6)
                } else {
                    let p = PublicKeyEncryptedSessionKey::from_session_key_v3(
                        &mut rng,
                        &sk,
                        SymmetricKeyAlgorithm::AES256,
                        enc,
                    );
                    (p.unwrap(), EskType::V3_4)
                }
            };

            // Encrypting to the recipient: only the session key is secret here.
            set_needles(&[&SESSION_KEY]);
            let hits = residue(|| drop(make()));
            clear_needles();
            let name = format!("{sub:?} {how:?} PKESK encrypt");
            eprintln!("{name}: {hits}");
            results.push((name, hits));

            let (pkesk, typ) = make();

            let secrets = secrets_of(&case.key, &password(case.how));
            let mut needles: Vec<&[u8]> = secrets.0.iter().map(|s| &s[..]).collect();
            // Not for RSA: rsa 0.9's PKCS#1 v1.5 decryption frees its padded block, which holds
            // the session key, unwiped (upstream; EFV refuses RSA secret keys). The RSA key's
            // own secrets are still checked.
            if !matches!(sub, KeyType::Rsa(_)) {
                needles.push(&SESSION_KEY);
            }
            set_needles(&needles);
            let hits = residue(|| {
                let key = SignedSecretKey::from_bytes(&case.bytes[..]).unwrap();
                let plain = key.secret_subkeys[0]
                    .key
                    .decrypt(&password(case.how), pkesk.values().unwrap(), typ)
                    .unwrap()
                    .unwrap();
                drop(plain);
                drop(key);
            });
            clear_needles();
            let name = format!("{sub:?} {how:?} PKESK decrypt");
            eprintln!("{name}: {hits}");
            results.push((name, hits));
        }
    }
    assert_clean(&results);
}

/// Password-encrypted session keys (SKESK v4 and v6): making one and decrypting one leave
/// neither the passphrase nor the session key behind. Whole password-encrypted messages
/// (SEIPD v1 and v2) leave no passphrase behind.
#[test]
fn skesk() {
    use pgp::{
        composed::{decrypt_session_key_with_password, Message, RawSessionKey},
        crypto::aead::{AeadAlgorithm, ChunkSize},
        packet::SymKeyEncryptedSessionKey,
    };

    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut results = Vec::new();
    let pw = || Password::from(PASSPHRASE);
    let s2k_iterated =
        || StringToKey::new_iterated(ChaCha8Rng::seed_from_u64(4), HashAlgorithm::Sha256, 96);
    let s2k_argon2 = || StringToKey::Argon2 {
        salt: [5; 16],
        t: 1,
        p: 1,
        m_enc: 3,
    };
    let mut record = |name: &str, needles: &[&[u8]], op: &dyn Fn()| {
        set_needles(needles);
        let hits = residue(op);
        clear_needles();
        eprintln!("{name}: {hits}");
        results.push((name.to_string(), hits));
    };
    let both: [&[u8]; 2] = [PASSPHRASE.as_bytes(), &SESSION_KEY];

    let make_v4 = || {
        let sk = RawSessionKey::from(&SESSION_KEY[..]);
        SymKeyEncryptedSessionKey::encrypt_v4(&pw(), &sk, s2k_iterated(), SymmetricKeyAlgorithm::AES256)
            .unwrap()
    };
    let make_v6 = || {
        let sk = RawSessionKey::from(&SESSION_KEY[..]);
        SymKeyEncryptedSessionKey::encrypt_v6(
            ChaCha8Rng::seed_from_u64(6),
            &pw(),
            &sk,
            s2k_argon2(),
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
        )
        .unwrap()
    };
    record("SKESK v4 make", &both, &|| drop(make_v4()));
    record("SKESK v6 make", &both, &|| drop(make_v6()));
    let (v4, v6) = (make_v4(), make_v6());
    record("SKESK v4 decrypt", &both, &|| {
        drop(decrypt_session_key_with_password(&v4, &pw()).unwrap())
    });
    record("SKESK v6 decrypt", &both, &|| {
        drop(decrypt_session_key_with_password(&v6, &pw()).unwrap())
    });

    let encrypt_v1 = || {
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let mut builder = MessageBuilder::from_bytes("", MESSAGE)
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.encrypt_with_password(s2k_iterated(), &pw()).unwrap();
        builder.to_vec(&mut rng).unwrap()
    };
    let encrypt_v2 = || {
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        let mut builder = MessageBuilder::from_bytes("", MESSAGE).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder
            .encrypt_with_password(&mut rng, s2k_argon2(), &pw())
            .unwrap();
        builder.to_vec(&mut rng).unwrap()
    };
    let decrypt = |encrypted: &[u8]| {
        let msg = Message::from_bytes(encrypted).unwrap();
        let mut msg = msg.decrypt_with_password(&pw()).unwrap();
        assert_eq!(msg.as_data_vec().unwrap(), MESSAGE);
    };
    let pass: [&[u8]; 1] = [PASSPHRASE.as_bytes()];
    record("SEIPD v1 password encrypt", &pass, &|| drop(encrypt_v1()));
    record("SEIPD v2 password encrypt", &pass, &|| drop(encrypt_v2()));
    let (m1, m2) = (encrypt_v1(), encrypt_v2());
    record("SEIPD v1 password decrypt", &pass, &|| decrypt(&m1));
    record("SEIPD v2 password decrypt", &pass, &|| decrypt(&m2));
    assert_clean(&results);
}

/// The `crypto` secret key types that claim `ZeroizeOnDrop` really wipe: each is boxed (so it
/// is freed whole, through the scanning allocator) and dropped armed.
#[cfg(feature = "pqc")]
#[test]
fn crypto_keys_wipe_on_drop() {
    use pgp::crypto::{
        ml_kem1024_x448, slh_dsa_shake128f, slh_dsa_shake128s, slh_dsa_shake256s,
    };

    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut results = Vec::new();
    let mut check = |name: &str, secret: &[u8], key: Box<dyn std::any::Any>| {
        set_needles(&[secret]);
        let hits = residue(|| drop(key));
        clear_needles();
        eprintln!("{name}: {hits}");
        results.push((name.to_string(), hits));
    };
    let rng = || ChaCha8Rng::seed_from_u64(11);

    // SLH-DSA: the secret half is SK.seed || SK.prf, the first half of the serialized key.
    let k = slh_dsa_shake128s::SecretKey::generate(rng());
    let b = zeroize::Zeroizing::new(k.to_bytes());
    check("SLH-DSA-SHAKE-128s", &b[..32], Box::new(k));
    let k = slh_dsa_shake128f::SecretKey::generate(rng());
    let b = zeroize::Zeroizing::new(k.to_bytes());
    check("SLH-DSA-SHAKE-128f", &b[..32], Box::new(k));
    let k = slh_dsa_shake256s::SecretKey::generate(rng());
    let b = zeroize::Zeroizing::new(k.to_bytes());
    check("SLH-DSA-SHAKE-256s", &b[..64], Box::new(k));

    // ML-KEM-1024+X448: the X448 half.
    let k = ml_kem1024_x448::SecretKey::generate(rng());
    let x = zeroize::Zeroizing::new(*k.as_bytes().0);
    check("ML-KEM-1024+X448 (X448 half)", &x[..], Box::new(k));

    assert_clean(&results);
}

/// The harness itself: a secret left in a freed buffer must be found.
#[test]
fn harness_finds_residue() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let secret = b"0123456789abcdef-harness-canary".to_vec();
    set_needles(&[&secret]);
    let leaked = secret.clone();
    let hits = residue(|| drop(leaked));
    let mut wiped = secret.clone();
    let hits_wiped = residue(|| {
        zeroize::Zeroize::zeroize(&mut wiped);
        drop(wiped)
    });
    clear_needles();
    zeroize::Zeroize::zeroize(&mut { secret });
    assert_eq!(hits, 1, "an unwiped copy must be found");
    assert_eq!(hits_wiped, 0, "a wiped copy must not be found");
}

