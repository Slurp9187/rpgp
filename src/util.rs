//! # Utilities

use std::{hash, io};

use bytes::{Buf, BufMut, BytesMut};
use digest::DynDigest;
use nom::Input;

/// This function will fill `buffer` to its full capacity, until the underlying reader is depleted.
///
/// If this function returns fewer bytes than `buffer.len()` the underlying reader is finished.
pub(crate) fn fill_buffer<R: std::io::Read>(
    mut source: R,
    buffer: &mut [u8],
    chunk_size: Option<usize>,
) -> std::io::Result<usize> {
    let mut offset = 0;
    let chunk_size = chunk_size.unwrap_or(buffer.len());
    loop {
        let read = source.read(&mut buffer[offset..chunk_size])?;
        offset += read;

        if read == 0 || offset == chunk_size {
            break;
        }
    }
    Ok(offset)
}

pub(crate) fn fill_buffer_bytes<R: std::io::BufRead>(
    mut source: R,
    buffer: &mut BytesMut,
    len: usize,
) -> std::io::Result<usize> {
    let mut read_total = 0;
    while buffer.remaining() < len {
        let source_buffer = source.fill_buf()?;
        let read = source_buffer.len().min(len - buffer.remaining());
        buffer.put_slice(&source_buffer[..read]);
        read_total += read;
        source.consume(read);

        if read == 0 {
            break;
        }
    }
    Ok(read_total)
}

/// How much stack [`burn_stack`] overwrites.
const BURN_STACK_SIZE: usize = 64 * 1024;

/// Overwrites the stack below the caller with zeros.
///
/// Secret material passes through stack frames that nothing can wipe: digest and cipher state,
/// arguments passed by value, moved-from locals. Once those frames return their bytes stay on
/// the stack, and a large value built later in the same place carries them into the heap in
/// its unused space. Called after an operation on secret material returns, this overwrites
/// the region its callees used.
#[inline(never)]
pub(crate) fn burn_stack() {
    let mut buf = [0u8; BURN_STACK_SIZE];
    zeroize::Zeroize::zeroize(&mut buf[..]);
    std::hint::black_box(&buf);
}

/// A fixed-size read buffer that never reallocates and wipes its whole allocation on drop.
///
/// Packet bodies pass through it, and a secret key packet's body is secret key material. A
/// `BytesMut` can't be wiped reliably: once advanced, the consumed bytes are out of reach, and
/// growing it can leave a copy behind.
pub(crate) struct WipingBuffer {
    data: Box<[u8]>,
    start: usize,
    end: usize,
}

impl WipingBuffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    /// The buffered bytes not yet consumed.
    pub(crate) fn remaining(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    pub(crate) fn has_remaining(&self) -> bool {
        self.start < self.end
    }

    pub(crate) fn advance(&mut self, amt: usize) {
        assert!(amt <= self.end - self.start, "advance past the end");
        self.start += amt;
    }

    /// Copies up to `buf.len()` buffered bytes into `buf` and consumes them.
    pub(crate) fn copy_to(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.end - self.start);
        buf[..n].copy_from_slice(&self.data[self.start..self.start + n]);
        self.start += n;
        n
    }

    /// Moves the unconsumed bytes to the front, then fills the rest from `source`.
    /// Returns how many bytes were read.
    pub(crate) fn fill<R: std::io::BufRead>(&mut self, mut source: R) -> std::io::Result<usize> {
        if self.start > 0 {
            self.data.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let mut read_total = 0;
        while self.end < self.data.len() {
            let source_buffer = source.fill_buf()?;
            let read = source_buffer.len().min(self.data.len() - self.end);
            if read == 0 {
                break;
            }
            self.data[self.end..self.end + read].copy_from_slice(&source_buffer[..read]);
            self.end += read;
            read_total += read;
            source.consume(read);
        }
        Ok(read_total)
    }
}

impl Drop for WipingBuffer {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.data[..]);
    }
}

impl std::fmt::Debug for WipingBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WipingBuffer")
            .field("remaining", &(self.end - self.start))
            .finish_non_exhaustive()
    }
}

macro_rules! impl_try_from_into {
    ($enum_name:ident, $( $name:ident => $variant_type:ty ),*) => {
       $(
           impl std::convert::TryFrom<$enum_name> for $variant_type {
               // TODO: Proper error
               type Error = $crate::errors::Error;

               fn try_from(other: $enum_name) -> ::std::result::Result<$variant_type, Self::Error> {
                   if let $enum_name::$name(value) = other {
                       Ok(value)
                   } else {
                       Err($crate::errors::format_err!("invalid packet type: {:?}", other))
                   }
               }
           }

           impl From<$variant_type> for $enum_name {
               fn from(other: $variant_type) -> $enum_name {
                   $enum_name::$name(other)
               }
           }
       )*
    }
}

pub(crate) use impl_try_from_into;

pub struct TeeWriter<'a, A, B> {
    a: &'a mut A,
    b: &'a mut B,
}

impl<'a, A, B> TeeWriter<'a, A, B> {
    pub fn new(a: &'a mut A, b: &'a mut B) -> Self {
        TeeWriter { a, b }
    }
}

impl<A: hash::Hasher, B: io::Write> io::Write for TeeWriter<'_, A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.b.write(buf)?;
        self.a.write(&buf[..written]);

        Ok(written)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {}
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.b.flush()?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use bytes::{Buf, Bytes};
    use rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~\r\n .,-!?\t";

    pub(crate) fn random_string(rng: &mut impl Rng, size: usize) -> String {
        (0..size)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    pub(crate) fn random_utf8_string(rng: &mut impl Rng, size: usize) -> String {
        (0..size).map(|_| rng.r#gen::<char>()).collect()
    }

    #[derive(Debug)]
    pub(crate) struct ChaosReader<R: Rng> {
        rng: R,
        source: Bytes,
    }

    impl<R: Rng> ChaosReader<R> {
        pub(crate) fn new(rng: R, source: impl Into<Bytes>) -> Self {
            Self {
                rng,
                source: source.into(),
            }
        }
    }

    impl<R: Rng> std::io::Read for ChaosReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.source.has_remaining() {
                return Ok(0);
            }
            let max = buf.len().min(self.source.remaining());
            let to_write: usize = self.rng.gen_range(1..=max);

            self.source.copy_to_slice(&mut buf[..to_write]);
            Ok(to_write)
        }
    }

    pub(crate) fn check_strings(a: impl AsRef<str>, b: impl AsRef<str>) {
        assert_eq!(
            escape_string::escape(a.as_ref()),
            escape_string::escape(b.as_ref())
        );
    }
}

#[derive(derive_more::Debug)]
pub struct NormalizingHasher {
    #[debug("hasher")]
    hasher: Box<dyn DynDigest + Send>,
    text_mode: bool,
    last_was_cr: bool,
}

impl NormalizingHasher {
    pub(crate) fn new(hasher: Box<dyn DynDigest + Send>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    pub(crate) fn done(mut self) -> Box<dyn DynDigest + Send> {
        if self.text_mode && self.last_was_cr {
            self.hasher.update(b"\n")
        }

        self.hasher
    }

    pub(crate) fn hash_buf(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }

        if !self.text_mode {
            self.hasher.update(buffer);
        } else {
            let mut buf = buffer;

            if self.last_was_cr {
                // detect and handle a LF that follows a CR
                // (it should not be normalized)
                if buf[0] == b'\n' {
                    self.hasher.update(b"\n");
                    buf = &buf[1..];
                }

                self.last_was_cr = false;
            }

            while !buf.is_empty() {
                match buf.position(|c| c == b'\r' || c == b'\n') {
                    None => {
                        // no line endings in sight, just hash the data
                        self.hasher.update(buf);
                        buf = &[]
                    }

                    Some(pos) => {
                        // consume all bytes before line-break-related position

                        self.hasher.update(&buf[..pos]);
                        buf = &buf[pos..];

                        // handle this line-break related context
                        let only_one = buf.len() == 1;
                        match (buf[0], only_one) {
                            (b'\n', _) => {
                                self.hasher.update(b"\r\n");
                                buf = &buf[1..];
                            }
                            (b'\r', false) => {
                                // we are guaranteed to have at least two bytes
                                if buf[1] == b'\n' {
                                    // there was a '\n' in the stream, we consume it as well
                                    self.hasher.update(b"\r\n");
                                    buf = &buf[2..];
                                } else {
                                    // this was a lone '\r', we don't normalize it
                                    self.hasher.update(b"\r");
                                    buf = &buf[1..];
                                }
                            }
                            (b'\r', true) => {
                                // this one '\r' was the last thing in the buffer
                                self.hasher.update(b"\r");
                                buf = &[];

                                // remember that the last character was a CR.
                                // if the next character is a LF, we want to *not* normalize it
                                self.last_was_cr = true;
                            }
                            _ => unreachable!("buf.position gave us either a '\n or a '\r'"),
                        }
                    }
                }
            }
        }
    }
}
