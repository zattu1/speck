#![forbid(unsafe_code)]

pub mod cipher_modes;

use crate::cipher_modes::ECB;

/// This library implements NSA's lightweight block cipher Speck.
/// The formal specification of Speck can be found: https://eprint.iacr.org/2013/404.pdf
///
/// The Speck parameters are found in Table 4.1 in the above paper.

/// Speck parameters (for 128-bit security)
/// ALPHA and BETA are the parameters to the rotations
/// ROUNDS is the number of times to apply the round function
const ALPHA: u32 = 8;
const BETA: u32 = 3;
const ROUNDS: usize = 32;

/// Performs the Speck round function once.
/// (S^{-\alpha}x + y) \oplus k, S^{\beta}y \oplus (S^{-\alpha}x + y) \oplus k
///
/// Notice that (S^{-\alpha}x + y) \oplus k component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 addition, and 2 XORs.
#[inline(always)]
fn round(x: &mut u64, y: &mut u64, k: &u64) {
    *x = x.rotate_right(ALPHA).wrapping_add(*y) ^ k;
    *y = y.rotate_left(BETA) ^ *x;
}

/// Performs the Speck inverse round function once.
/// The inverse round function is necessary for decryption.
/// (S^{\alpha}((x \oplus k) - S^{-\beta}(x \oplus y)), S^{-\beta}(x \oplus y))
///
/// Notice that that S^{-\beta}(x \oplus y) component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 subtraction, and 2 XORs.
#[inline(always)]
fn inv_round(x: &mut u64, y: &mut u64, k: &u64) {
    *y = (*y ^ *x).rotate_right(BETA);
    *x = (*x ^ *k).wrapping_sub(*y).rotate_left(ALPHA);
}

/// Computes the Speck key schedule via the round function.
#[inline(always)]
fn key_schedule(k1: &mut u64, k2: &mut u64) -> [u64; ROUNDS] {
    let mut schedule = [0u64; ROUNDS];
    for i in 0..ROUNDS as u64 {
        schedule[i as usize] = *k2;
        round(k1, k2, &i)
    }
    schedule
}

/// Implements Speck encryption/decryption.
/// This tuple-struct takes a key schedule as input.
///
/// TODO: Build an API around generating the key schedule
pub struct Speck([u64; ROUNDS]);

impl Speck {
    pub fn new(key: &u128) -> Self {
        let mut k1 = (key >> 64) as u64;
        let mut k2 = *key as u64;

        Speck(key_schedule(&mut k1, &mut k2))
    }

    /// Performs a raw encryption using Speck.
    /// This is not exposed via the Speck type because the raw
    /// encryption function is generally unsafe to use.
    ///
    /// TODO: Implement ciphermodes, potentially expose this as ECB.
    pub(crate) fn encrypt(&self, plaintext: &u128) -> u128 {
        // Split the u128 block into u64 chunks
        let mut chunk_1 = (plaintext >> 64) as u64;
        let mut chunk_2 = *plaintext as u64;

        // Perform the Speck round with each of its round keys
        for round_key in &self.0 {
            round(&mut chunk_1, &mut chunk_2, round_key);
        }

        // The chunks are mutated in place, so we just put them back together
        chunk_2 as u128 | (chunk_1 as u128) << 64
    }

    /// Performs a raw decryption using Speck.
    ///
    /// TODO: Implement ciphermodes, potentially expose this as ECB.
    pub(crate) fn decrypt(&self, ciphertext: &u128) -> u128 {
        // Split the u128 block into u64 chunks
        let mut chunk_1 = (ciphertext >> 64) as u64;
        let mut chunk_2 = *ciphertext as u64;

        // Perform the Speck round with each of its round keys
        for round_key in self.0.iter().rev() {
            inv_round(&mut chunk_1, &mut chunk_2, round_key);
        }

        // The chunks are mutated in place, so we just put them back together
        chunk_2 as u128 | (chunk_1 as u128) << 64
    }
}

impl ECB for Speck {
    fn encrypt(&self, plaintext: &Vec<u8>) -> Vec<u8> {
        let length: usize = plaintext.len() / 16 + plaintext.len() % 16;
        let mut ciphertext: Vec<u8> = Vec::with_capacity(length);
        let mut plain: u128 = 0;
        let mut i: u32 = 0;
        let mut j: usize = 0;

        for it in plaintext.iter() {
            plain |= (it << (i * 8)) as u128;
            i += 1;
            if i == 16 {
                i = 0;
                let enc = self.encrypt(&plain);
                for k in 0..16 {
                    ciphertext[j] = ((enc >> k) & 0xFFu128) as u8;
                    j += 1;
                }
                plain = 0;
            }
        }
        if i < 16 {
            let enc = self.encrypt(&plain);
            for k in 0..16 {
                ciphertext[j] = ((enc >> k) & 0xFFu128) as u8;
                j += 1;
            }
        }
        ciphertext
    }
    fn decrypt(&self, ciphertext: &Vec<u8>) -> Vec<u8> {
        let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
        if (ciphertext.len() % 16) == 0 {
            let mut cipher: u128 = 0;
            let mut i: u32 = 0;
            let mut j: usize = 0;

            for it in ciphertext.iter() {
                cipher |= (it << (i * 8)) as u128;
                i += 1;
                if i == 16 {
                    i = 0;
                    let dec = self.decrypt(&cipher);
                    for k in 0..16 {
                        plaintext[j] = ((dec >> k) & 0xFFu128) as u8;
                        j += 1;
                    }
                    cipher = 0;
                }
            }
        }
        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speck128_128_encryption_and_decryption() {
        // Speck128/128 test vectors (see Appendix C in the paper)
        let key: u128 = 0x0f0e0d0c0b0a09080706050403020100;
        let plaintext = vec![ 0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20, 0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20 ];
        let ciphertext = vec![ 0xa6, 0x5d, 0x98, 0x51, 0x79, 0x78, 0x32, 0x65, 0x78, 0x60, 0xfe, 0xdf, 0x5c, 0x57, 0x0d, 0x18 ];

        let speck = Speck::new(&key);
        assert_eq!(<Speck as ECB>::encrypt(&plaintext), ciphertext);
        assert_eq!(<Speck as ECB>::decrypt(&ciphertext), plaintext);
    }
}
