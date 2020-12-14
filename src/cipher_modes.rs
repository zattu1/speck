/// A trait for the Electronic Codebook (ECB) ciphermode.
/// WARNING: ECB is generally unsafe to use because it lacks diffusion.
/// See: https://blog.filippo.io/the-ecb-penguin/ for details.
///
/// TODO: Implement other ciphermodes

pub trait ECB {
    fn encrypt(&self, plaintext: &Vec<u8>) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &Vec<u8>) -> Vec<u8>;
}
