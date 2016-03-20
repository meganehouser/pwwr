use rand::{Rng, OsRng};
use std::io::{Read, Write};
use crypto::{aes, blockmodes, symmetriccipher};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer, RefReadBuffer, RefWriteBuffer};
use crypto::hmac::Hmac;
use crypto::pbkdf2;
use crypto::sha1::Sha1;
use crypto::md5::Md5;
use crypto::digest::Digest;

use input::Input;

pub struct KeyProvider<'a, T: 'a + Input, U: Read + Write> {
    input: &'a T,
    name_holder: U,
}

impl<'a, T, U> KeyProvider<'a, T, U>
    where T: Input,
          U: Read + Write
{
    pub fn new(input: &'a T, name_holder: U) -> KeyProvider<'a, T, U> {
        KeyProvider {
            name_holder: name_holder,
            input: input,
        }
    }

    pub fn get(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut user_name = Vec::new();
        let _ = self.name_holder.read_to_end(&mut user_name);
        if user_name.len() == 0 {
            user_name = self.input.required("user name");
            let _ = self.name_holder.write_all(&user_name.as_ref());
        }

        let mut salt: [u8; 8] = [0; 8];
        self.make_salt(user_name.as_ref(), &mut salt);

        let password = self.input.get_password();
        (password, Vec::from(&salt as &[u8]))
    }

    fn make_salt(&self, source: &[u8], dest: &mut [u8; 8]) {
        let mut md5 = Md5::new();
        md5.input(source);
        let salt = &md5.result_str()[..8];
        dest.clone_from_slice(salt.as_bytes());
    }
}

pub struct Cipher {
    key: Vec<u8>,
}

impl Cipher {
    pub fn new(password: &[u8], salt: &[u8]) -> Cipher {
        let key = Self::gen_key(password, salt);
        Cipher { key: key }
    }

    fn gen_key(password: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::new(Sha1::new(), password);
        let mut key: [u8; 128] = [0; 128];
        pbkdf2::pbkdf2(&mut mac, &salt, 1000, &mut key);
        Vec::<u8>::from(key.as_ref())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

        let mut rng = OsRng::new().ok().unwrap();
        let mut iv: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut iv);

        let mut enc = aes::cbc_encryptor(aes::KeySize::KeySize128,
                                         &self.key,
                                         &mut iv,
                                         blockmodes::PkcsPadding);

        let mut read_buffer = RefReadBuffer::new(data);
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);
        let mut encrypted = Vec::<u8>::new();

        loop {
            let result = try!(enc.encrypt(&mut read_buffer, &mut write_buffer, true));
            encrypted.extend(write_buffer.take_read_buffer()
                                         .take_remaining()
                                         .iter()
                                         .map(|&i| i));

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }

        }

        let mut final_result = Vec::from(&iv as &[u8]);
        final_result.extend(encrypted);
        Ok(final_result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        let iv: &[u8] = &data[0..16];
        let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize128,
                                               &self.key,
                                               &iv,
                                               blockmodes::PkcsPadding);

        let mut decrypted = Vec::<u8>::new();
        let mut read_buffer = RefReadBuffer::new(&data[16..]);
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        loop {
            let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
            decrypted.extend(write_buffer.take_read_buffer()
                                         .take_remaining()
                                         .iter()
                                         .map(|&i| i));

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        Ok(decrypted)
    }
}


#[cfg(test)]
mod test {
    #[test]
    fn keyprovider_test() {
        let input = Dummy;
        let holder = Cursor::new(vec![0; 16]);
        let mut kp = KeyProvider::new(&input, holder);
        let (password, salt) = kp.get();
        println!("{:?} - {:?}", password, salt);
    }

    #[test]
    fn cipher_test() {
        let password = "pasword123";
        let salt = "salttlas";
        let cipher = Cipher::new(password.as_bytes(), salt.as_bytes());

        let data = String::from("hello world");
        let encrypted = cipher.encrypt(data.as_bytes());
        let decrypted = cipher.decrypt(encrypted.unwrap().as_slice());
        assert_eq!(decrypted.unwrap().as_slice(), data.as_bytes());
    }
}
