use std::io::{stdin, stdout};
use std::io::Write;
use rand::{OsRng, Rng};
use crypto::{aes, blockmodes};
use crypto::hmac::Hmac;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::pbkdf2;
use crypto::sha1::Sha1;
use crypto::md5::Md5;
use crypto::digest::Digest;
use rpassword::read_password;
use rawio::RawStore;
use entrystore::{Cipher, CliEntrySelector};
use errors::*;

pub trait KeyInput {
    fn required(&self, name: &str) -> Result<Vec<u8>>;
    fn get_password(&self) -> Result<Vec<u8>>;
}

pub struct KeyProvider<'a, T: 'a + KeyInput, RW: 'a + RawStore> {
    input: &'a T,
    name_holder: &'a mut RW,
}

impl<'a, T, RW> KeyProvider<'a, T, RW>
where
    T: KeyInput,
    RW: RawStore,
{
    pub fn new(input: &'a T, name_holder: &'a mut RW) -> KeyProvider<'a, T, RW> {
        KeyProvider {
            name_holder: name_holder,
            input: input,
        }
    }

    /// get password and salt
    pub fn get(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut user_name = Vec::new();
        let _ = self.name_holder.read_to_end(&mut user_name);
        if user_name.len() == 0 {
            user_name = self.input.required("user name")?;
            let _ = self.name_holder.write_all(&user_name.as_ref());
        }

        let mut salt: [u8; 8] = [0; 8];
        self.make_salt(user_name.as_ref(), &mut salt);

        let password = self.input.get_password()?;
        Ok((password, Vec::from(&salt as &[u8])))
    }

    fn make_salt(&self, source: &[u8], dest: &mut [u8; 8]) {
        let mut md5 = Md5::new();
        md5.input(source);
        let salt = &md5.result_str()[..8];
        dest.clone_from_slice(salt.as_bytes());
    }
}

pub struct AesCipher {
    key: Vec<u8>,
}

impl AesCipher {
    pub fn new(password: &[u8], salt: &[u8]) -> AesCipher {
        let key = Self::gen_key(password, salt);
        AesCipher { key: key }
    }

    fn gen_key(password: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::new(Sha1::new(), password);
        let mut key: [u8; 128] = [0; 128];
        pbkdf2::pbkdf2(&mut mac, &salt, 1000, &mut key);
        Vec::<u8>::from(key.as_ref())
    }
}

impl Cipher for AesCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut rng = OsRng::new().ok().unwrap();
        let mut iv: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut iv);

        let mut enc = aes::cbc_encryptor(
            aes::KeySize::KeySize128,
            &self.key,
            &mut iv,
            blockmodes::PkcsPadding,
        );

        let mut read_buffer = RefReadBuffer::new(data);
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);
        let mut encrypted = Vec::<u8>::new();

        loop {
            let result = match enc.encrypt(&mut read_buffer, &mut write_buffer, true) {
                Ok(bresult) => bresult,
                Err(_) => bail!("failed to encrypt"),
            };

            encrypted.extend(
                write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .iter()
                    .map(|&i| i),
            );

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        let mut final_result = Vec::from(&iv as &[u8]);
        final_result.extend(encrypted);
        Ok(final_result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let iv: &[u8] = &data[0..16];
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize128,
            &self.key,
            &iv,
            blockmodes::PkcsPadding,
        );

        let mut decrypted = Vec::<u8>::new();
        let mut read_buffer = RefReadBuffer::new(&data[16..]);
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        loop {
            let result = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
                Ok(bresult) => bresult,
                Err(_) => bail!("failed to decrypt"),
            };
            decrypted.extend(
                write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .iter()
                    .map(|&i| i),
            );

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        Ok(decrypted)
    }
}

impl KeyInput for CliEntrySelector {
    fn required(&self, name: &str) -> Result<Vec<u8>> {
        let mut sout = stdout();
        let sin = stdin();
        let mut value = String::new();

        while value.len() <= 1 {
            value.clear();
            sout.write_all([name, ": "].concat().as_bytes())
                .chain_err(|| "can't write to stdout")?;
            sout.flush().chain_err(|| "flush fail")?;
            sin.read_line(&mut value)
                .chain_err(|| "can't read line from stdin")?;
        }

        Ok(Vec::from(value.as_str().trim_right().as_bytes()))
    }

    fn get_password(&self) -> Result<Vec<u8>> {
        let mut sout = stdout();
        let mut password = String::new();

        while password.len() == 0 {
            sout.write_all("password: ".as_bytes())
                .chain_err(|| "print exception")?;
            sout.flush().chain_err(|| "print flush exception")?;

            password = read_password().chain_err(|| "failed to reading a password")?;
        }

        Ok(Vec::from(password.as_bytes()))
    }
}


#[cfg(test)]
mod test {
    use std;
    use pwdcrypto::*;
    use rawio::*;
    use errors::*;

    struct DummyKeyInput {
        key: String,
        password: String,
    }

    impl KeyInput for DummyKeyInput {
        fn required(&self, name: &str) -> Result<Vec<u8>> {
            Ok(Vec::from(self.key.as_str()))
        }

        fn get_password(&self) -> Result<Vec<u8>> {
            Ok(Vec::from(self.password.as_str()))
        }
    }

    struct DummyRS {
        buf: Vec<u8>,
    }

    impl RawStore for DummyRS {
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
            buf.extend_from_slice(self.buf.as_slice());
            Ok(self.buf.len())
        }
        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            self.buf.extend_from_slice(buf);
            Ok(())
        }
    }


    #[test]
    fn keyprovider_test() {
        let mut input = DummyKeyInput {
            key: String::from("testuser"),
            password: String::from("password"),
        };
        let mut rw = DummyRS {
            buf: Vec::from("sample"),
        };

        let mut kp = KeyProvider::new(&mut input, &mut rw);
        let (password, salt) = kp.get().unwrap();

        assert_eq!(
            "password",
            std::str::from_utf8(password.as_slice()).unwrap()
        );
        assert_eq!("5e8ff9bf", std::str::from_utf8(salt.as_slice()).unwrap());
    }

    #[test]
    fn aes_cipher_test() {
        let password = "pasword123";
        let salt = "salttlas";
        let cipher = AesCipher::new(password.as_bytes(), salt.as_bytes());

        let data = String::from("hello world, hello world, hello world, hello world, hello world, hello world}}{{");
        let encrypted = cipher.encrypt(data.as_bytes());
        let decrypted = cipher.decrypt(encrypted.unwrap().as_slice());
        assert_eq!(decrypted.unwrap().as_slice(), data.as_bytes());
    }
}
