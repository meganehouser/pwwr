use std::collections::HashMap;
use std::fmt;
use std::iter::FromIterator;
use std::io::{stdin, stdout};
use serde_json;
use std::io::Write;
use rawio::RawStore;
use errors::*;

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthInfo {
    pub user: String,
    pub password: String,
    pub other: String,
}

impl AuthInfo {
    pub fn new(user: &str, password: &str, other: &str) -> AuthInfo {
        AuthInfo {
            user: String::from(user),
            password: String::from(password),
            other: String::from(other),
        }
    }

    pub fn blank() -> AuthInfo {
        AuthInfo {
            user: String::new(),
            password: String::new(),
            other: String::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub title: String,
    pub auth_info: AuthInfo,
}

impl Entry {
    pub fn new(title: &str, auth_info: AuthInfo) -> Entry {
        Entry {
            title: String::from(title),
            auth_info: auth_info,
        }
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "title: {}\nuser: {}\npassword: {}\nother: {}\n",
            self.title.as_str(),
            self.auth_info.user.as_str(),
            self.auth_info.password.as_str(),
            self.auth_info.other.as_str()
        )
    }
}

pub struct EntryStore<RW, CP>
where
    RW: RawStore,
    CP: Cipher,
{
    data: HashMap<String, AuthInfo>,
    cipher: CP,
    rw: RW,
}

impl<RW, CP> EntryStore<RW, CP>
where
    RW: RawStore,
    CP: Cipher,
{
    pub fn load(mut rw: RW, cipher: CP) -> Result<EntryStore<RW, CP>> {
        let mut content = Vec::new();
        rw.read_to_end(&mut content)?;
        if content.len() == 0 {
            Ok(EntryStore {
                data: HashMap::new(),
                cipher: cipher,
                rw: rw,
            })
        } else {
            let plain_data = cipher.decrypt(&content)?;
            let plain_str =
                String::from_utf8(plain_data).chain_err(|| "plain data can't convert to utf8")?;
            let data: HashMap<String, AuthInfo> = serde_json::from_str(plain_str.as_str())
                .chain_err(|| "plain str can't convert to json")?;
            Ok(EntryStore {
                data: data,
                cipher: cipher,
                rw: rw,
            })
        }
    }

    pub fn add(&mut self, entry: Entry) -> Result<()> {
        if self.data.keys().any(|k| k.as_str() == entry.title.as_str()) {
            bail!("the entry already been exist")
        } else {
            self.data.insert(entry.title, entry.auth_info);
            Ok(())
        }
    }

    pub fn search(&self, title_pattern: &str) -> Vec<Entry> {
        Vec::from_iter(self.data.iter().filter_map(
            |(k, v)| {
            if k.as_str().starts_with(title_pattern) {
                Some(Entry::new(&k, v.clone()))
            } else {
                None
            }
            }))
    }

    pub fn select_one<T: EntrySelector>(
        &self,
        title_pattern: &str,
        input: &T,
    ) -> Result<Option<Entry>> {
        let mut entries = self.search(title_pattern);
        let len = entries.len();
        if len == 0 {
            return Ok(None);
        } else if len == 1 {
            let entry = entries.into_iter().nth(0).unwrap();
            return Ok(Some(entry));
        }

        let sorted = entries.as_mut_slice();
        sorted.sort_by_key(|a| a.title.clone());
        let entry = input.select_one(Vec::from(sorted.as_ref()))?;
        return Ok(Some(entry));
    }

    pub fn change(&mut self, title: &str, entry: Entry) -> Result<()> {
        if let Some(_) = self.data.get(title) {
            self.data.remove(title);
            self.data.insert(entry.title, entry.auth_info);
            Ok(())
        } else {
            bail!("the entry is not found")
        }
    }

    pub fn save(&mut self) -> Result<()> {
        let j =
            serde_json::to_string(&self.data).chain_err(|| "fail to converting this data to json")?;
        let data = self.cipher.encrypt(j.as_bytes())?;
        self.rw
            .write_all(&data)
            .chain_err(|| "fail to writing json data")?;
        Ok(())
    }
}

pub trait EntrySelector {
    fn get_entry_info(&self, default: &Entry) -> Result<Entry>;
    fn select_one(&self, Vec<Entry>) -> Result<Entry>;
}

pub struct CliEntrySelector;

impl CliEntrySelector {
    pub fn new() -> CliEntrySelector {
        CliEntrySelector {}
    }

    pub fn get_or_default(name: &str, default: &str) -> Result<String> {
        let sin = stdin();
        let mut sout = stdout();
        let message = format!("{} [{}]: ", name, default);
        sout.write_all(message.as_bytes())
            .chain_err(|| "can't write to stdout.")?;
        sout.flush().chain_err(|| "can't flush to stdout")?;
        let mut value = String::new();
        let size = sin.read_line(&mut value)
            .chain_err(|| "can't read from stdin")?;
        if size == 1 {
            Ok(String::from(default))
        } else {
            Ok(value.trim_right().to_string())
        }
    }
}

impl EntrySelector for CliEntrySelector {
    fn get_entry_info(&self, default: &Entry) -> Result<Entry> {
        let auth = &default.auth_info;
        let title = CliEntrySelector::get_or_default("title", default.title.as_str())?;
        let user = CliEntrySelector::get_or_default("user", auth.user.as_str())?;
        let password = CliEntrySelector::get_or_default("password", auth.password.as_str())?;
        let other = CliEntrySelector::get_or_default("other", auth.other.as_str())?;
        let auth = AuthInfo::new(&user, &password, &other);

        Ok(Entry::new(&title, auth))
    }

    fn select_one(&self, v: Vec<Entry>) -> Result<Entry> {
        let sin = stdin();
        let mut sout = stdout();

        loop {
            {
                for (i, entry) in v.iter().enumerate() {
                    sout.write_fmt(format_args!("[{}] {}\r\n", i, entry.title))
                        .chain_err(|| "")?
                }
            }
            sout.write_all("> ".as_bytes())
                .chain_err(|| "can't write to stdout.")?;
            sout.flush().chain_err(|| "failed to flush to stdout")?;

            let mut line = String::new();
            sin.read_line(&mut line)
                .chain_err(|| "can't read from stdio.")?;
            let n = line.trim_right()
                .parse::<usize>()
                .chain_err(|| "failed to convert strint to usize")?;

            if v.as_slice().len() >= n {
                return Ok(v.into_iter().nth(n).unwrap());
            } else {
                sout.write_all("invalid number\r\n".as_bytes())
                    .chain_err(|| "failed to write to stdout")?;
            }

            sout.flush().chain_err(|| "can't flush to stdout.")?;
        }
    }
}
