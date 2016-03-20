use std::collections::HashMap;
use std::path::PathBuf;
use std::io::Read;
use std::fs::{File, DirBuilder};
use std::iter::FromIterator;
use rustc_serialize::json;
use std::path::Path;
use pwdcrypto::{Cipher, KeyProvider};
use input::Input;

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct Entry {
    pub user: String,
    pub password: String,
    pub other: String,
}

impl Entry {
    pub fn new(user: &str, password: &str, other: &str) -> Entry {
        Entry {
            user: String::from(user),
            password: String::from(password),
            other: String::from(other),
        }
    }
}

#[derive(Clone)]
pub struct EntryKeyValue {
    pub title: String,
    pub entry: Entry,
}

impl EntryKeyValue {
    pub fn new(title: &str, entry: Entry) -> EntryKeyValue {
        EntryKeyValue {
            title: String::from(title),
            entry: entry,
        }
    }
}

pub struct EntryStore {
    data: HashMap<String, Entry>,
    cipher: Cipher,
    file: PathBuf,
}

const PWWR_PATH: &'static str = ".pwwr";
const ENTRY_FILE: &'static str = "entries";
const USER_FILE: &'static str = "user";

impl EntryStore {
    pub fn load<T: Input>(home_dir: &PathBuf, input: &T) -> EntryStore {
        let pwwr_path = Path::new(home_dir).join(PWWR_PATH);
        let _ = DirBuilder::new().create(pwwr_path.clone());

        let entries_path = pwwr_path.join(ENTRY_FILE);
        let user_path = pwwr_path.join(USER_FILE);
        let mut entries_file: File = try_panic!(File::open(entries_path.clone()),
                                                "entries file cannot open");
        let mut user_file = try_panic!(File::open(user_path), "user file cannot open");

        let mut key_provider = KeyProvider::new(input, user_file);
        let (password, salt) = key_provider.get();
        let cipher = Cipher::new(&password, &salt);

        let mut content = Vec::new();
        let _ = entries_file.read_to_end(&mut content);
        let plain_data = cipher.decrypt(&content).unwrap();
        let plain_str = String::from_utf8(plain_data).unwrap();
        let data: HashMap<String, Entry> = json::decode(plain_str.as_str()).unwrap();

        EntryStore {
            data: data,
            cipher: cipher,
            file: entries_path,
        }
    }

    pub fn add(&mut self, title: &str, entry: Entry) {
        self.data.insert(String::from(title), entry);
    }

    pub fn search(&self, title_pattern: &str) -> Vec<EntryKeyValue> {
        let ekvs = self.data
                       .keys()
                       .filter_map(|ref key| {
                           let key_str = key.as_str();
                           if key.starts_with(title_pattern) {
                               if let Some(v) = self.data.get(key.as_str()) {
                                   return Some(EntryKeyValue::new(key.as_str(), v.clone()));
                               }
                           }

                           None
                       });
        Vec::from_iter(ekvs)
    }

    pub fn select_one<T: Input>(&self, title_pattern: &str, input: &T) -> Option<EntryKeyValue> {
        let entries = self.search(title_pattern);
        let len = entries.len();
        if len == 0 {
            return None;
        } else if len >= 2 {
            return Some(entries.into_iter().nth(0).unwrap());
        }

        return Some(input.select_one(entries));
    }

    pub fn change(&mut self, title: &str, entry: Entry) {}

    pub fn save(&mut self) {}
}
