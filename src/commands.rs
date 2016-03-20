use std::env;
use std::path;
use input::Input;
use entrystore::{EntryStore, Entry, EntryKeyValue};

pub struct Command<T: Input> {
    home: path::PathBuf,
    input: T,
}

impl<T: Input> Command<T> {
    pub fn new(input: T) -> Command<T> {
        let home = match env::home_dir() {
            Some(p) => p,
            None => panic!("Impossible to get home dir"),
        };

        Command {
            home: home,
            input: input,
        }
    }

    pub fn add_entry(&self, title: &str) {
        let mut store = EntryStore::load(&self.home, &self.input);
        let default = Entry::new(title, "", "");
        let kv = self.input.get_entry_info(title, default);
        store.add(kv.title.as_str(), kv.entry);
        store.save();
    }

    pub fn show_entry(&self, title: &str) -> Option<EntryKeyValue> {
        let store = EntryStore::load(&self.home, &self.input);
        store.select_one(title, &self.input)
    }

    pub fn change_entry(&self, title: &str) {
        let mut store = EntryStore::load(&self.home, &self.input);
        match store.select_one(title, &self.input) {
            Some(default_kv) => {
                let new_entry = self.input
                                    .get_entry_info(default_kv.title.as_str(), default_kv.entry);
                store.change(new_entry.title.as_str(), new_entry.entry);
                store.save();
            }
            None => println!("No entry."),
        }
    }
}
