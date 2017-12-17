use entrystore::{AuthInfo, Entry, EntryStore};
use entrystore::EntrySelector;
use rawio::RawStore;
use entrystore::Cipher;
use errors::*;

pub struct Command<T: EntrySelector, RW: RawStore, CP: Cipher> {
    entry_store: EntryStore<RW, CP>,
    input: T,
}

impl<T, RW, CP> Command<T, RW, CP>
where
    T: EntrySelector,
    RW: RawStore,
    CP: Cipher,
{
    pub fn new(input: T, entry_store: EntryStore<RW, CP>) -> Command<T, RW, CP> {
        Command {
            entry_store: entry_store,
            input: input,
        }
    }

    pub fn add_entry(&mut self, title: &str) -> Result<()> {
        let default = Entry::new(title, AuthInfo::blank());
        let entry = self.input.get_entry_info(&default)?;
        self.entry_store.add(entry)?;
        self.entry_store.save()?;
        Ok(())
    }

    pub fn get_entry(&mut self, title: &str) -> Result<Option<Entry>> {
        self.entry_store.select_one(title, &self.input)
    }

    pub fn change_entry(&mut self, title: &str) -> Result<()> {
        match self.entry_store.select_one(title, &self.input)? {
            Some(default) => {
                let new_entry = self.input.get_entry_info(&default)?;
                self.entry_store.change(&default.title.as_str(), new_entry)?;
                self.entry_store.save()?;
                Ok(())
            }
            None => {
                println!("No entry.");
                Ok(())
            }
        }
    }
}
