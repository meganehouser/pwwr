extern crate clap;
extern crate crypto;
extern crate rand;
extern crate rpassword;

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate error_chain;

use std::env;
use std::fs::DirBuilder;
use std::path::Path;
use clap::{App, Arg, SubCommand};
use commands::Command;
use entrystore::{CliEntrySelector, EntryStore};
use pwdcrypto::{AesCipher, KeyProvider};
use rawio::FileRawStore;
use errors::*;

mod errors {
    error_chain!{}
}

mod pwdcrypto;
mod entrystore;
mod commands;
mod rawio;

const PWWR_DIR: &'static str = ".pwwr";
const ENTRY_FILE: &'static str = "entries";
const USER_FILE: &'static str = "user";

fn make_command() -> Result<Command<CliEntrySelector, FileRawStore, AesCipher>> {
    let home_dir = env::home_dir().chain_err(|| "Can't find home directory.")?;
    let pwwr_path = Path::new(&home_dir).join(PWWR_DIR);
    if !pwwr_path.exists() {
        DirBuilder::new()
            .create(pwwr_path.clone())
            .chain_err(|| "Can't create pwwr directory.")?;
    }

    let entries_path = pwwr_path.join(ENTRY_FILE);
    let entries_file = FileRawStore::new(entries_path).chain_err(|| "entries")?;

    let user_path = pwwr_path.join(USER_FILE);
    let mut user_file = FileRawStore::new(user_path).chain_err(|| "user")?;

    let input = CliEntrySelector::new();

    let mut key_provider = KeyProvider::new(&input, &mut user_file);
    let (password, salt) = key_provider.get()?;
    let cipher = AesCipher::new(&password, &salt);

    let entry_store = EntryStore::load(entries_file, cipher)?;
    Ok(Command::new(CliEntrySelector::new(), entry_store))
}

fn execute_cmd() -> Result<()> {
    let matches = App::new("pwwr")
        .version("0.1.0")
        .about("Rust Password Wound")
        .author("meganehouser <sleepy.st818@gmail.com>")
        .subcommand(
            SubCommand::with_name("add")
                .about("add a password entry.")
                .arg(Arg::with_name("name_for_add").index(1)),
        )
        .subcommand(
            SubCommand::with_name("change")
                .about("change the password entry.")
                .arg(Arg::with_name("name_for_change").index(1)),
        )
        .subcommand(
            SubCommand::with_name("show")
                .about("show the password entry.")
                .arg(Arg::with_name("name_for_show").index(1)),
        )
        .get_matches();


    if let Some(ref sub_matches) = matches.subcommand_matches("add") {
        let title = sub_matches.value_of("name_for_add").unwrap_or("");
        make_command()?.add_entry(title)?;
    } else if let Some(ref sub_matches) = matches.subcommand_matches("change") {
        let title = sub_matches.value_of("name_for_change").unwrap_or("");
        make_command()?.change_entry(title)?;
    } else if let Some(ref sub_matches) = matches.subcommand_matches("show") {
        let title = sub_matches.value_of("name_for_show").unwrap_or("");
        match make_command()?.get_entry(title)? {
            Some(ref entry) => println!("{}", entry),
            None => bail!("No entry."),
        };
    } else {
        println!("{}", matches.usage());
    };

    Ok(())
}

fn main() {
    match execute_cmd() {
        Ok(_) => {}
        Err(e) => {
            println!("{:?}", e);
        }
    };
}
