extern crate clap;
extern crate crypto;
extern crate rand;
extern crate rpassword;
extern crate rustc_serialize;

use clap::{Arg, App, SubCommand};
use commands::Command;
use input::CliInput;

macro_rules! try_panic(
    ($e: expr, $message: expr) => { 
        match $e {
            Ok(val) => val,
            Err(e) => {
                let errkind = format!("{:?}", e.kind());
                panic!([$message, "Error: ", errkind.as_str()].concat());
            }
        }
    };
);

mod input;
mod pwdcrypto;
mod entrystore;
mod commands;

fn main() {
    let matches = App::new("rpw")
                      .version("1.0")
                      .about("Rust Password Wound")
                      .subcommand(SubCommand::with_name("add")
                                      .about("add a password entry.")
                                      .arg(Arg::with_name("name_for_add").index(1)))
                      .subcommand(SubCommand::with_name("change")
                                      .about("change the password entry.")
                                      .arg(Arg::with_name("name_for_change").index(1)))
                      .subcommand(SubCommand::with_name("show")
                                      .about("show the password entry.")
                                      .arg(Arg::with_name("name_for_show").index(1)))
                      .get_matches();

    let command = Command::new(CliInput::new());

    if let Some(ref sub_matches) = matches.subcommand_matches("add") {
        let title = sub_matches.value_of("name_for_add").unwrap();
        command.add_entry(title);
    } else if let Some(ref sub_matches) = matches.subcommand_matches("change") {
        let title = sub_matches.value_of("nameof_for_change").unwrap();
        command.change_entry(title);
    } else if let Some(ref sub_matches) = matches.subcommand_matches("show") {
        let title = sub_matches.value_of("nameof_for_show").unwrap();
        command.show_entry(title);
    }
}
