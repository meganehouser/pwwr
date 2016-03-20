use std::io::{Write, stdout, stdin};
use std::str;
use rpassword::read_password;
use entrystore::{Entry, EntryKeyValue};


pub trait Input{
    fn required(&self, name: &str) -> Vec<u8>;
    fn get_password(&self) -> Vec<u8>;
    fn get_entry_info(&self, default_title: &str, default: Entry) -> EntryKeyValue;
    fn select_one(&self, Vec<EntryKeyValue>) -> EntryKeyValue;
}

pub struct CliInput;

impl CliInput {
    pub fn new() -> CliInput {
        CliInput{}
    }
}

impl Input for CliInput {
    fn required(&self, name: &str) -> Vec<u8> {
        let mut sout = stdout();
        let sin = stdin();
        let mut value = String::new();

        while value.len() <= 1 {
            value.clear();
            try_panic!(sout.write_all(name.as_bytes()), "print exception");
            try_panic!(sout.flush(), "print flush exception");
            try_panic!(sin.read_line(&mut value), "input exception");
        }

        Vec::from(value.as_str().trim_right().as_bytes())
    }

    fn get_password(&self) -> Vec<u8> {
        let mut sout = stdout();
        let mut password = String::new();

        while password.len() == 0 {
            try_panic!(sout.write_all("password: ".as_bytes()), "print exception");
            try_panic!(sout.flush(), "print flush exception");

            let result = read_password();
            if result.is_ok() {
                password = result.unwrap();
            } else {
                panic!("input password exception");
            }
        }

        Vec::from(password.as_bytes())
    }

    fn get_entry_info(&self, title: &str, default: Entry) -> EntryKeyValue {
        let title = get_or_default("title", title);
        let user = get_or_default("user",default.user.as_str()); 
        let password = get_or_default("password", default.password.as_str());
        let other= get_or_default("other", default.other.as_str());

        let entry = Entry::new(user.as_str(), password.as_str(), other.as_str());
        EntryKeyValue::new(title.as_str(), entry)
    }

    fn select_one(&self, v: Vec<EntryKeyValue>) -> EntryKeyValue {
        let sin = stdin();
        let mut sout =  stdout();

        loop {
            let _v = v.clone();
            for (i, ekv) in _v.iter().enumerate() {
                let _ = sout.write_fmt(format_args!("[{}] {}\r\n", i, ekv.title));
            }

            let _ = sout.write_all("> ".as_bytes());
            let _ = sout.flush();

            let mut line = String::new();
            match sin.read_line(&mut line) {
                Ok(_) => {
                    match str::FromStr::from_str(line.as_str()) {
                        Ok(n) => {
                            match _v.into_iter().nth(n) {
                                Some(ekv) => return ekv,
                                None => {
                                    let _ = sout.write_all("invalid number\r\n".as_bytes());
                                }
                            };
                        },
                        Err(e) => {
                            let _ = sout.write_fmt(format_args!("input error: {:?}\r\n", e));
                        } ,
                    };
                },
                Err(e) => {
                    let _ = sout.write_fmt(format_args!("input error: {:?}\r\n", e));
                }
            };
                let _ = sout.flush();
        }
    }
}

fn get_or_default(name: &str, default: &str) -> String {
    let sin = stdin();
    let mut sout = stdout();
    let message = format!("{} [{}]: ", name, default);
    let _ = sout.write_all(message.as_bytes());  
    let _ = sout.flush();
    let mut value = String::new();
    let size = sin.read_line(&mut value).unwrap();

    if size == 0 {
        String::from(default)
    } else {
        value
    }
}
