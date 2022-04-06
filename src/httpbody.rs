//
// Support for http body types
/// 
// There are 2 main datatypes to hold the http body 
//   BodyBytes:  u8
//   BodyString: utf-8 compatible
//   NB: As mentioned in main.rs, only BodyBytes was implemented 
//
// The SearchMethods trait implements the interface to work with either type
//   bypass(): 
//   find_any_match(): 
//   find_names():
//   find_regexes():
//   find_indexes():
//   find_captures():
//   replace_matches():
//

use crate::commands::Command;
use crate::LOGGING_PREFIX;
use crate::algorithms::AlgorithmMethods;
use crate::secrets::Secrets;
use crate::search::SearchMethods;

use std::borrow::Cow;
use std::fmt;
use std::fmt::{Debug, Display};
use regex::bytes::Regex as BytesRegex;
use regex::bytes::Captures as BytesCaptures;
use regex::bytes::RegexSet as BytesRegexSet;

// Types:  ----------------------------------------------------------------------------------------
// const CROSSOUT_CHAR: &str =  "x";
const CROSSOUT_BYTE: u8 = b'x';
pub type Bytes = Vec<u8>;

// Struct: BodyBytes ------------------------------------------------------------------------------
#[derive(Debug)]
pub struct BodyBytes (
    pub Bytes,
);
impl Display for BodyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Struct: BodyString -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct BodyString(
    pub String
);
impl Display for BodyString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}


// 
// Processing of Bytes based http bodies
// Examples: "image/png" "image/jpeg"
// 
impl SearchMethods for BodyBytes {
    fn bypass(&self) -> bool {
        log::info!("{}", format!("{} information: bypass mode", LOGGING_PREFIX));
        println!("BodyBytes: bypass()");
        true
    }

    fn find_any_match(&self, command: &Command) -> bool {
        log::info!("{}", format!("{} body information: find_any_match", LOGGING_PREFIX));
        println!("BodyBytes: find_any_match()");
        let secret_regexes: Vec<String> = command.secrets.iter().map(|w| w.regex.to_string()).collect();
        let regex_set = BytesRegexSet::new(secret_regexes).unwrap();
        let found = regex_set.is_match(&self.0);
        log::info!("{}", if found { format!("{} body found: at least one match", LOGGING_PREFIX) } else { format!("{} body not found: no matches", LOGGING_PREFIX) });
        println!(">returning: body found = {:?}", found);
        found
    }

    fn find_names(&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<String> {
        log::info!("{}", format!("{} body information: find_names", LOGGING_PREFIX));
        println!("BodyBytes: find_names()");
        let found = self.find_indexes(command, algorithm).into_iter().map(|x| command.secrets[x].name.into()).collect();
        log::info!("{}", format!(">>found names: {:?}", found));
        println!(">>found names: {:?}", found);
        found
    }

    // fn find_regexes(&self, algorithm: &Option<impl AlgorithmMethods + Debug + Display>, secret_regexes: &[String]) -> impl Iterator<Item=String> + '_ {    
    fn find_regexes(&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<String> {
        log::info!("{}", format!("{} body information: find_regexes", LOGGING_PREFIX));
        println!("BodyBytes: find_regexes()");
        let found = self.find_indexes(command, algorithm).into_iter().map(|x| command.secrets[x].regex.into()).collect();
        log::info!("{}", format!(">>found regexes: {:?}", found));
        println!(">>found regexes: {:?}", found);
        found
    }

    // Warning: shows the actual secret, i.e credit card number
    fn find_captures(&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<String> {
        log::info!("{}", format!("{} body information: find_captures", LOGGING_PREFIX));
        println!("BodyBytes: find_captures()");
        let secret_regexes: Vec<String> = command.secrets.iter().map(|w| w.regex.to_string()).collect();

        const MATCHED_NUM: usize = 1;
        let mut found: Vec<String> = Vec::new();

        let regex_set = BytesRegexSet::new(&secret_regexes).unwrap();
        let indexes: Vec<usize> = regex_set.matches(&self.0).into_iter().collect();

        // Create a list of all found matches
        for index in indexes {
            let regex = BytesRegex::new(&secret_regexes[index]).unwrap();
            for capture in regex.captures_iter(&self.0) {
                match std::str::from_utf8(&capture[MATCHED_NUM]) {
                    Ok(good) => {
                        let cap:String = good.to_string();
                        match algorithm {
                            Some(algo) => {
                                if algo.validate_string(&cap) && !found.contains(&cap) {
                                    found.push(cap);
                                }
                            },
                            None => {
                                if !found.contains(&cap) {
                                    found.push(cap);
                                }
                            },
                        };
                    },
                    Err(error) => { 
                        log::info!("{}", format!(">>warning: can't convert to utf-8, ignoring: {:?}", error.to_string()));
                    },
                };
            }
        }
        log::info!("{}", format!(">>found: {:?}", found));
        println!(">>found: {:?}", found);
        found
    }

    fn find_indexes(&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<usize> {
        log::info!("{}", format!("{} body information: find_indexes", LOGGING_PREFIX));
        println!("BodyBytes: find_indexes()");
        let secret_regexes: Vec<String> = command.secrets.iter().map(|w| w.regex.to_string()).collect();

        match algorithm {
            Some(algo) => {
                const MATCHED_NUM: usize = 1;
                let mut found: Vec<usize> = Vec::new();

                let regex_set = BytesRegexSet::new(&secret_regexes).unwrap();
                let indexes: Vec<usize> = regex_set.matches(&self.0).into_iter().collect();

                // Create a list of all found matches
                for index in indexes {
                    let regex = BytesRegex::new(&secret_regexes[index]).unwrap();
                    for capture in regex.captures_iter(&self.0) {
                        if algo.validate_bytes(&capture[MATCHED_NUM]) && !found.contains(&index) {
                            found.push(index);
                        }
                    }
                }
                log::info!("{}", format!(">>found indexes: {:?}", found));
                println!(">>found indexes: {:?}", found);
                found
            },
            None => {
                let indexes: Vec<_>;
                let regex_set = BytesRegexSet::new(&secret_regexes).unwrap();
                indexes = regex_set.matches(&self.0).into_iter().collect();

                let found: Vec<usize> = indexes.iter().map(|&x| indexes[x]).collect();
                log::info!("{}", format!(">>found indexes: {:?}", found));
                found
            },
        }
    }
    
    fn replace_matches(&mut self, secrets: &Secrets, indexes: &[usize]) {
        log::info!("{}", format!("{} body information: replace_matches", LOGGING_PREFIX));
        println!("BodyBytes: replace_matches()");

        for index in indexes {
            let regex = BytesRegex::new(secrets[*index].regex).unwrap();
            log::info!("{}", format!("{} masking index: {} matched: {}", LOGGING_PREFIX, *index, regex));
            println!(">replace_matches(): masking index: {} matched: {}", *index, regex);

            // Replace found matches with the crossout byte 
            // Save this alternative syntax:  &vec![CROSSOUT_BYTE; caps[1].len()]
            match regex.replace_all(&self.0, |caps: &BytesCaptures| { std::iter::repeat(CROSSOUT_BYTE).take(caps[1].len()).collect::<Vec<u8>>() }) {
                Cow::Owned(new) => *self = BodyBytes(new), 
                Cow::Borrowed(_) => {},
            };
        }
    }
}

