//
// Trait for types that can be searched by different commands
// 
//   BodyBytes:    u8
//   BodyString:   utf-8 compatible
//   HeaderBytes:  u8
//   HeaderString: utf-8 compatible
// 
// The SearchMethods trait implements the interface
//   bypass(): 
//   find_any_match(): 
//   find_names():
//   find_regexes():
//   find_indexes():
//   find_captures():
//   replace_matches():
//
use crate::commands::Command;
use std::fmt::{Debug, Display};

use crate::algorithms::AlgorithmMethods;
use crate::secrets::Secrets;



// Trait: BodyMethods -----------------------------------------------------------------------------
pub trait SearchMethods {
    fn bypass         (&self) -> bool;

    fn find_any_match (&self, command: &Command) -> bool;
    
    fn find_names     (&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<String>;    
    fn find_regexes   (&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<String>;
    fn find_captures  (&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<String>;
    fn find_indexes   (&self, command: &Command, algorithm: &Option<impl AlgorithmMethods + Debug + Display>) -> Vec<usize>;

    fn replace_matches(&mut self, secrets: &Secrets, indexes: &[usize]);
}












