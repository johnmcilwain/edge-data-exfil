//
// Details around a command
// 
// Command:
//   name:
//   percent:
//   algorithm:
//   secrets:
// 
// Sample data:
//   Valid credit card formats:
//     Visa:                         # 13 or 16 digits, starting with 4.
//     MasterCard:                   # 16 digits, starting with 51 through 55.
//     American Express:             # 15 digits, starting with 34 or 37.
//   
//   Fake cards numbers to test (they do pass the Luhn algorithm)
//     Visa: 4222222222222, 4111111111111111, 4012888888881881 
//     MasterCard: 5555555555554444, 5105105105105100
//     American Express: 378282246310005, 371449635398431
//     Reference: https://www.paypalobjects.com/en_US/vhelp/paypalmanager_help/credit_card_numbers.htm//
//
pub use percentage::{Percentage, PercentageInteger};

use crate::algorithms::AlgorithmName;
use crate::secrets::{Secret, Secrets};


// Things to match (note: using '_' to disable dead_code warnings...after testing, remove the underscores)
const _SOCIALSECURITY:       &str             = r"(\d{3}-?\d{2}-?\d{4})"; 
const _CCARD_AMEX:           &str             = r"(35\d{13}|37\d{13})"; 
const _CCARD_VISA13:         &str             = r"(4\d{12})"; 
const _CCARD_VISA16:         &str             = r"(4\d{15})"; 
const _CCARD_MASTERCARD:     &str             = r"(51\d{14}|52\d{14}|53\d{14}|54\d{14}|55\d{14})"; 
const _INTERNAL_IP:          &str             = r"(10)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
const _ANY_IP:               &str             = r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
const _MAC_ADDRESS:          &str             = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})";
const _ANY_EMAIL:            &str             = r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})";
const _HONEYPOT_EMAIL:       &str             = r"secret@secretcompany.com";
const _HONEYPOT_TEXT1:       &str             = r"xyzzy";
const _HONEYPOT_TEXT2:       &str             = r"Up, Up, Down, Down, Left, Right, Left, Right, B, A"; 


// Enum: CommandMethod ----------------------------------------------------------------------------
#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub enum CommandMethod {
    Bypass,            
    FindAnyMatch,  
    FindNames, 
    FindIndexes,          
    FindRegexes,        
    FindCaptures, 
    ReplaceMatches,     
}


// Enum: CommandSearch ----------------------------------------------------------------------------
#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub enum CommandSearch {
    SearchBody,            
}
 

// Struct: Command --------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Command<'a> {
    pub name: CommandMethod,
    pub search: Vec<CommandSearch>,
    pub percent: percentage::PercentageInteger,           
    pub algorithm: Option<AlgorithmName>,  
    pub secrets: Secrets<'a>,
}

impl Command<'_> {
    pub fn new(name: CommandMethod, search: Vec<CommandSearch>, percent: percentage::PercentageInteger, algorithm: Option<AlgorithmName>, secrets: Secrets) -> Command {
        Command { name, search, percent, algorithm, secrets } 
    }
}

pub type Commands<'a> = Vec<Command<'a>>;



//
//  List of commands to execute
//  Note: you could put this in a dictionary if you need to change the tests often
//
//  COMMAND               BODY MODIFIED?      SINGLE PASS?        DESCRIPTION                                                     
//  --------------------  ------------------  ------------------  -----------------------------------------
//  Bypass                No                  No                  Bypass most code and return, might be useful for testing        
//  FindAnyMatch          No                  Yes/No              Single pass if no algorithm -- Log if any regex matched
//  FindNames             No                  No                  Log the list of all secret names that match                       
//  FindRegexes           No                  No                  Log the list of all regexes that match                          
//  FindIndexes           No                  No                  Log the list of all matching regex indexes                      
//  FindCaptures          No                  No                  Contains the real secret data...do not log this!            
//  ReplaceMatches        Yes                 No                  Mask any found matches (and log them)                           
//
pub fn get_commands() -> Commands<'static> {

    // Single command examples:    
    // Example: for 100% of requests, find any Amex cards and log if any cards were found
    return vec![ Command::new(CommandMethod::FindAnyMatch, 
                              vec![CommandSearch::SearchBody],
                              Percentage::from(100), 
                              None, 
                              vec![Secret::new("amex", _CCARD_AMEX)] ) ];   
    // 
    // Example: for 100% of requests, find any Amex cards that pass the Luhn algorithm and mask(hide) show a unique list of names
    // return vec![ Command::new(CommandMethod::FindCaptures, 
    //                           vec![CommandSearch::SearchBody],
    //                           Percentage::from(100), 
    //                           Some(AlgorithmName::LuhnNumbers), 
    //                           vec![Secret::new("amex", _CCARD_AMEX)] ) ];
    //
    // Example: for 100% of requests, find any Amex cards that pass the Luhn algorithm and mask(hide) the text before the viewer can see it
    // return vec![ Command::new(CommandMethod::ReplaceMatches, 
    //                           vec![CommandSearch::SearchBody],
    //                           Percentage::from(100), 
    //                           Some(AlgorithmName::LuhnNumbers), 
    //                           vec![Secret::new("amex", _CCARD_AMEX)] ) ];


    // Multiple command example:
    //
    // return vec![ Command::new(CommandMethod::FindNames,      vec![CommandSearch::SearchBody], Percentage::from(100),  Some(AlgorithmName::LuhnNumbers), vec![Secret::new("amex",       _CCARD_AMEX)]   ), 
    //              Command::new(CommandMethod::ReplaceMatches, vec![CommandSearch::SearchBody], Percentage::from(100),  Some(AlgorithmName::LuhnNumbers), vec![Secret::new("amex",       _CCARD_AMEX)]   ), 
    //              Command::new(CommandMethod::FindRegexes,    vec![CommandSearch::SearchBody], Percentage::from(100),  None,                             vec![Secret::new("visa16",     _CCARD_VISA16)] ), 
    //              Command::new(CommandMethod::FindNames,      vec![CommandSearch::SearchBody], Percentage::from(100),  None,                             vec![Secret::new("mastercard", _CCARD_MASTERCARD),
    //                                                                                                                                                          Secret::new("amex",       _CCARD_AMEX), 
    //                                                                                                                                                         ]),
    //            ];
}
















