// 
// Name    : edge-data-exfil
// Author  : john mcilwain (johnmc@f.c)
// Version : 0.25
// License : 
//   This sample code is provided on an "AS IS" basis.  THERE ARE NO 
//   WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
//   WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
//   PURPOSE, REGARDING THE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
//   COMBINATION WITH YOUR PRODUCTS.  
//
// Pre Release Notes:
//   This project was created for a hackathon. At the time, I didn't have a complete idea of what to create,
//   so I started creating a bunch of base regex functions and hoped a final idea would come.
//   An idea did come: to redact outgoing data that matched a regex.  This could have been accomplished
//   much easier with a single regex and a very small program, but since I started creating all of those base funcitons,
//   I just keep them in and went with the original idea.
//   Afterall, the whole idea was to write my first Rust program and I wanted to try out as many language features that I could.
//
//   Also, this program started out wanting to support both Bytes and Strings as input (same as the regex crate)
//   I ended up simplifying it to only support Bytes, but would like to re-address the surrounding issuses in the future
//   Same with headers, they should be checked
//
//   To compile, you would need a slightly modified verson of these crates: 
//     Percentage: to add a Debug trait
//     Luhn: to add support for binary input
//
//
// Description:
//   A starter implementation for scanning and blocking confidential data via web requests
//
//   Before the https response reaches the client, scan the https body and headers and look for predefined regex matches
//   If any are found, log it and optionally replace the matches (mask) with meaningless characters
//
// Commands (see Command enum):
//   COMMAND               MODIFIED?      SINGLE PASS?        DESCRIPTION                                                     
//   --------------------  -------------  ------------------  -----------------------------------------
//   Bypass                No             No                  Bypass most code and return, might be useful for testing        
//   FindAnyMatch          No             Yes/No              Log if any regex matched
//   FindNames             No             No                  Log the list of all secret names that match                       
//   FindRegexes           No             No                  Log the list of all regexes that match                          
//   FindIndexes           No             No                  Log the list of all matching regex indexes                      
//   FindCaptures          No             No                  Contains the real secret data...do not log this!            
//   ReplaceMatches        Yes            No                  Mask any found matches (and log them)                           
// 
//   Single pass regex (i.e. fast) is only supported when the search result is true/false and doesn't use an algorithm validator
//
//   There are 2 validator algorithm defined
//     LuhnNumbers         Does a check on the possible credit card number to validate it (https://en.wikipedia.org/wiki/Luhn_algorithm)
//     AlwaysTrue          Always returns yes (useful testing and for FindCaptures)
// 
// Initial Setup:
//   See commands.rs to setup your list of commands/regexes and for test data
//
// Future ideas: 
//   Support chunked data
//   Support searching headers (key and value)
//   Add tests and better error checking / logging
//   Update or replace Percent crate
//   Update or replace Lunh crate
//   Are gzip and compression handled automatically?
//
// Test CLI:
//   <<redacted>>
// 
mod algorithms; 
mod commands;
mod httpbody;
mod search;
mod secrets;
mod utilities; 

use commands::{Commands, CommandMethod, CommandSearch, get_commands};
use httpbody::BodyBytes;
use search::SearchMethods;
use utilities::{percent_hit};
use fastly::{Error, Request, Response};

const BACKEND_NAME:         &str             = "";
const LOGGING_ENDPOINT:     &str             = "";
const LOGGING_PREFIX:       &str             = "DataExfil:";
const LOGGING_LEVEL:        log::LevelFilter = log::LevelFilter::Info;


//
// main() 
//
#[fastly::main]
fn main(request: Request) -> Result<Response, Error> {
    // Setup logger
    log_fastly::Logger::builder()
        .max_level(LOGGING_LEVEL)
        .default_endpoint(LOGGING_ENDPOINT)
        .init();
    println!("{}", "\n".repeat(10));
    println!("Version = {}", std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new()));

    // Get list of commands to execute
    let commands = get_commands();
    log::info!("{}{}", LOGGING_PREFIX, format!("Current command: {:?}", commands));
    println!("Current command: {:?}", commands);

    // Send request off
    let mut response = request.send(BACKEND_NAME)?;

    // Process the results
    let mut body_bytes = BodyBytes(response.take_body_bytes());
    process_command(&mut body_bytes, &commands);
    let return_buffer = body_bytes.0;

    // Return (possibly modified) body and headers
    Ok(Response::from_body(return_buffer))
}


//
//  Process each command if the percentage hit comes up true  
//
//   COMMAND               MODIFIED?      SINGLE PASS?        DESCRIPTION                                                     
//   --------------------  -------------  ------------------  -----------------------------------------
//   Bypass                No             No                  Bypass most code and return, might be useful for testing        
//   FindAnyMatch          No             Yes/No              Log if any regex matched
//   FindNames             No             No                  Log the list of all secret names that match                       
//   FindRegexes           No             No                  Log the list of all regexes that match                          
//   FindIndexes           No             No                  Log the list of all matching regex indexes                      
//   FindCaptures          No             No                  Contains the real secret data...do not log this!            
//   ReplaceMatches        Yes            No                  Mask any found matches (and log them)                           
//
fn process_command(body: &mut impl SearchMethods, commands: &Commands) {
    let mut rng = rand::thread_rng();

    for command in commands {
        // Only execute x percent of the time
        if percent_hit(&mut rng, &command.percent) {
            // Optionally, process the body
            if command.search.contains(&CommandSearch::SearchBody) {
                match command.name {
                    CommandMethod::Bypass => {
                        body.bypass();
                    },
                    CommandMethod::FindAnyMatch => { 
                        match &command.algorithm {
                            None => body.find_any_match(&command),
                            Some(_) => !body.find_names(&command, &command.algorithm).is_empty(),
                        };
                    },
                    CommandMethod::FindNames => {
                        body.find_names(&command, &command.algorithm);
                    }
                    CommandMethod::FindRegexes => {
                        body.find_regexes(&command, &command.algorithm);
                    }
                    CommandMethod::FindIndexes => {
                        body.find_indexes(&command, &command.algorithm);
                    }
                    CommandMethod::FindCaptures => { 
                        body.find_captures(&command, &command.algorithm);
                    },
                    CommandMethod::ReplaceMatches => { 
                        let indexes = body.find_indexes(&command, &command.algorithm);
                        body.replace_matches(&command.secrets, &indexes);
                    }
                }
            }
        }
    }
}    
























