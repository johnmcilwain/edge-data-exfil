# Data Exfiltration Test for Fastly's Compute@Edge (in Rust)

## Description 
A starter implementation for scanning and blocking confidential data via web requests
Before the https response reaches the client, scan the https body and look for predefined regex matches
   If any are found, log it and optionally replace the matches (mask) with meaningless characters

 Commands (see Command enum):
   COMMAND               MODIFIED?      SINGLE PASS?        DESCRIPTION                                                     
   --------------------  -------------  ------------------  -----------------------------------------
   Bypass                No             No                  Bypass most code and return, might be useful for testing        
   FindAnyMatch          No             Yes/No              Log if any regex matched
   FindNames             No             No                  Log the list of all secret names that match                       
   FindRegexes           No             No                  Log the list of all regexes that match                          
   FindIndexes           No             No                  Log the list of all matching regex indexes                      
   FindCaptures          No             No                  Contains the real secret data...do not log this!            
   ReplaceMatches        Yes            No                  Mask any found matches (and log them)                           
 
   Single pass regex (i.e. fast) is only supported when the search result is true/false and doesn't use an algorithm validator

   There are 2 validator algorithm defined
     LuhnNumbers         Does a check on the possible credit card number to validate it (https:en.wikipedia.org/wiki/Luhn_algorithm)
     AlwaysTrue          Always returns yes (useful testing and for FindCaptures)
 
 Initial Setup:
   See commands.rs to setup your list of commands/regexes and for test data


