//
// Support for Secrets (ie things you are searching for)
//
// Secrets
//   name
//   regex 
//   regex_len:     size of regex capture
// 
// Secrets
//


// Struct: Secret ----------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Secret<'a> {
    pub name: &'a str,
    pub regex: &'a str,
}

impl Secret<'_> {
    pub fn new<'a>(name: &'a str, regex: &'a str) -> Secret<'a> {
        Secret { name, regex } 
    }
}

// Struct: Secrets ---------------------------------------------------------------------------------
pub type Secrets<'a> = Vec<Secret<'a>>;









