//
// Validate regex captures (with CRC or similar technique)
//
// Enum: AlgorithmName:
//   AlwaysTrue - always is true
//   LuhnNumbers - validates numbers according to the luhn algorighm
//
// Trait: AlgorithmMethods: functions to validate Strings and Bytes
//
use std::fmt;
use std::fmt::{Debug, Display};


// Enum: AlgorithmName ----------------------------------------------------------------------------
#[allow(dead_code)]
#[derive(Copy, Clone, PartialEq)]
pub enum AlgorithmName {
    AlwaysTrue,
    LuhnNumbers,
}

impl Default for AlgorithmName {
    fn default() -> Self { 
        AlgorithmName::AlwaysTrue 
    }
}

impl Debug for AlgorithmName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AlgorithmName::AlwaysTrue => "AlwaysTrue".to_string(),
            AlgorithmName::LuhnNumbers => "Luhn".to_string(),
        };
        write!(f, "{:?}", text)
    }
}


impl Display for AlgorithmName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AlgorithmName::AlwaysTrue => "AlwaysTrue".to_string(),
            AlgorithmName::LuhnNumbers => "Luhn".to_string(),
        };

        f.debug_struct("AlgorithmName")
         .field("Selected: ", &text)
         .finish()
    }
}

// Trait: AlgorithmMethods ------------------------------------------------------------------------
pub trait AlgorithmMethods {
    fn validate_bytes(&self, data: &[u8]) -> bool; 
    fn validate_string(&self, data: &str) -> bool; 
}

impl AlgorithmMethods for AlgorithmName {
    fn validate_bytes(&self, data: &[u8]) -> bool {
        match &self {
            AlgorithmName::AlwaysTrue => true,
            AlgorithmName::LuhnNumbers => luhn::valid_bytes(data.to_vec()),
        }
    }

    fn validate_string(&self, data: &str) -> bool {
        match &self {
            AlgorithmName::AlwaysTrue => true,
            AlgorithmName::LuhnNumbers => luhn::valid(data),
        }
    }
}














