//
// Utilities
// 
// fn header_value: 
// fn percent_hit:
//


pub use percentage::{Percentage, PercentageInteger};
use rand::prelude::*;
use std::fmt;


//
// Test if a random occurance happened
//
pub fn percent_hit(rng: &mut ThreadRng, percent: &PercentageInteger) -> bool {
    let random = rng.gen_range(0, 100);
    percent.value() > random
}

//
// To allow fmt::Display for <T>
//
pub struct SliceDisplay<'a, T: 'a>(&'a [T]);
impl<'a, T: fmt::Display + 'a> fmt::Display for SliceDisplay<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for item in self.0 {
            if !first {
                write!(f, "{}", item)?;
            } else {
                write!(f, "{}", item)?;
            }
            first = false;
        }
        Ok(())
    }
}























