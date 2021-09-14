pub mod base_types;
pub mod core_state;
pub mod core_types;
pub mod crypto;
pub mod driver;
pub mod mempool;
pub mod messages;
pub mod net;

#[macro_use]
extern crate serde_big_array;
big_array! { BigArray; }

#[macro_use]
extern crate failure;

fn main() {
    println!("Hello, world!");
}
