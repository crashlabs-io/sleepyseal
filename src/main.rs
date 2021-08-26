pub mod base_types;
pub mod core_state;
pub mod core_types;
pub mod driver;
pub mod messages;
pub mod mempool;

#[macro_use]
extern crate serde_big_array;
big_array! { BigArray; }

fn main() {
    println!("Hello, world!");
}
