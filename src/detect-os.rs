/// Small test binary for testing OS detection
extern crate os_info;

fn main() {
    let info = os_info::get();
    println!("OS type: {:?}", os_info::get());
    println!("Type: {}", info.os_type());
    println!("Version: {}", info.version());
}