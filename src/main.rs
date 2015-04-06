use std::fmt;
use sro::connection::Connection;
use sro::blowfish::Blowfish;

extern crate byteorder;

mod sro;

struct Packet {
    length : u16,
    opcode : u16,
}


impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "[{:x}] Length {}", self.opcode, self.length);
    }
}

fn main() {
    println!("Hello, world!");

    let p = Packet { length : 37, opcode : 0x5000 };
    println!("{}",p);

    let mut con = Connection::new("gwgt1.joymax.com",15779);

    match con.connect() {
        Ok(()) => println!("Sucessfully connected."),
        Err(err) => {
            println!("Could not connect : {}", err);
            return
        }
    };

    match con.begin_receive() {
        Ok(()) => println!("Started receiving data."),
        Err(err) => {
            println!("Could not start receiving : {}", err);
            return;
        }
    };

    let key : [u8;8] = [1,2,3,4,5,6,7,8];

    let mut blowfish = Blowfish::new();
    blowfish.initialize(&key,0,8);
}