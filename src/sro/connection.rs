#![allow(dead_code)]


use std::io::prelude::*;
use std::net::{TcpStream};
use std::io::{Result, Error, ErrorKind};

pub struct Connection {
	stream : Option<TcpStream>,
}

impl Connection {
	pub fn new(host: String, prt : u16) -> Result<Connection> {
		let mut con = Connection {
			stream : None
		};
		let stream = try!(TcpStream::connect((&*host, prt)));
		con.stream = Some(stream);
		Ok(con)
	}


	pub fn receive(&mut self) -> Result<Vec<u8>> {
		match self.stream.as_mut() {
			Some(ref mut stream) =>  {
				//Start reading
				let mut buff : [u8; 128] = [0; 128];
				let size = try!(stream.read(&mut buff));
				if size == 0 {
					return Err(Error::new(ErrorKind::Other, "Connection closed!"));
				}
				return Ok(buff[0..size].to_vec())
			},
			None => {
				println!("Not connected.");
				return Err(Error::new(ErrorKind::Other, "Not connected!"));
			}
		}
	}
	
	pub fn send(&mut self, buffer : Vec<u8>) -> Result<()> {
		match self.stream.as_mut() {
			Some(ref mut stream) =>  {
				let size = try!(stream.write(&buffer[..]));
				if size != buffer.len() {
					return Err(Error::new(ErrorKind::Other, "Did not write the entire buffer."));
				}
				return Ok(());
			},
			None => {
				println!("Not connected.");
				return Err(Error::new(ErrorKind::Other, "Not connected!"));
			}
		}
	}
}