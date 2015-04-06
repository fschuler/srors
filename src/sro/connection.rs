use std::io::prelude::*;
use std::net::TcpStream;
use std::io::{Result, Error, ErrorKind};

pub struct Connection {
	hostname : &'static str,
	port : u16,
	stream : Option<TcpStream>,
}

impl Connection {
	pub fn new(host: &'static str, prt : u16) -> Connection {
		Connection {
			hostname : host,
			port : prt,
			stream : None
		}
	}

	pub fn connect(&mut self) -> Result<()> {
		//Create connection
		let stream = try!(TcpStream::connect((self.hostname, self.port)));
		self.stream = Some(stream);
		Ok(())
	}

	pub fn begin_receive(&mut self) -> Result<()> {
		match self.stream.as_mut() {
			Some(ref mut stream) =>  {
				//Start reading
				let mut buff : [u8; 128] = [0; 128];

				let size = try!(stream.read(&mut buff));
				println!("{:?}",buff[0..size].as_ref());
				return Ok(())
			},
			None => {
				println!("Not connected.");
				return Err(Error::new(ErrorKind::Other, "Not connected!"));
			}
		}
	}
}