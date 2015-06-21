#![allow(dead_code)]

use std::fmt;
use sro::packetwriter::PacketWriter;
use sro::packetreader::PacketReader;


#[derive(Clone)]
pub struct Packet {
	m_opcode : u16,
	m_writer : Option<PacketWriter>,
	m_reader : Option<PacketReader>,
	m_encrypted : bool,
	m_massive : bool,
	m_locked : bool,
	m_reader_bytes : Option<Vec<u8>>
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "[{:x}] Length {}", self.m_opcode, 0);
    }
}

impl Packet {
	pub fn new(opcode : u16) -> Packet {
		Packet {
			m_opcode : opcode,
			m_massive : false,
			m_encrypted : false,
			m_locked : false,
			m_writer : Some(PacketWriter::new()),
			m_reader : None,
			m_reader_bytes : None
		}
	}
	
	pub fn new_enc(opcode : u16, encrypted : bool) -> Packet {
		Packet {
			m_opcode : opcode,
			m_massive : false,
			m_encrypted : encrypted,
			m_locked : false,
			m_writer : Some(PacketWriter::new()),
			m_reader : None,
			m_reader_bytes : None
		}
	}
	
	pub fn new_enc_mass(opcode : u16, encrypted : bool, massive : bool) -> Packet {
		Packet {
			m_opcode : opcode ,
			m_massive : massive,
			m_encrypted : encrypted,
			m_locked : false,
			m_writer : Some(PacketWriter::new()),
			m_reader : None,
			m_reader_bytes : None
		}
	}
	
	pub fn new_enc_mass_bytes(opcode : u16, encrypted : bool, massive : bool, bytes : Vec<u8>) -> Packet {
		let mut p = Packet {
			m_opcode : opcode,
			m_massive : massive,
			m_encrypted : encrypted,
			m_locked : false,
			m_writer : Some(PacketWriter::new()),
			m_reader : None,
			m_reader_bytes : None
		};
		p.write_bytes(bytes);
		return p;
	} 
	
	pub fn get_bytes(&mut self) -> Option<Vec<u8>> {
		if self.m_locked {
			//return Vec::<u8>::new();
			return self.m_reader_bytes.clone();
		}
		
		match self.m_writer {
			Some(ref mut writer) => Some(writer.get_bytes()),
			None => None
		}
	}
	
	pub fn opcode(&self) -> u16 {
		self.m_opcode
	}
	
	pub fn massive(&self) -> bool {
		self.m_massive
	}
	
	pub fn encrypted(&self) -> bool {
		self.m_encrypted
	}
	
	pub fn lock(&mut self) {
		if !self.m_locked {
			let bytes = match self.m_writer {
				Some(ref mut writer) => writer.get_bytes(),
				None => panic!("Writer == None")
			};
			self.m_reader = Some(PacketReader::new(bytes));
			self.m_writer = None;
			self.m_locked = true;
		}	
	}
	
	pub fn write_bytes(&mut self, bytes : Vec<u8>) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_bytes(bytes),
			None => panic!("Writer == None")
		}
	} 
	
	pub fn write_u8(&mut self, val : u8) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_u8(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_u16(&mut self, val : u16) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_u16(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_u32(&mut self, val : u32) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_u32(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_u64(&mut self, val : u64) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_u64(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_i16(&mut self, val : i16) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_i16(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_i32(&mut self, val : i32) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_i32(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_i64(&mut self, val : i64) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_i64(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_f32(&mut self, val : f32) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_f32(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_f64(&mut self, val : f64) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_f64(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn write_ascii(&mut self, val : String) {
		match self.m_writer {
			Some(ref mut writer) => writer.write_ascii(val),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_u8(&mut self) -> u8 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_u8(),
			None => panic!("Writer == None")
		}	
	}
	
	pub fn read_u16(&mut self) -> u16 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_u16(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_u32(&mut self) -> u32 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_u32(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_u64(&mut self) -> u64 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_u64(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_i16(&mut self) -> i16 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_i16(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_i32(&mut self) -> i32 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_i32(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_i64(&mut self) -> i64 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_i64(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_f32(&mut self) -> f32 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_f32(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_f64(&mut self) -> f64 {
		match self.m_reader {
			Some(ref mut reader) => reader.read_f64(),
			None => panic!("Writer == None")
		}
	}
	
	pub fn read_ascii(&mut self) -> String {
		match self.m_reader {
			Some(ref mut reader) => reader.read_ascii(),
			None => panic!("Writer == None")
		}
	}
}