#![allow(dead_code)]

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

#[derive(Clone)]
pub struct PacketReader {
	m_reader : Cursor<Vec<u8>>
}

impl PacketReader {
	pub fn new(bytes : Vec<u8>) -> PacketReader {
		PacketReader {
			m_reader : Cursor::new(bytes)
		}
	}
	pub fn read_bytes(&mut self, count : usize) -> Vec<u8> {
		let mut tmp = Vec::<u8>::with_capacity(count);
		for _ in 0..count {
			tmp.push(self.read_u8());
		}
		return tmp;
	}
	
	pub fn read_u8(&mut self) -> u8 {
		self.m_reader.read_u8().unwrap()	
	}
	
	pub fn read_u16(&mut self) -> u16 {
		self.m_reader.read_u16::<LittleEndian>().unwrap()
	}
	
	pub fn read_u32(&mut self) -> u32 {
		self.m_reader.read_u32::<LittleEndian>().unwrap()
	}
	
	pub fn read_u64(&mut self) -> u64 {
		self.m_reader.read_u64::<LittleEndian>().unwrap()
	}
	
	pub fn read_i16(&mut self) -> i16 {
		self.m_reader.read_i16::<LittleEndian>().unwrap()
	}
	
	pub fn read_i32(&mut self) -> i32 {
		self.m_reader.read_i32::<LittleEndian>().unwrap()
	}
	
	pub fn read_i64(&mut self) -> i64 {
		self.m_reader.read_i64::<LittleEndian>().unwrap()
	}
	
	pub fn read_f32(&mut self) -> f32 {
		self.m_reader.read_f32::<LittleEndian>().unwrap()
	}
	
	pub fn read_f64(&mut self) -> f64 {
		self.m_reader.read_f64::<LittleEndian>().unwrap()
	}
	
	pub fn read_ascii(&mut self) -> String {
		let len = self.read_u16();
		let mut buff = Vec::<u8>::new();
		for _ in 0..len {
			buff.push(self.read_u8());
		}
		let str = match String::from_utf8(buff) {
        	Ok(v) => v,
        	Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    	};
		return str;
	}
}