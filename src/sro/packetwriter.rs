#![allow(dead_code)]

use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Cursor;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Result;

#[derive(Clone)]
pub struct PacketWriter {
	m_writer : Cursor<Vec<u8>>
}

impl PacketWriter {
	pub fn new() -> PacketWriter {
		PacketWriter {
			m_writer : Cursor::new(Vec::new())
		}
	}
	
	pub fn write_bytes(&mut self, data: Vec<u8>) {
		for b in data {
			self.write_u8(b);
		}
	}
	
	pub fn write_u8(&mut self, val : u8) {
		self.m_writer.write_u8(val).unwrap();
	}
	
	pub fn write_u16(&mut self, val : u16) {
		self.m_writer.write_u16::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_u32(&mut self, val : u32) {
		self.m_writer.write_u32::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_u64(&mut self, val : u64) {
		self.m_writer.write_u64::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_i16(&mut self, val : i16) {
		self.m_writer.write_i16::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_i32(&mut self, val : i32) {
		self.m_writer.write_i32::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_i64(&mut self, val : i64) {
		self.m_writer.write_i64::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_f32(&mut self, val : f32) {
		self.m_writer.write_f32::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_f64(&mut self, val : f64) {
		self.m_writer.write_f64::<LittleEndian>(val).unwrap();
	}
	
	pub fn write_ascii(&mut self, val : String) {
		self.write_u16(val.len() as u16);
		for b in val.as_bytes() {
			self.write_u8(*b);
		}
	}
	
	pub fn seek(&mut self, pos : SeekFrom) -> Result<u64>{
		self.m_writer.seek(pos)
	}
	
	pub fn get_bytes(&mut self) -> Vec<u8> {
		self.m_writer.clone().into_inner()
	}
}