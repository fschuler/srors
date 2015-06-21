#![allow(dead_code)]
use std::io::Cursor;
use std::io::SeekFrom;
use std::mem;
use std::num::Wrapping;

use byteorder::{LittleEndian, ReadBytesExt};

use sro::packet::Packet;
use sro::blowfish::Blowfish;
use sro::blowfish::get_output_length;
use sro::packetreader::PacketReader;
use sro::packetwriter::PacketWriter;

pub struct Security {
	m_value_x : u32,
	m_value_g : u32,
	m_value_p : u32,
	m_value_a : u32,
	m_value_b : u32,
	m_value_k : u32,
	m_seed_count : u32,
	m_crc_seed : u32,
	m_initial_blowfish_key : u64,
	m_handshake_blowfish_key : u64,
	m_count_byte_seeds : [u8; 3],
	m_client_key : u64,
	m_challenge_key : u64,
	
	m_client_security : bool,
	m_security_flag : u8,
	m_security_flags : SecurityFlags,
	m_accepted_handshake : bool,
	m_started_handshake : bool,
	
	m_identity_flag : u8,
	m_identity_name : String,
	
	m_incoming_packets : Vec<Packet>,
	m_outgoing_packets : Vec<Packet>,
	
	m_massive_count : u16,
	m_massive_packet : Packet,
	
	m_enc_opcodes : Vec<u16>,
	
	m_global_security_table :  [u32; 0x10000],
	
	m_blowfish : Blowfish
}

impl Security {
	pub fn new() -> Security {
		Security {
			m_value_x : 0,
			m_value_g : 0,
			m_value_p : 0,
			m_value_a : 0,
			m_value_b : 0,
			m_value_k : 0,
			m_seed_count : 0,
			m_crc_seed : 0,
			m_initial_blowfish_key : 0,
			m_handshake_blowfish_key : 0,
			m_count_byte_seeds : [0u8;3],
			m_client_key : 0,
			m_challenge_key : 0,
			
			m_client_security : false,
			m_security_flag : 0,
			m_security_flags : to_security_flags(0),
			m_accepted_handshake : false,
			m_started_handshake : false,
			m_identity_flag : 0,
			m_identity_name : "SR_Client".to_string(),
			
			m_outgoing_packets : Vec::<Packet>::new(),
			m_incoming_packets : Vec::<Packet>::new(),
			
			m_massive_count : 0,
			m_massive_packet : Packet::new(0),
			
			m_enc_opcodes : Vec::<u16>::new(),
			m_global_security_table : generate_security_table(),
			m_blowfish : Blowfish::new()
		}
	}
	
	
	pub fn change_identity(&mut self, name : String, flag : u8) {
		self.m_identity_name = name;
		self.m_identity_flag = flag;	
	}
	
	
	fn handshake(&mut self, packet_opcode : u16, packet_data : &mut PacketReader, packet_encrypted : bool) {
		if packet_encrypted {
			panic!("[Security::handshake] Received an illogical encrypted handshake packet");
		}
		
		if self.m_client_security {
			if self.m_security_flags.handshake == 0 {
				if packet_opcode == 0x9000 {
					if self.m_accepted_handshake {
						panic!("[Security::handshake] Received an illogical handshake packet (duplicate 0x9000).");
					}
					self.m_accepted_handshake = true;
					return;
				}
				
				if packet_opcode == 0x5000 {
					panic!("[Security::handshake] Received an illogical handshake packet (0x5000 with no handshake).");
				}
				else
				{
					panic!("[Security::handshake] Received an illogical handshake packet (programmer error).");	
				}
			}
			else {
				if packet_opcode == 0x9000 {
					if !self.m_started_handshake {
						panic!("[Security::handshake] Received an illogical handshake packet (out of order 0x9000).");
					}
					if self.m_accepted_handshake {
						panic!("[Security::handshake] Received an illogical handshake packet (duplicate 0x9000).");
					}
					self.m_accepted_handshake = true;
					return;
				}
				
				if packet_opcode == 0x5000 {
					if self.m_started_handshake {
						panic!("[Security::handshake] Received an illogical handshake packet (duplicate 0x5000).");
					}
					self.m_started_handshake = true;
				}
				else {
					panic!("[Security::handshake] Received an illogical handshake packet (programmer error).")
				}
			}

			let mut key_array;
			let mut tmp_bytes : Vec<u8>;
			
			self.m_value_b = packet_data.read_u32();
			self.m_client_key = packet_data.read_u64();
			
			self.m_value_k = g_pow_x_mod_p(self.m_value_p, self.m_value_x, self.m_value_b);
			
			key_array = make_long_long(self.m_value_a, self.m_value_b);
			key_transform_value(&mut key_array, self.m_value_k, lobyte(loword(self.m_value_k)) & 0x03u8);
			
			unsafe {
				let key = mem::transmute::<u64,[u8;8]>(key_array);
				self.m_blowfish.initialize(&key);
			}
			
			unsafe {
				let client_key_arr = mem::transmute::<u64,[u8;8]>(self.m_client_key);
				tmp_bytes = self.m_blowfish.decode(client_key_arr.to_vec());
				let mut fixed : [u8;8] = [0;8];
				for i in 0..8 {
					fixed[i] = tmp_bytes[i];
				}
				self.m_client_key = mem::transmute::<[u8;8],u64>(fixed);
			}
			
			key_array = make_long_long(self.m_value_b, self.m_value_a);
			key_transform_value(&mut key_array, self.m_value_k, lobyte(loword(self.m_value_b)) & 0x07u8);
			if self.m_client_key != key_array {
				panic!("[Security::handshake] Client signature error.");
			}
			
			key_array = make_long_long(self.m_value_a, self.m_value_b);
			key_transform_value(&mut key_array, self.m_value_k, lobyte(loword(self.m_value_k)) & 0x03u8);
			unsafe {
				let key_arr = mem::transmute::<u64, [u8;8]>(key_array);
				self.m_blowfish.initialize(&key_arr);
			}
			
			self.m_challenge_key = make_long_long(self.m_value_a, self.m_value_b);
			key_transform_value(&mut self.m_challenge_key, self.m_value_k, lobyte(loword(self.m_value_a)) & 0x07u8);
			
			unsafe {
				let challenge_key_arr = mem::transmute::<u64, [u8;8]>(self.m_challenge_key);
				tmp_bytes = self.m_blowfish.encode(challenge_key_arr.to_vec());
				let mut fixed : [u8;8] = [0;8];
				for i in 0..8 {
					fixed[i] = tmp_bytes[i];
				}
				self.m_challenge_key = mem::transmute::<[u8;8], u64>(fixed);
				
				key_transform_value(&mut self.m_handshake_blowfish_key, self.m_value_k, 0x3);
				let handshake_key = mem::transmute::<u64, [u8;8]>(self.m_handshake_blowfish_key);
				self.m_blowfish.initialize(&handshake_key);
			}
			
			let tmp_flags = SecurityFlags {
				none : 0,
				blowfish : 0,
				handshake : 0,
				security_bytes : 0,
				handshake_response : 1,
				_6 : 0,
				_7 : 0,
				_8 : 0
			};
			let tmp_flag = from_security_flags(&tmp_flags);
			
			let mut response = Packet::new(0x5000);
			response.write_u8(tmp_flag);
			response.write_u64(self.m_challenge_key);
			
			self.m_outgoing_packets.push(response);
		}
		else {
			if packet_opcode != 0x5000 {
				panic!("[Security::handshake] Received an illogical handshake packet (programmer error).");
			}
			
			let flag = packet_data.read_u8();
			
			let flags = to_security_flags(flag);
			
			if self.m_security_flag == 0 {
				self.m_security_flag = flag.clone();
				self.m_security_flags = flags.clone();
			}
			
			if flags.blowfish == 1 {
				self.m_initial_blowfish_key = packet_data.read_u64();
				unsafe {
					let key = mem::transmute::<u64,[u8;8]>(self.m_initial_blowfish_key);
					self.m_blowfish.initialize(&key);
				}
			}
			
			if flags.security_bytes == 1 {
				self.m_seed_count = packet_data.read_u32();
				self.m_crc_seed = packet_data.read_u32();
				let seed_count = self.m_seed_count;
				self.setup_count_byte(seed_count);
			}
			
			if flags.handshake == 1 {
				self.m_handshake_blowfish_key = packet_data.read_u64();
				self.m_value_g = packet_data.read_u32();
				self.m_value_p = packet_data.read_u32();
				self.m_value_a = packet_data.read_u32();
				
				self.m_value_x = next_u32() & 0x7fffffff;
				
				self.m_value_b = g_pow_x_mod_p(self.m_value_p, self.m_value_x, self.m_value_g);
				self.m_value_k = g_pow_x_mod_p(self.m_value_p, self.m_value_x, self.m_value_a);
			
				let mut key_array = make_long_long(self.m_value_a, self.m_value_b);
				key_transform_value(&mut key_array, self.m_value_k, lobyte(loword(self.m_value_k)) & 0x03u8);
			
				unsafe {
					let key = mem::transmute::<u64,[u8;8]>(key_array);
					self.m_blowfish.initialize(&key);
				}
				
				self.m_client_key = make_long_long(self.m_value_b, self.m_value_a);
				key_transform_value(&mut self.m_client_key, self.m_value_k, lobyte(loword(self.m_value_b)) & 0x07u8);
			
				unsafe {
					let client_key = mem::transmute::<u64,[u8;8]>(self.m_client_key);
					let tmp_bytes = self.m_blowfish.encode(client_key.to_vec());
					let mut fixed : [u8;8] = [0;8];
 					for i in 0..8 {
						fixed[i] = tmp_bytes[i];
					}
					self.m_client_key = mem::transmute::<[u8;8], u64>(fixed);
				}
			}
			
			if flags.handshake_response == 1 {
				self.m_challenge_key = packet_data.read_u64();
				
				let mut expected_challenge_key = make_long_long(self.m_value_a, self.m_value_b);
				key_transform_value(&mut expected_challenge_key, self.m_value_k, lobyte(loword(self.m_value_a)) & 0x07u8);
			
				unsafe {
					let client_key = mem::transmute::<u64,[u8;8]>(expected_challenge_key);
					let tmp_bytes = self.m_blowfish.encode(client_key.to_vec());
					let mut fixed : [u8;8] = [0;8];
					for i in 0..8 {
						fixed[i] = tmp_bytes[i];
					}
					expected_challenge_key = mem::transmute::<[u8;8], u64>(fixed);
				}
				
				if self.m_challenge_key != expected_challenge_key {
					panic!("[Security::handshake] Server signature error.");
				}
				
				key_transform_value(&mut self.m_handshake_blowfish_key, self.m_value_k, 0x03u8);
				unsafe {
					let blowfish_key = mem::transmute::<u64,[u8;8]>(self.m_handshake_blowfish_key);
					self.m_blowfish.initialize(&blowfish_key);
				}
			}
			
			if flags.handshake == 1 && 
					self.m_security_flags.handshake_response == 0 {
				
				if self.m_started_handshake || self.m_accepted_handshake {
					panic!("[Security::handshake] Received an illogical handshake packet (duplicate 0x5000).");
				}
				
				let mut response = Packet::new(0x5000);
				response.write_u32(self.m_value_b);
				response.write_u64(self.m_client_key);
				
				self.m_outgoing_packets.insert(0, response);
				
				self.m_started_handshake = true;
			} else {
				if self.m_accepted_handshake {
					panic!("[Security::handshake] Received an illogical handshake packet (duplicate 0x5000).");
				}
				
				let response1 = Packet::new(0x9000);
				
				let mut response2 = Packet::new_enc_mass(0x2001, true, false);
				response2.write_ascii(self.m_identity_name.clone());
				response2.write_u8(self.m_identity_flag);
				
				self.m_outgoing_packets.insert(0, response2);
				self.m_outgoing_packets.insert(0, response1);
				
				self.m_started_handshake = true;
				self.m_accepted_handshake = true;
			}
		}
		
	}
	
	fn generate_security(&mut self, flags : SecurityFlags) {
		self.m_security_flags = flags;
		self.m_security_flag = from_security_flags(&self.m_security_flags);
		self.m_client_security = true;
		
		let mut response = Packet::new(0x5000);
		response.write_u8(self.m_security_flag);
		
		if self.m_security_flags.blowfish == 1 {
			self.m_initial_blowfish_key = next_u64();
			response.write_u64(self.m_initial_blowfish_key);
		}
		
		if self.m_security_flags.security_bytes == 1 {
			self.m_seed_count = next_u8() as u32;
			let seed_count = self.m_seed_count;
			self.setup_count_byte(seed_count);
			self.m_crc_seed = next_u8() as u32;
			
			response.write_u32(self.m_seed_count);
			response.write_u32(self.m_crc_seed);
		} 
		if self.m_security_flags.handshake == 1 {
			self.m_handshake_blowfish_key = next_u64();
			self.m_value_x = next_u32() & 0x7fffffff;
			self.m_value_g = next_u32() & 0x7fffffff;
			self.m_value_p = next_u32() & 0x7fffffff;
			self.m_value_a = g_pow_x_mod_p(self.m_value_p, self.m_value_x, self.m_value_g);
			
			response.write_u64(self.m_handshake_blowfish_key);
			response.write_u32(self.m_value_g);
			response.write_u32(self.m_value_p);
			response.write_u32(self.m_value_a);
		}
		
		self.m_outgoing_packets.push(response);
	}
	
	
	fn format_packet(&mut self, opcode : u16, data : &Vec<u8>, encrypted : bool) -> Vec<u8> {
		if data.len() >= 0x8000 {
			panic!("[Security::format_packet] Payload is too large!");
		}
		
		let data_length = data.len() as u16;
		
		let mut writer = PacketWriter::new();
		writer.write_u16(data_length);
		writer.write_u16(opcode);
		writer.write_u16(0);
		writer.write_bytes(data.clone());

		
		if encrypted && (self.m_security_flags.blowfish == 1 || (self.m_security_flags.security_bytes == 1 && self.m_security_flags.blowfish == 0)) {
			let seed_index = match writer.seek(SeekFrom::Current(0)) {
				Ok(pos) => pos,
				Err(e) => panic!("{}",e)
			};
			
			let packet_size = (data_length | 0x8000) as u16;
			
			match writer.seek(SeekFrom::Start(0)) {
				Ok(_) => 0,
				Err(e) => panic!("{}",e)
			};
			
			writer.write_u16(packet_size);
			
			match writer.seek(SeekFrom::Start(seed_index)) {
				Ok(_) => 0,
				Err(e) => panic!("{}",e)
			};
		}
		
		if self.m_client_security == false && self.m_security_flags.security_bytes == 1  {
			let seed_index = match writer.seek(SeekFrom::Current(0)) {
				Ok(pos) => pos,
				Err(e) => panic!("{}",e)
			};
			
			let sb1 = self.generate_count_byte(true);
			match writer.seek(SeekFrom::Start(4)) {
				Ok(_) => 0,
				Err(e) => panic!("{}",e)
			};
			writer.write_u8(sb1);
			
			let bytes = writer.get_bytes();
			let len = bytes.len();
			let sb2 = self.generate_check_byte(bytes,0,len);
			match writer.seek(SeekFrom::Start(5)) {
				Ok(_) => 0,
				Err(e) => panic!("{}",e)
			};
			writer.write_u8(sb2);
			
			match writer.seek(SeekFrom::Start(seed_index)) {
				Ok(_) => 0,
				Err(e) => panic!("{}",e)
			};
		}
		
		if encrypted && self.m_security_flags.blowfish == 1 {
			let raw_data = writer.get_bytes();
			let encrypted_data = self.m_blowfish.encode(raw_data[2..].to_vec());
			
			match writer.seek(SeekFrom::Start(2)) {
				Ok(_) => 0,
				Err(e) => panic!("{}",e)
			};
			
			writer.write_bytes(encrypted_data);
		} else {
			if encrypted && (self.m_security_flags.security_bytes == 1 && self.m_security_flags.blowfish == 0) {
				let seed_index = match writer.seek(SeekFrom::Current(0)) {
					Ok(pos) => pos,
					Err(e) => panic!("{}",e)
				};
				
				match writer.seek(SeekFrom::Start(0)) {
					Ok(_) => 0,
					Err(e) => panic!("{}",e)
				};
				writer.write_u16(data_length);
				
				match writer.seek(SeekFrom::Start(seed_index)) {
					Ok(_) => 0,
					Err(e) => panic!("{}",e)
				};
			}
		}
		
		return writer.get_bytes();
	}
	
	fn has_packet_to_send(&self) -> bool {
		if self.m_outgoing_packets.len() == 0 {
			return false;
		}
		
		if self.m_accepted_handshake {
			return true;
		}
		
		let ref packet = self.m_outgoing_packets[0];
		if packet.opcode() == 0x5000 || packet.opcode() == 0x9000 {
			return true;
		}
		
		return false;
	}
	
	pub fn recv(&mut self, raw_buffer : Vec<u8>) {

		let mut working_buffer = raw_buffer;
		
		while working_buffer.len() > 0 {
			let mut packet_encrypted = false;
			let mut packet_size = (working_buffer[1] as u16) << 8 | working_buffer[0] as u16;

			if packet_size & 0x8000 > 0 {
				if self.m_security_flags.blowfish == 1 {
					packet_size &= 0x7fff;
					packet_size = 2 + get_output_length((packet_size + 4) as usize) as u16;
					packet_encrypted = true;
				} else {
					packet_size &= 0x7fff;
				}
			}
			else {
				packet_size += 6;
			}
			
			
			let tmp_working_buffer = working_buffer.clone();
			
			
			
			let (packet_buff, remaining_buffer) = tmp_working_buffer.split_at(packet_size as usize);
			working_buffer = remaining_buffer.to_vec();
			let mut packet_buffer = packet_buff.to_vec();
		

			
			if packet_encrypted {
				
				let decrypted = self.m_blowfish.decode(packet_buff[2..].to_vec());
				
				
				let mut new_buffer = Vec::<u8>::with_capacity(packet_size as usize);		
				new_buffer.push((packet_size & 0xff) as u8);
				new_buffer.push((packet_size >> 8) as u8);
				
				for b in decrypted {
					new_buffer.push(b);
				}
				packet_buffer = new_buffer;
			}
			
			let mut packet_data = PacketReader::new(packet_buffer.clone());
			packet_size = packet_data.read_u16();
			let packet_opcode = packet_data.read_u16();
			let packet_security_count = packet_data.read_u8();
			let packet_security_crc = packet_data.read_u8();
			
			if self.m_client_security {
				if self.m_security_flags.security_bytes == 1 {
					let expected_count = self.generate_count_byte(true);
					if packet_security_count != expected_count {
						panic!("[Security::recv] Count byte mismatch.");
					}
					
					if packet_encrypted || (self.m_security_flags.security_bytes == 1 && self.m_security_flags.blowfish == 0) {
						if packet_encrypted || self.m_enc_opcodes.contains(&packet_opcode) {
							packet_size |= 0x8000;
							packet_buffer[0] = packet_size as u8;
							packet_buffer[1] = (packet_size >> 8) as u8;
						}
					}
					
					packet_buffer[5] = 0;
					let len = packet_buffer.len();
					let expected_crc = self.generate_check_byte(packet_buffer.clone(),0,len);
					
					if packet_security_crc != expected_crc {
						panic!("[Security::recv] CRC byte mismatch.");
					}
					packet_buffer[4] = 0;
					
					if packet_encrypted || (self.m_security_flags.security_bytes == 1 && self.m_security_flags.blowfish == 0) {
						if packet_encrypted || self.m_enc_opcodes.contains(&packet_opcode) {
							packet_size &= 0x7fff;
							packet_buffer[0] = packet_size as u8;
							packet_buffer[1] = (packet_size >> 8) as u8;
						}
					}
				}
			}
			
			if packet_opcode == 0x5000 || packet_opcode == 0x9000 {
				self.handshake(packet_opcode, &mut packet_data, packet_encrypted);
			
				let mut packet = Packet::new_enc_mass_bytes(packet_opcode, packet_encrypted, false, packet_buffer[6..].to_vec());
				packet.lock();
				self.m_incoming_packets.push(packet);
			} else {
				if self.m_client_security {
					if !self.m_accepted_handshake {
						panic!("[Security::recv] The client has not accepted the handshake.");
					}
				}
				
				if packet_opcode == 0x600D {
					let mode = packet_data.read_u8();
					if mode == 1 {
						self.m_massive_count = packet_data.read_u16();
						let contained_packet_opcode = packet_data.read_u16();
						self.m_massive_packet = Packet::new_enc_mass(contained_packet_opcode, packet_encrypted, true);
					} else {
						self.m_massive_packet.write_bytes(packet_data.read_bytes((packet_size - 1) as usize));
						self.m_massive_count = self.m_massive_count - 1;
						if self.m_massive_count == 0 {
							self.m_massive_packet.lock();
							self.m_incoming_packets.push(self.m_massive_packet.clone());
						}
					}
				} else {
					let mut packet = Packet::new_enc_mass_bytes(packet_opcode, packet_encrypted, false, packet_buffer[6..].to_vec());
					packet.lock();
					self.m_incoming_packets.push(packet);
				}
			}
		}
	}
	
	pub fn transfer_incoming(&mut self) -> Vec<Packet> {
		let mut packets = Vec::new();
		while let Some(p) = self.m_incoming_packets.pop() {
			packets.push(p);
		}
		return packets;
	}
	
	
	pub fn transfer_outgoing(&mut self) -> Vec<(Vec<u8>, Packet)> {
		let mut buffers = Vec::new();
		
		while self.has_packet_to_send() {
			buffers.push(self.get_packet_to_send());
		}
		
		return buffers;
	}
	
	pub fn send(&mut self, p : Packet) {
		if p.opcode() == 0x5000 || p.opcode() == 0x9000 {
			panic!("Handshake packets can not be sent through this function!");
		}
		
		self.m_outgoing_packets.push(p);
	}
	
	fn get_packet_to_send(&mut self) -> (Vec<u8>, Packet) {
		if self.m_outgoing_packets.len() == 0 {
			panic!("[Security::get_packet_to_send] No packes are available to send.");
		}
		
		let mut packet = self.m_outgoing_packets.remove(0);
		
		if packet.massive() {
			panic!("Not implemented");
		} else {
			let mut encrypted = packet.encrypted();
			if self.m_client_security {
				if self.m_enc_opcodes.contains(&packet.opcode()) {
					encrypted = true;
				}
			}
			let opcode = packet.opcode();
			let bytes = match packet.get_bytes() {
				Some(buff) => buff,
				None => panic!("Cannot get packet bytes")
			};
			
			let raw_bytes = self.format_packet(opcode, &bytes, encrypted);
			return (raw_bytes, packet)
		}
	}
	
	fn generate_count_byte(&mut self, update : bool) -> u8 {
		let mut result : Wrapping<u8>;
		result = Wrapping(self.m_count_byte_seeds[2]) * (!Wrapping(self.m_count_byte_seeds[0]) + Wrapping(self.m_count_byte_seeds[1]));
		result = result ^ (result >> 4);
		if update {
			self.m_count_byte_seeds[0] = result.0;
		}
		return result.0;
	}
	
	fn generate_check_byte(&mut self, stream : Vec<u8>, offset : usize, len : usize) -> u8 {
		let mut checksum = 0xffffffffu32;
		let moddedseed = (self.m_crc_seed << 8) as u32;
		
		for x in offset .. (offset + len) {
			checksum = (checksum >> 8) ^ self.m_global_security_table[(moddedseed + (((stream[x] as u32) ^ checksum) & 0xffu32)) as usize];
		}
		
		return (((checksum >> 24) & 0xff) + ((checksum >> 8) & 0xff) + ((checksum >> 16) & 0xff) + (checksum & 0xff)) as u8;
	}
	
	fn setup_count_byte(&mut self, s : u32) {
		let mut seed = s;
		if seed == 0  {
			seed = 0x9ABFB3B6
		}
		
		let mut m = seed;
		let m1 = generate_value(&mut m);
		let m2 = generate_value(&mut m);
		let m3 = generate_value(&mut m);
		generate_value(&mut m);
		
		let mut byte1 = ((m & 0xff) ^ (m3 & 0xff)) as u8;
		let mut byte2 = ((m1 & 0xff) ^ (m2 & 0xff)) as u8;
		if byte1 == 0 {
			byte1 = 1
		}
		if byte2 == 0 {
			byte2 = 1
		}
		
		self.m_count_byte_seeds[0] = (byte1 ^ byte2) as u8;
		self.m_count_byte_seeds[1] = byte2;
		self.m_count_byte_seeds[2] = byte1;
	}
}

fn key_transform_value(val : &mut u64, key : u32, key_byte : u8) {
	unsafe {
		let mut stream = mem::transmute::<u64,[u8;8]>(*val);
		stream[0] ^= (Wrapping(stream[0]) + Wrapping(lobyte(loword(key))) + Wrapping(key_byte)).0;
		stream[1] ^= (Wrapping(stream[1]) + Wrapping(hibyte(loword(key))) + Wrapping(key_byte)).0;
		stream[2] ^= (Wrapping(stream[2]) + Wrapping(lobyte(hiword(key))) + Wrapping(key_byte)).0;
		stream[3] ^= (Wrapping(stream[3]) + Wrapping(hibyte(hiword(key))) + Wrapping(key_byte)).0;
		stream[4] ^= (Wrapping(stream[4]) + Wrapping(lobyte(loword(key))) + Wrapping(key_byte)).0;
		stream[5] ^= (Wrapping(stream[5]) + Wrapping(hibyte(loword(key))) + Wrapping(key_byte)).0;
		stream[6] ^= (Wrapping(stream[6]) + Wrapping(lobyte(hiword(key))) + Wrapping(key_byte)).0;
		stream[7] ^= (Wrapping(stream[7]) + Wrapping(hibyte(hiword(key))) + Wrapping(key_byte)).0;
		*val = mem::transmute::<[u8;8],u64>(stream);
	}
}

fn generate_value(val : &mut u32) -> u32 {
	let mut value = *val;
	for _ in 0..32 {
		value = (((((((((((value >> 2) ^ value) >> 2) ^ value) >> 1) ^ value) >> 1) ^ value) >> 1) ^ value) & 1u32) | ((((value & 1u32) << 31) | (value >> 1u32)) & 0xFFFFFFFEu32);
	}
	*val = value;
	return *val;
}

fn g_pow_x_mod_p(p : u32, x : u32, g : u32) -> u32 {
	let mut result : i64 = 1;
	let mut mult : i64 = g as i64;
	let mut val = x;
	if val == 0 {
		return 1;
	}
	
	while val != 0 {
		if (val & 1) > 0 {
			result = (mult * result) % p as i64;
		}
		val = val >> 1;
		mult = (mult * mult) % p as i64; 
	}
	
	return result as u32;
}

#[derive(Clone)]
struct SecurityFlags {
	pub none : u8,
	pub blowfish : u8,
	pub security_bytes : u8,
	pub handshake : u8,
	pub handshake_response : u8,
	pub _6 : u8,
	pub _7 : u8,
	pub _8 : u8
}

fn from_security_flags(flags : &SecurityFlags) -> u8 {
	return flags.none | flags.blowfish << 1 | flags.security_bytes << 2 | flags.handshake << 3 | flags.handshake_response << 4 | flags._6 << 5 | flags._7 << 6 | flags._8 << 7
}

fn to_security_flags(val : u8) -> SecurityFlags {
	let mut s = SecurityFlags {
		none : 0,
		blowfish : 0,
		security_bytes : 0,
		handshake : 0,
		handshake_response : 0,
		_6 : 0,
		_7 : 0,
		_8 : 0
	};
	let mut value = val;
	s.none = value & 1;
	value >>= 1;
	s.blowfish = value & 1;
	value >>= 1;
	s.security_bytes = value & 1;
	value >>= 1;
	s.handshake = value & 1;
	value >>= 1;
	s.handshake_response = value & 1;
	value >>= 1;
	s._6 = value & 1;
	value >>= 1;
	s._7 = value & 1;
	value >> 1;
	s._8 = value & 1;
	return s;
}

fn next_u64() -> u64 {
	5
}

fn next_u32() -> u32 {
	4
}

fn next_u16() -> u16 {
	3
}

fn next_u8() -> u8 {
	1
}

fn lobyte(a : u16) -> u8 {
	(a & 0xff) as u8
}

fn hibyte(a : u16) -> u8 {
	((a >> 8) & 0xff) as u8
}

fn loword(a : u32) -> u16 {
	(a & 0xffff) as u16
}

fn hiword(a : u32) -> u16 {
	((a >> 16) & 0xffff) as u16
}

fn make_long_long(a : u32, b : u32) -> u64  {
	let a_ = a as u64;
	let b_ = b as u64;
	(b_ << 32 | a_)
}

fn generate_security_table() -> [u32; 0x10000] {
	let mut reader = Cursor::new(BASE_SECURITY_TABLE.as_ref());
	
	
	let mut security_table : [u32; 0x10000] = [0; 0x10000];
	let mut index = 0;
	let mut edi = 0;
	while edi < 1024 {
		let edx = reader.read_u32::<LittleEndian>().unwrap();
		for ecx in 0..256u32 {
			let mut eax = ecx >> 1;
			if (ecx & 1) != 0 {
				eax ^= edx;
			}
			for _ in 0..7 {
				if (eax & 1) != 0 {
					eax >>= 1;
					eax ^= edx;
				}
				else {
					eax >>= 1;
				}
			}
			security_table[index] = eax;
			index += 1;
		}
		edi += 4;
	}
	
	return security_table; 	
}

static BASE_SECURITY_TABLE : [u8;1024] = [
		0xB1, 0xD6, 0x8B, 0x96, 0x96, 0x30, 0x07, 0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99, 
		0x19, 0xC4, 0x6D, 0x07, 0x8F, 0xF4, 0x6A, 0x70, 0x35, 0xA5, 0x63, 0xE9, 0xA3, 0x95, 0x64, 0x9E,
		0x32, 0x88, 0xDB, 0x0E, 0xA4, 0xB8, 0xDC, 0x79, 0x1E, 0xE9, 0xD5, 0xE0, 0x88, 0xD9, 0xD2, 0x97, 
		0x2B, 0x4C, 0xB6, 0x09, 0xBD, 0x7C, 0xB1, 0x7E, 0x07, 0x2D, 0xB8, 0xE7, 0x91, 0x1D, 0xBF, 0x90,
		0x64, 0x10, 0xB7, 0x1D, 0xF2, 0x20, 0xB0, 0x6A, 0x48, 0x71, 0xB1, 0xF3, 0xDE, 0x41, 0xBE, 0x8C, 
		0x7D, 0xD4, 0xDA, 0x1A, 0xEB, 0xE4, 0xDD, 0x6D, 0x51, 0xB5, 0xD4, 0xF4, 0xC7, 0x85, 0xD3, 0x83,
		0x56, 0x98, 0x6C, 0x13, 0xC0, 0xA8, 0x6B, 0x64, 0x7A, 0xF9, 0x62, 0xFD, 0xEC, 0xC9, 0x65, 0x8A, 
		0x4F, 0x5C, 0x01, 0x14, 0xD9, 0x6C, 0x06, 0x63, 0x63, 0x3D, 0x0F, 0xFA, 0xF5, 0x0D, 0x08, 0x8D,
		0xC8, 0x20, 0x6E, 0x3B, 0x5E, 0x10, 0x69, 0x4C, 0xE4, 0x41, 0x60, 0xD5, 0x72, 0x71, 0x67, 0xA2, 
		0xD1, 0xE4, 0x03, 0x3C, 0x47, 0xD4, 0x04, 0x4B, 0xFD, 0x85, 0x0D, 0xD2, 0x6B, 0xB5, 0x0A, 0xA5,
		0xFA, 0xA8, 0xB5, 0x35, 0x6C, 0x98, 0xB2, 0x42, 0xD6, 0xC9, 0xBB, 0xDB, 0x40, 0xF9, 0xBC, 0xAC, 
		0xE3, 0x6C, 0xD8, 0x32, 0x75, 0x5C, 0xDF, 0x45, 0xCF, 0x0D, 0xD6, 0xDC, 0x59, 0x3D, 0xD1, 0xAB,
		0xAC, 0x30, 0xD9, 0x26, 0x3A, 0x00, 0xDE, 0x51, 0x80, 0x51, 0xD7, 0xC8, 0x16, 0x61, 0xD0, 0xBF, 
		0xB5, 0xF4, 0xB4, 0x21, 0x23, 0xC4, 0xB3, 0x56, 0x99, 0x95, 0xBA, 0xCF, 0x0F, 0xA5, 0xB7, 0xB8,
		0x9E, 0xB8, 0x02, 0x28, 0x08, 0x88, 0x05, 0x5F, 0xB2, 0xD9, 0xEC, 0xC6, 0x24, 0xE9, 0x0B, 0xB1, 
		0x87, 0x7C, 0x6F, 0x2F, 0x11, 0x4C, 0x68, 0x58, 0xAB, 0x1D, 0x61, 0xC1, 0x3D, 0x2D, 0x66, 0xB6,
		0x90, 0x41, 0xDC, 0x76, 0x06, 0x71, 0xDB, 0x01, 0xBC, 0x20, 0xD2, 0x98, 0x2A, 0x10, 0xD5, 0xEF, 
		0x89, 0x85, 0xB1, 0x71, 0x1F, 0xB5, 0xB6, 0x06, 0xA5, 0xE4, 0xBF, 0x9F, 0x33, 0xD4, 0xB8, 0xE8,
		0xA2, 0xC9, 0x07, 0x78, 0x34, 0xF9, 0xA0, 0x0F, 0x8E, 0xA8, 0x09, 0x96, 0x18, 0x98, 0x0E, 0xE1, 
		0xBB, 0x0D, 0x6A, 0x7F, 0x2D, 0x3D, 0x6D, 0x08, 0x97, 0x6C, 0x64, 0x91, 0x01, 0x5C, 0x63, 0xE6,
		0xF4, 0x51, 0x6B, 0x6B, 0x62, 0x61, 0x6C, 0x1C, 0xD8, 0x30, 0x65, 0x85, 0x4E, 0x00, 0x62, 0xF2, 
		0xED, 0x95, 0x06, 0x6C, 0x7B, 0xA5, 0x01, 0x1B, 0xC1, 0xF4, 0x08, 0x82, 0x57, 0xC4, 0x0F, 0xF5,
		0xC6, 0xD9, 0xB0, 0x63, 0x50, 0xE9, 0xB7, 0x12, 0xEA, 0xB8, 0xBE, 0x8B, 0x7C, 0x88, 0xB9, 0xFC, 
		0xDF, 0x1D, 0xDD, 0x62, 0x49, 0x2D, 0xDA, 0x15, 0xF3, 0x7C, 0xD3, 0x8C, 0x65, 0x4C, 0xD4, 0xFB,
		0x58, 0x61, 0xB2, 0x4D, 0xCE, 0x51, 0xB5, 0x3A, 0x74, 0x00, 0xBC, 0xA3, 0xE2, 0x30, 0xBB, 0xD4, 
		0x41, 0xA5, 0xDF, 0x4A, 0xD7, 0x95, 0xD8, 0x3D, 0x6D, 0xC4, 0xD1, 0xA4, 0xFB, 0xF4, 0xD6, 0xD3,
		0x6A, 0xE9, 0x69, 0x43, 0xFC, 0xD9, 0x6E, 0x34, 0x46, 0x88, 0x67, 0xAD, 0xD0, 0xB8, 0x60, 0xDA, 
		0x73, 0x2D, 0x04, 0x44, 0xE5, 0x1D, 0x03, 0x33, 0x5F, 0x4C, 0x0A, 0xAA, 0xC9, 0x7C, 0x0D, 0xDD,
		0x3C, 0x71, 0x05, 0x50, 0xAA, 0x41, 0x02, 0x27, 0x10, 0x10, 0x0B, 0xBE, 0x86, 0x20, 0x0C, 0xC9, 
		0x25, 0xB5, 0x68, 0x57, 0xB3, 0x85, 0x6F, 0x20, 0x09, 0xD4, 0x66, 0xB9, 0x9F, 0xE4, 0x61, 0xCE,
		0x0E, 0xF9, 0xDE, 0x5E, 0x08, 0xC9, 0xD9, 0x29, 0x22, 0x98, 0xD0, 0xB0, 0xB4, 0xA8, 0x57, 0xC7, 
		0x17, 0x3D, 0xB3, 0x59, 0x81, 0x0D, 0xB4, 0x3E, 0x3B, 0x5C, 0xBD, 0xB7, 0xAD, 0x6C, 0xBA, 0xC0,
		0x20, 0x83, 0xB8, 0xED, 0xB6, 0xB3, 0xBF, 0x9A, 0x0C, 0xE2, 0xB6, 0x03, 0x9A, 0xD2, 0xB1, 0x74, 
		0x39, 0x47, 0xD5, 0xEA, 0xAF, 0x77, 0xD2, 0x9D, 0x15, 0x26, 0xDB, 0x04, 0x83, 0x16, 0xDC, 0x73,
		0x12, 0x0B, 0x63, 0xE3, 0x84, 0x3B, 0x64, 0x94, 0x3E, 0x6A, 0x6D, 0x0D, 0xA8, 0x5A, 0x6A, 0x7A, 
		0x0B, 0xCF, 0x0E, 0xE4, 0x9D, 0xFF, 0x09, 0x93, 0x27, 0xAE, 0x00, 0x0A, 0xB1, 0x9E, 0x07, 0x7D,
		0x44, 0x93, 0x0F, 0xF0, 0xD2, 0xA2, 0x08, 0x87, 0x68, 0xF2, 0x01, 0x1E, 0xFE, 0xC2, 0x06, 0x69, 
		0x5D, 0x57, 0x62, 0xF7, 0xCB, 0x67, 0x65, 0x80, 0x71, 0x36, 0x6C, 0x19, 0xE7, 0x06, 0x6B, 0x6E,
		0x76, 0x1B, 0xD4, 0xFE, 0xE0, 0x2B, 0xD3, 0x89, 0x5A, 0x7A, 0xDA, 0x10, 0xCC, 0x4A, 0xDD, 0x67, 
		0x6F, 0xDF, 0xB9, 0xF9, 0xF9, 0xEF, 0xBE, 0x8E, 0x43, 0xBE, 0xB7, 0x17, 0xD5, 0x8E, 0xB0, 0x60,
		0xE8, 0xA3, 0xD6, 0xD6, 0x7E, 0x93, 0xD1, 0xA1, 0xC4, 0xC2, 0xD8, 0x38, 0x52, 0xF2, 0xDF, 0x4F, 
		0xF1, 0x67, 0xBB, 0xD1, 0x67, 0x57, 0xBC, 0xA6, 0xDD, 0x06, 0xB5, 0x3F, 0x4B, 0x36, 0xB2, 0x48,
		0xDA, 0x2B, 0x0D, 0xD8, 0x4C, 0x1B, 0x0A, 0xAF, 0xF6, 0x4A, 0x03, 0x36, 0x60, 0x7A, 0x04, 0x41, 
		0xC3, 0xEF, 0x60, 0xDF, 0x55, 0xDF, 0x67, 0xA8, 0xEF, 0x8E, 0x6E, 0x31, 0x79, 0x0E, 0x69, 0x46,
		0x8C, 0xB3, 0x51, 0xCB, 0x1A, 0x83, 0x63, 0xBC, 0xA0, 0xD2, 0x6F, 0x25, 0x36, 0xE2, 0x68, 0x52, 
		0x95, 0x77, 0x0C, 0xCC, 0x03, 0x47, 0x0B, 0xBB, 0xB9, 0x14, 0x02, 0x22, 0x2F, 0x26, 0x05, 0x55,
		0xBE, 0x3B, 0xB6, 0xC5, 0x28, 0x0B, 0xBD, 0xB2, 0x92, 0x5A, 0xB4, 0x2B, 0x04, 0x6A, 0xB3, 0x5C, 
		0xA7, 0xFF, 0xD7, 0xC2, 0x31, 0xCF, 0xD0, 0xB5, 0x8B, 0x9E, 0xD9, 0x2C, 0x1D, 0xAE, 0xDE, 0x5B,
		0xB0, 0x72, 0x64, 0x9B, 0x26, 0xF2, 0xE3, 0xEC, 0x9C, 0xA3, 0x6A, 0x75, 0x0A, 0x93, 0x6D, 0x02, 
		0xA9, 0x06, 0x09, 0x9C, 0x3F, 0x36, 0x0E, 0xEB, 0x85, 0x68, 0x07, 0x72, 0x13, 0x07, 0x00, 0x05,
		0x82, 0x48, 0xBF, 0x95, 0x14, 0x7A, 0xB8, 0xE2, 0xAE, 0x2B, 0xB1, 0x7B, 0x38, 0x1B, 0xB6, 0x0C, 
		0x9B, 0x8E, 0xD2, 0x92, 0x0D, 0xBE, 0xD5, 0xE5, 0xB7, 0xEF, 0xDC, 0x7C, 0x21, 0xDF, 0xDB, 0x0B,
		0x94, 0xD2, 0xD3, 0x86, 0x42, 0xE2, 0xD4, 0xF1, 0xF8, 0xB3, 0xDD, 0x68, 0x6E, 0x83, 0xDA, 0x1F, 
		0xCD, 0x16, 0xBE, 0x81, 0x5B, 0x26, 0xB9, 0xF6, 0xE1, 0x77, 0xB0, 0x6F, 0x77, 0x47, 0xB7, 0x18,
		0xE0, 0x5A, 0x08, 0x88, 0x70, 0x6A, 0x0F, 0xF1, 0xCA, 0x3B, 0x06, 0x66, 0x5C, 0x0B, 0x01, 0x11, 
		0xFF, 0x9E, 0x65, 0x8F, 0x69, 0xAE, 0x62, 0xF8, 0xD3, 0xFF, 0x6B, 0x61, 0x45, 0xCF, 0x6C, 0x16,
		0x78, 0xE2, 0x0A, 0xA0, 0xEE, 0xD2, 0x0D, 0xD7, 0x54, 0x83, 0x04, 0x4E, 0xC2, 0xB3, 0x03, 0x39, 
		0x61, 0x26, 0x67, 0xA7, 0xF7, 0x16, 0x60, 0xD0, 0x4D, 0x47, 0x69, 0x49, 0xDB, 0x77, 0x6E, 0x3E,
		0x4A, 0x6A, 0xD1, 0xAE, 0xDC, 0x5A, 0xD6, 0xD9, 0x66, 0x0B, 0xDF, 0x40, 0xF0, 0x3B, 0xD8, 0x37, 
		0x53, 0xAE, 0xBC, 0xA9, 0xC5, 0x9E, 0xBB, 0xDE, 0x7F, 0xCF, 0xB2, 0x47, 0xE9, 0xFF, 0xB5, 0x30,
		0x1C, 0xF9, 0xBD, 0xBD, 0x8A, 0xCD, 0xBA, 0xCA, 0x30, 0x9E, 0xB3, 0x53, 0xA6, 0xA3, 0xBC, 0x24, 
		0x05, 0x3B, 0xD0, 0xBA, 0xA3, 0x06, 0xD7, 0xCD, 0xE9, 0x57, 0xDE, 0x54, 0xBF, 0x67, 0xD9, 0x23,
		0x2E, 0x72, 0x66, 0xB3, 0xB8, 0x4A, 0x61, 0xC4, 0x02, 0x1B, 0x38, 0x5D, 0x94, 0x2B, 0x6F, 0x2B, 
		0x37, 0xBE, 0xCB, 0xB4, 0xA1, 0x8E, 0xCC, 0xC3, 0x1B, 0xDF, 0x0D, 0x5A, 0x8D, 0xED, 0x02, 0x2D,
	];
