use sro::connection::Connection;
use sro::security::Security;
use sro::packet::Packet;
use std::thread;
use std::thread::{JoinHandle};
use std::sync::{Arc, Mutex};
use std::io::Result;

pub struct GatewaySession {
	security : Arc<Mutex<Security>>,
	connection : Option<Arc<Mutex<Connection>>>,
	recv_thread : Option<JoinHandle<()>>,
	send_thread : Option<JoinHandle<()>>
}

static LOCALE : u8 = 22;
static VERSION : u32 = 555;

impl GatewaySession {
	pub fn new() -> Result<GatewaySession> {
		let mut gw = GatewaySession {
			security : Arc::new(Mutex::new(Security::new())),
			connection : None,
			recv_thread : None,
			send_thread : None
		};
		
		match Connection::new("server.droad.net".to_string(), 15779) {
			Ok(connection) => {				
				gw.connection = Some(Arc::new(Mutex::new(connection)));
			},
			Err(e) => return Err(e)
		};
		
		gw.start_recv_thread();
		gw.start_send_thread();
				
		return Ok(gw);
	}
	
	
	fn start_recv_thread(&mut self) {
		let local_security = self.security.clone();
		let local_connection = self.connection.clone().unwrap();
		
		self.recv_thread = Some(thread::spawn(move || {
			loop {
					{
					let mut con = local_connection.lock().unwrap();
					match con.receive() {
						Ok(data) => {
							let mut sec = local_security.lock().unwrap();
							sec.recv(data);
							for mut packet in sec.transfer_incoming() {
    							println!("{}", format!("[S->C] {:02X}", packet.opcode()));
    							match packet.opcode() {
			    					0x2001 => {
			    						 let mut response = Packet::new_enc_mass(0x6100, true, false);
			                             response.write_u8(LOCALE);
			                             response.write_ascii("SR_Client".to_string());
			                             response.write_u32(VERSION);
			                             sec.send(response);
			    					},
			    					0x2005 => {},
			    					0xA100 => {
			    						let result = packet.read_u8();
			    						if result == 1 {
			    							if LOCALE == 18 {
			    								let response = Packet::new_enc_mass(0x6107, true, false);
			    								sec.send(response);
			
			    							} else {
			    								let response = Packet::new_enc(0x6101, true);
			                                    sec.send(response);
			    							}
			    							println!("Requesting server list");
			    						} else {
			    							let result_v2 = packet.read_u8();
			    							match result_v2 {
			    								1 => println!("Version too new"),
			    								2 => {
			    									//Updates available 
			    									let ip = packet.read_ascii();
			    									let port = packet.read_u16();
			    									let new_version = packet.read_u32();
			    								
			    									println!("New version availble {}:{} v{}",ip, port, new_version);
			    								},
			    								4 => println!("Server down (Gateway closed"),
			    								5 => println!("Version too old"),
			    								r => println!("Unknown response {}" , r)
			    							}
			    						}
			    					},
			    					0xA101 => {
			    					
			    						let mut new_entry = packet.read_u8();
			    						while new_entry == 1 {
			    							let id = packet.read_u8();
			    							let name = packet.read_ascii();
			    							
			    							println!("{} : {}", id, name);
			    							
			    							new_entry = packet.read_u8();
			    						}
			    						
			    						new_entry = packet.read_u8();
			    						
			    						while new_entry == 1 {
			    							let id = packet.read_u16();
			    							let name = packet.read_ascii();
			    							let current = packet.read_u16();
			    							let max = packet.read_u16();
			    							let state = packet.read_u8();
			    							
			    							
			    							println!("{} {} {}/{} {}", id, name, current, max, state);
			    							
			    							new_entry = packet.read_u8();
			    						}
			    					},
			    					opcode => println!("{}", format!("Unknown opcode {:02X}", opcode))
			    				}
							}
						},
						Err(e) => panic!("{}",e)
					}
				}
				thread::sleep_ms(10);
			}
		}));
	}
	
	
	fn start_send_thread(&mut self) {
		let local_security = self.security.clone();
		let local_connection = self.connection.clone().unwrap();
		
		self.send_thread = Some(thread::spawn(move || {
			loop {
				{
					let mut con = local_connection.lock().unwrap();
					let mut sec = local_security.lock().unwrap();
					for kvp in sec.transfer_outgoing() {
						println!("{}", format!("[C->S] {:02X}", kvp.1.opcode()));
    					match con.send(kvp.0) {
    						Ok(()) => {},
    						Err(e) => { panic!("{}", e); }
    					}
					}
				}
				thread::sleep_ms(10);
			}
		}));
	}
}
