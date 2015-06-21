use sro::connection::Connection;
use sro::security::Security;
use sro::packet::Packet;
use std::thread;
use std::thread::{JoinHandle};
use std::sync::{Arc, Mutex, MutexGuard};
use std::io::Result;
use sro::opcodes::server_opcode;
use sro::opcodes::ServerOpcode;
use sro::opcodes::client_opcode;
use sro::opcodes::ClientOpcode;
use sro::agentserver_info::AgentServerInfo;

pub struct GameserverSession {
	security : Arc<Mutex<Security>>,
	connection : Option<Arc<Mutex<Connection>>>,
	pub recv_thread : Option<JoinHandle<()>>,
	pub send_thread : Option<JoinHandle<()>>,
	pub agentserver_info : Arc<Mutex<AgentServerInfo>>
}

static LOCALE : u8 = 22;
static VERSION : u32 = 279;

impl GameserverSession {
	pub fn new(agentserver_info : AgentServerInfo) -> Result<GameserverSession> {
		let info = agentserver_info.clone();
		let mut gw = GameserverSession {
			security : Arc::new(Mutex::new(Security::new())),
			connection : None,
			recv_thread : None,
			send_thread : None,
			agentserver_info : Arc::new(Mutex::new(agentserver_info))
		};
		
		match Connection::new(info.ip, info.port) {
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
		let local_info = self.agentserver_info.clone();
		self.recv_thread = Some(thread::spawn(move || {
			loop {
				{
					let mut con = local_connection.lock().unwrap();
					if con.closed {
						break;
					}
					let mut sec = local_security.lock().unwrap();
					let mut info = local_info.lock().unwrap().clone();
					process_incoming(&mut sec, &mut con, &info)
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
					process_outgoing(&mut sec, &mut con);					
				}
				thread::sleep_ms(10);
			}
		}));
	}
}


fn process_outgoing(sec : &mut MutexGuard<Security>, con : &mut MutexGuard<Connection>) {
	for kvp in sec.transfer_outgoing() {
		println!("{}", format!("[C->S] {:?}", client_opcode(kvp.1.opcode())));
		match con.send(kvp.0) {
			Ok(()) => {},
			Err(e) => { panic!("{}", e); }
		}
	}
}

fn process_packet(packet : &mut Packet, sec : &mut MutexGuard<Security>, info : &AgentServerInfo, con : &mut MutexGuard<Connection>) {
	println!("{}", format!("[S->C] {:?}", server_opcode(packet.opcode())));		
	match server_opcode(packet.opcode()) {
		ServerOpcode::Handshake 			=> {},
		ServerOpcode::Identification 		=> identify(sec, info),
		ServerOpcode::Unkown 				=> println!("{}", format!("Unknown opcode {:02X}", packet.opcode())),
		_ => { /* We dont care about these opcodes here.*/ }
	}
}

fn process_incoming(sec : &mut MutexGuard<Security>, con : &mut MutexGuard<Connection>, info : &AgentServerInfo) {
	match con.receive() { 
		Ok(data) => {
			sec.recv(data); 
			for mut packet in sec.transfer_incoming() {
				process_packet(&mut packet, sec, info, con)
			}
		},
		Err(e) => panic!("{}",e)
	}
}

fn identify(sec : &mut MutexGuard<Security>, info : &AgentServerInfo) {
	let mut response = Packet::new_enc(ClientOpcode::AgentLoginRequest as u16, true);
 	response.write_u32(info.session_token);
 	response.write_ascii(info.username.clone());
 	response.write_ascii(info.password.clone());
 	response.write_u8(LOCALE);
 	response.write_u32(0);
 	response.write_u16(0);
 	sec.send(response);
}



