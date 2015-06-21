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

pub struct GatewaySession {
	security : Arc<Mutex<Security>>,
	connection : Option<Arc<Mutex<Connection>>>,
	pub recv_thread : Option<JoinHandle<()>>,
	pub send_thread : Option<JoinHandle<()>>,
	pub agentserver_info : Arc<Mutex<AgentServerInfo>>
}

pub struct AgentServerInfo {
	pub username : String,
	pub password : String,
	pub session_token : u32,
	pub ip : String,
	pub port : u16
}
impl AgentServerInfo {
	pub fn new() -> AgentServerInfo {
		AgentServerInfo {
			username : "".to_string(),
			password : "".to_string(),
			session_token : 0,
			ip : "".to_string(),
			port : 0
		}
	}
}


static LOCALE : u8 = 22;
static VERSION : u32 = 279;

impl GatewaySession {
	pub fn new() -> Result<GatewaySession> {
		let mut gw = GatewaySession {
			security : Arc::new(Mutex::new(Security::new())),
			connection : None,
			recv_thread : None,
			send_thread : None,
			agentserver_info : Arc::new(Mutex::new(AgentServerInfo::new()))
		};
		
		match Connection::new("login.januera.com".to_string(), 45622) {
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
					let mut info = local_info.lock().unwrap();
					process_incoming(&mut sec, &mut con, &mut info)
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

fn process_packet(packet : &mut Packet, sec : &mut MutexGuard<Security>, info : &mut MutexGuard<AgentServerInfo>, con : &mut MutexGuard<Connection>) {
	println!("{}", format!("[S->C] {:?}", server_opcode(packet.opcode())));		
	match server_opcode(packet.opcode()) {
		ServerOpcode::Handshake 			=> println!("{:?}",ServerOpcode::Handshake),
		ServerOpcode::Identification 		=> identify(sec),
    	ServerOpcode::PatchResponse 		=> request_serverlist(packet, sec),
		ServerOpcode::ServerlistResponse 	=> login(serverlist(packet), sec, info),
		ServerOpcode::LoginIBUVChallenge 	=> imagecode(packet, sec),
		ServerOpcode::LoginResponse 		=> { login_response(packet, info); con.closed = true },
		ServerOpcode::NoticeResponse 		=> notice_response(packet), 
		ServerOpcode::LoginIBUVResult 		=> imagecode_result(packet),
		ServerOpcode::Unkown 				=> println!("{}", format!("Unknown opcode {:02X}", packet.opcode()))
	}
}

fn process_incoming(sec : &mut MutexGuard<Security>, con : &mut MutexGuard<Connection>, info : &mut MutexGuard<AgentServerInfo>) {
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

fn login(serverlist : Vec<ServerlistEntry>, sec : &mut MutexGuard<Security>, info : &mut MutexGuard<AgentServerInfo>) {
	//Send this weird packet so the gateway gives us the corrent agentserver ip.
	let bytes = vec![0x00, 0x24, 0x7A, 0x7A, 0x34, 0x2E, 0x77, 0x69, 0x78, 0x7A, 0x7C, 0x7C, 0x70, 0x61, 0x7C, 0x6E,
			0x65, 0x29, 0x77, 0x64, 0x66, 0x7B, 0x68, 0x7A, 0x70, 0x7C, 0x7E, 0x21, 0x30, 0x7B, 0x7B, 0x33,
			0x72, 0x21, 0x33, 0x7A, 0x71, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
	
	let mut p = Packet::new(0x9001);
	p.write_bytes(bytes);
	sec.send(p);	 
	
	info.username = "rustsro".to_string();
	info.password = "rustsro".to_string();
	
	let login_packet = get_login_packet(serverlist[0].id, "theonly112".to_string(), "flori1993".to_string());
	sec.send(login_packet);
}

fn imagecode_result(packet: &mut Packet) {
	packet.read_u8();
}

fn imagecode(packet: &mut Packet, sec : &mut MutexGuard<Security>) {
	let flag = packet.read_u8();
	let remain = packet.read_u16();
	let compressed = packet.read_u16();
	let uncompressed = packet.read_u16();
	let width = packet.read_u16();
	let height = packet.read_u16();
	
	println!("{} {} Compression {}/{}  Size : {}x{}", flag, remain, compressed, uncompressed, width, height);
	
	let mut response = Packet::new(ClientOpcode::LoginIBUVAwnser as u16);
 	response.write_ascii("0".to_string());
 	sec.send(response);
}

fn login_response(packet: &mut Packet, info : &mut MutexGuard<AgentServerInfo>) {
	let result = packet.read_u8();
	match result {
		1 => { 
			info.session_token = packet.read_u32();
			info.ip = packet.read_ascii();
			info.port = packet.read_u16(); 			
			println!("token : {} server: {}:{}", info.session_token, info.ip, info.port);
		},
		2 => { 
			let error_code = packet.read_u8();
			match error_code {
				1 => {},
				2 => { println!("Blocked"); },
				3 => { println!("This user is already connected. The user may still be connected because of an error that forced the game to close. Please try again in 5 minutes."); },
				4 => { println!("Faild to Connect to Server (C5)."); },
				5 => { println!("The server is full, please try again later."); },
				6 => { println!("Faild to Connect to Server (C7)."); },
				7 => { println!("Faild to Connect to Server (C8)."); },
				8 => { println!( "Faild to connect to server because access to the current IP has exceeded its limit."); },
				9 => { println!("0"); },
				10 => { println!("Only adults over the age of 18 are allowed to connect to server."); },
				11 => { println!("Only users over the age of 12 are allowed to connect to the server."); },
				12 => { println!("Adults over the age of 18 are not allowed to connect to the Teen server."); },
				error_code => { println!("Unkown login error code : {}", error_code); }
			}	
		},
		3 => { }
		result => { println!("Unknown login result : {}", result);}
	}
}

fn notice_response(packet: &mut Packet) {
	packet.read_u8();
}

fn identify(sec : &mut MutexGuard<Security>) {
	let mut response = Packet::new_enc_mass(ClientOpcode::PatchRequest as u16, true, false);
 	response.write_u8(LOCALE);
 	response.write_ascii("SR_Client".to_string());
 	response.write_u32(VERSION);
 	sec.send(response);
}

struct ServerlistEntry {
	pub id : u16,
	pub name : String,
	pub current : u16,
	pub max : u16,
	pub state : u8
}

fn get_login_packet(sid : u16, username : String, password : String) -> Packet {
	let mut packet = Packet::new_enc(ClientOpcode::LoginRequest as u16, true);
	packet.write_u8(LOCALE);
	packet.write_ascii(username);
	packet.write_ascii(password);
	packet.write_u16(sid);
	return packet;
}

fn serverlist(packet: &mut Packet) -> Vec<ServerlistEntry> {
	let mut new_entry = packet.read_u8();
	while new_entry == 1 {
		let id = packet.read_u8();
		let name = packet.read_ascii();	
		println!("{} : {}", id, name);
		
		new_entry = packet.read_u8();
	}
			
	new_entry = packet.read_u8();
	let mut serverlist = Vec::<ServerlistEntry>::new();
		
	while new_entry == 1 {
		let id = packet.read_u16();
		let name = packet.read_ascii();
		let current = packet.read_u16();
		let max = packet.read_u16();
		let state = packet.read_u8();
		
		
		let entry = ServerlistEntry {
				id : id,
				name : name,
				current : current,
				max : max,
				state : state 
		};
		
		println!("{} {} {}/{} {}", entry.id, entry.name, entry.current, entry.max, entry.state);
		
		serverlist.push(entry);
		new_entry = packet.read_u8();

	}
	return serverlist;
}

fn request_serverlist(packet: &mut Packet, sec : &mut MutexGuard<Security>) {
	let result = packet.read_u8();
		if result == 1 {
			let response = Packet::new_enc(ClientOpcode::ServerlistRequest as u16, true);
			sec.send(response);
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
}