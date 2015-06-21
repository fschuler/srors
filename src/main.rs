use sro::gateway_session::GatewaySession;
use sro::agentserver_info::AgentServerInfo;
use sro::gameserver_session::GameserverSession;
extern crate byteorder;

mod sro;

fn main() {
	let gw_session = match GatewaySession::new() {
		Ok(s) => s,
		Err(e) => panic!("{}",e)
	};
	
	println!("Connected!");
	
	match gw_session.recv_thread.unwrap().join() {
		Ok(_) => println!("Stopped receiving."),
		Err(e) => panic!("Error receiving {:?}",e)
	}
	
	println!("Now we connect to the agentserver");
	
	
	let info = gw_session.agentserver_info.lock().unwrap();
	
	let new_info = AgentServerInfo {
		session_token : info.session_token,
		username : info.username.clone(),
		password : info.password.clone(),
		ip : info.ip.clone(),
		port : info.port
	};
	let game_session = match GameserverSession::new(new_info) {
		Ok(s) => s,
		Err(e) => panic!("{}",e)
	};
	
	match game_session.recv_thread.unwrap().join() {
		Ok(_) => println!("Stopped receiving."),
		Err(e) => panic!("Error receiving {:?}",e)
	}
	
	
}