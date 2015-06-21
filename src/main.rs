use sro::gateway_session::GatewaySession;
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
}