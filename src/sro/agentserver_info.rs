#[derive(Clone)]
pub struct AgentServerInfo {
	pub username : String,
	pub password : String,
	pub session_token : u32,
	pub ip : String,
	pub port : u16
}