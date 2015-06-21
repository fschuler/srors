#[repr(u16)]
#[derive(Debug)]
pub enum ClientOpcode {
	Identification = 0x2001u16,
	Handshake = 0x5000u16,
	PatchRequest = 0x6100u16,
	ServerlistRequest = 0x6101u16,
	LoginRequest = 0x6102u16,
	AgentLoginRequest = 0x6103u16,
	NoticeRequest = 0x6104u16,
	LoginIBUVAwnser = 0x6323u16,
	Unkown
}

#[repr(u16)]
#[derive(Debug)]
pub enum ServerOpcode {
	Handshake = 0x5000u16,
	Identification = 0x2001u16,
	LoginIBUVChallenge = 0x2322u16,
	PatchResponse = 0xA100u16,
	ServerlistResponse = 0xA101u16,
	LoginResponse = 0xA102u16,
	NoticeResponse = 0xA104u16,
	LoginIBUVResult = 0xA323u16,
	Unkown
}



pub fn client_opcode(opcode : u16) -> ClientOpcode {
if opcode == ClientOpcode::Identification as u16 {
		return ClientOpcode::Identification
	}
	if opcode == ClientOpcode::Handshake as u16 {
		return ClientOpcode::Handshake
	}
	if opcode == ClientOpcode::PatchRequest as u16 {
		return ClientOpcode::PatchRequest
	}
	if opcode == ClientOpcode::ServerlistRequest as u16 {
		return ClientOpcode::ServerlistRequest
	}
	if opcode == ClientOpcode::LoginRequest as u16 {
		return ClientOpcode::LoginRequest
	}
	if opcode == ClientOpcode::NoticeRequest as u16 {
		return ClientOpcode::NoticeRequest
	}
	if opcode == ClientOpcode::LoginIBUVAwnser as u16 {
		return ClientOpcode::LoginIBUVAwnser
	}
	if opcode == ClientOpcode::AgentLoginRequest as u16 {
		return ClientOpcode::AgentLoginRequest
	}
	ClientOpcode::Unkown
}

pub fn server_opcode(opcode : u16) -> ServerOpcode {
	if opcode == ServerOpcode::Handshake as u16 {
		return ServerOpcode::Handshake
	}
	if opcode == ServerOpcode::Identification as u16 {
		return ServerOpcode::Identification
	}
	if opcode == ServerOpcode::LoginIBUVChallenge as u16 {
		return ServerOpcode::LoginIBUVChallenge
	}
	if opcode == ServerOpcode::PatchResponse as u16 {
		return ServerOpcode::PatchResponse
	}
	if opcode == ServerOpcode::ServerlistResponse as u16 {
		return ServerOpcode::ServerlistResponse
	}
	if opcode == ServerOpcode::LoginResponse as u16 {
		return ServerOpcode::LoginResponse
	}
	if opcode == ServerOpcode::NoticeResponse as u16 {
		return ServerOpcode::NoticeResponse
	}
	if opcode == ServerOpcode::LoginIBUVResult as u16 {
		return ServerOpcode::LoginIBUVResult
	}
	ServerOpcode::Unkown
}