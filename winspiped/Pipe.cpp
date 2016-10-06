#include "stdafx.h"
#include "Pipe.h"
#include "info.h"


Pipe::Pipe(int s, int t, PipeConfig * conf) : HandshakeDone(0), op_ref(0), client_key(0), server_key(0), K(0) {
	this->s = s;
	this->t = t;
	this->Decr = conf->decr;
	this->K = conf->K;
	this->conf = conf;
	Init();
}


Pipe::~Pipe()
{
	// original spiped lib doesn't free the keys, we need to free it here.
	if (client_key) {
		free(client_key);
	}
	if (server_key) {
		free(server_key);
	}
}

/*
	check if the overlaped operation failed
*/

void Pipe::CheckError(int code, int line) {
	if (code) {
		int ecode = WSAGetLastError();
		if (ecode != WSA_IO_PENDING) {
			debug_out("error code %d at line %d\n", ecode, line);
			// to close or not to close the pipe
			OpRelease();
		}
	}
}

int Pipe::Init() {
	memset(Ops, 0, sizeof(PipeOperation) * 5);
	// init handshakes

	/*
		trans_condition

			0: send complete
			1: recv complete
	*/
	Handshakes[HandshakeStatus::SENDING_NONCE].trans_condition = 0;
	Handshakes[HandshakeStatus::SENDING_NONCE].fp = &Pipe::RecvNonce;

	Handshakes[HandshakeStatus::RECVING_NONCE].trans_condition = 1;
	Handshakes[HandshakeStatus::RECVING_NONCE].fp = &Pipe::SendDmac;

	Handshakes[HandshakeStatus::SENDING_DMAC].trans_condition = 0;
	Handshakes[HandshakeStatus::SENDING_DMAC].fp = &Pipe::RecvDmac;

	Handshakes[HandshakeStatus::RECVING_DMAC].trans_condition = 1;
	Handshakes[HandshakeStatus::RECVING_DMAC].fp = &Pipe::Mixing;
	return 0;
}

int Pipe::StartHandshake() {
	// set the entry status to SENDING_NONCE
	CurrentShaking = HandshakeStatus::SENDING_NONCE;
	SendNonce(NULL);
	return 0;
}

/*
	the handshake state transformation
*/
int Pipe::ShakingIt(PipeOperation * Operation) {
	
	HandshakeStatus current = Handshakes[CurrentShaking];
	int type = Operation->Type;
	int trans_condition;
	if (type == PipeOperation::RECV_SOURCE || type == PipeOperation::RECV_TARGET) {
		trans_condition = 1;
	} else {
		trans_condition = 0;
	}
	// condition matched
	if (current.trans_condition == trans_condition) {
		// transforming 
		CurrentShaking = (HandshakeStatus::hsStatus)(CurrentShaking + 1);
		debug_out("current status %d\n", CurrentShaking);
		// enter that state
		(*this.*current.fp)(Operation);
	}
	return 0;
}


int Pipe::SendNonce(PipeOperation * preOperation) {
	// get nounce
	crypto_entropy_read(nonce_local, PCRYPT_NONCE_LEN);
	// send the nonce
	if (!Decr) {
		// we are client
		SendTarget((char*)nonce_local, PCRYPT_NONCE_LEN);
	} else {
		// we are server
		SendSource((char*)nonce_local, PCRYPT_NONCE_LEN);
	}
	return 0;
}

int Pipe::RecvNonce(PipeOperation * preOperation) {
	if (!Decr) {
		// we are client
		RecvTarget(0, PCRYPT_NONCE_LEN, 0);
	}
	else {
		// we are server
		RecvSource(0, PCRYPT_NONCE_LEN, 0);
	}
	return 0;
}

int Pipe::SendDmac(PipeOperation * preOperation) {
	//  preOperation contains the remote nonce
	memcpy(nonce_remote, preOperation->buffer, PCRYPT_NONCE_LEN);
	//  compute the shared secret
	proto_crypt_dhmac(K, nonce_local, nonce_remote, dhmac_local, dhmac_remote, Decr);
	// send local diffie-hellman parameter
	proto_crypt_dh_generate(yh_local, x, dhmac_local, 0);
	if (!Decr) {
		// we are client
		SendTarget((char*)yh_local, PCRYPT_YH_LEN);
	}
	else {
		// we are server
		SendSource((char*)yh_local, PCRYPT_YH_LEN);
	}
	return 0;
}

int Pipe::RecvDmac(PipeOperation * preOperation) {
	if (!Decr) {
		// we are client
		RecvTarget(0, PCRYPT_YH_LEN, 0);
	}
	else {
		// we are server
		RecvSource(0, PCRYPT_YH_LEN, 0);
	}
	return 0;
}

int Pipe::Mixing(PipeOperation * preOperation) {
	//  preOperation contains the remote hdmaced
	memcpy(yh_remote, preOperation->buffer, PCRYPT_YH_LEN);
	// compute the common secret key
	if (proto_crypt_dh_validate(yh_remote, dhmac_remote, 1)) {
		ShakeItOff();
	} else {
		if (proto_crypt_mkkeys(K, nonce_local, nonce_remote, yh_remote, x, 0, Decr, &client_key, &server_key)) {
			info_out("compute common secret failed\n");
			ShakeItOff();
		} else {
			HandshakeDone = 1;
			info_out("handshake successe\n");
			StartPipeling();
		}
	}
	return 0;
}

/*
	handshake failed
*/
int Pipe::ShakeItOff() {
	// close all sockets
	info_out("droped an evil pipe\n");
	Close();
	return 0;
}

int Pipe::RecvSource(int offset, int need_size, int max_size) {
	//info_out("issue a recv on source\n");
	PipeOperation * operation = InitOperation(PipeOperation::RECV_SOURCE);
	operation->socket = s;
	if (need_size == -1) {
		need_size = max_size ? max_size : BUFFER_SIZE;;
		operation->remain = 0;
	} else {
		operation->remain = need_size - offset;
	}
	WSABUF Buffer = {};
	DWORD Flags = 0;
	Buffer.buf = operation->buffer + offset;
	Buffer.len = need_size - offset;
	operation->transferred = offset;
	int ret = WSARecv(s, &Buffer, 1, 0, &Flags, (LPOVERLAPPED)operation, 0);
	CheckError(ret, __LINE__);
	return 0;
}

int Pipe::RecvTarget(int offset, int need_size, int max_size) {
	//info_out("issue a recv on target\n");
	PipeOperation * operation = InitOperation(PipeOperation::RECV_TARGET);
	operation->socket = t;
	if (need_size == -1) {
		need_size = max_size ? max_size : BUFFER_SIZE;
		operation->remain = 0;
	}
	else {
		operation->remain = need_size - offset;
	}
	WSABUF Buffer = {};
	DWORD Flags = 0;
	Buffer.buf = operation->buffer + offset;
	Buffer.len = need_size - offset;
	operation->transferred = offset;
	int ret = WSARecv(t, &Buffer, 1, 0, &Flags, (LPOVERLAPPED)operation, 0);
	CheckError(ret, __LINE__);
	return 0;
}

int Pipe::SendSource(char * buffer, int len) {
	if (len <0 || len > BUFFER_SIZE) {
		info_out("error: seding invalid length %d\n", len);
		Close();
	}
	WSABUF Buffer = {};
	PipeOperation * peer_op = InitOperation(PipeOperation::SEND_SOURCE);
	peer_op->socket = s;
	memcpy(peer_op->buffer, buffer, len);
	peer_op->remain = len;
	Buffer.buf = peer_op->buffer;
	Buffer.len = len;
	int ret = WSASend(s, &Buffer, 1, NULL, 0, (LPOVERLAPPED)peer_op, NULL);
	CheckError(ret, __LINE__);
	return 0;
}

int Pipe::SendTarget(char * buffer, int len) {
	if (len <0 || len > BUFFER_SIZE) {
		info_out("error: seding invalid length %d\n", len);
		Close();
	}
	WSABUF Buffer = {};
	PipeOperation * peer_op = InitOperation(PipeOperation::SEND_TARGET);
	peer_op->socket = t;
	memcpy(peer_op->buffer, buffer, len);
	peer_op->remain = len;
	Buffer.buf = peer_op->buffer;
	Buffer.len = len;
	int ret = WSASend(t, &Buffer, 1, NULL, 0, (LPOVERLAPPED)peer_op, NULL);
	CheckError(ret, __LINE__);
	return 0;
}

PipeOperation * Pipe::InitOperation(PipeOperation::OpType  Type) {
	PipeOperation * operation = &Ops[Type];
	memset(&operation->overlapped, 0, sizeof(OVERLAPPED));
	operation->end = operation->buffer;
	operation->transferred = 0;
	operation->Type = Type;
	operation->socket = -1;
	return operation;
}

int Pipe::StartPipeling() {
	OpRef();
	if (!Decr) {
		RecvSource(0, -1, PACKAGE_SIZE);
		RecvTarget(0, PCRYPT_ESZ, 0);
	} else {
		RecvSource(0, PCRYPT_ESZ, 0);
		RecvTarget(0, -1, PACKAGE_SIZE);
	}
	return 0;
}


int Pipe::Pipeling(DWORD byteTransferred, PipeOperation * Operation) {
	int Type = Operation->Type;
	// assume the handshake is done
	Operation->transferred += byteTransferred;
	Operation->end += byteTransferred;
	if (Operation->remain) {
		Operation->remain -= byteTransferred;
	}
	char buff[PCRYPT_ESZ];
	int len = 0;
	switch (Type) {
	case  PipeOperation::RECV_SOURCE:
		if (!byteTransferred) {
			OpRelease();
			break;
		} 
		if (Operation->remain) {
			RecvSource(Operation->transferred, Operation->remain + Operation->transferred, 0);
			break;
		}
		// just send it to target
		if (!Decr) {
			// enc data and send to target
			proto_crypt_enc((uint8_t*)Operation->buffer, Operation->transferred, (uint8_t*)buff, client_key);
			SendTarget(buff, PCRYPT_ESZ);
		} else {
			len = proto_crypt_dec((uint8_t*)Operation->buffer, (uint8_t*)buff, client_key);
			SendTarget(buff, len);
		}
		break;
	case PipeOperation::RECV_TARGET:
		if (!byteTransferred) {
			OpRelease();
			break;
		}
		if (Operation->remain) {
			RecvTarget(Operation->transferred, Operation->remain + Operation->transferred, 0);
			break;
		}
		// just send it to source
		if (!Decr) {
			// enc data and send to target
			len = proto_crypt_dec((uint8_t*)Operation->buffer, (uint8_t*)buff, server_key);
			SendSource(buff, len);
		}
		else {
			proto_crypt_enc((uint8_t*)Operation->buffer, Operation->transferred, (uint8_t*)buff, server_key);
			SendSource(buff, PCRYPT_ESZ);
		}
		break;
	case PipeOperation::SEND_SOURCE:
		if (Operation->remain) {
			// send the remain data
			SendSource(Operation->buffer + byteTransferred, Operation->remain);
		}
		else {
			// the send is finished, issue another recv
			if (!Decr) {
				RecvTarget(0, PCRYPT_ESZ, 0);
			} else {
				RecvTarget(0, -1, PACKAGE_SIZE);
			}
		}
		break;
	case PipeOperation::SEND_TARGET:
		if (Operation->remain) {
			// send the remain data
			SendTarget(Operation->buffer + byteTransferred, Operation->remain);
		}
		else {
			// the send is finished, issue another recv
			if (!Decr) {
				RecvSource(0, -1, PACKAGE_SIZE);
			}
			else {
				RecvSource(0, PCRYPT_ESZ, 0);
			}
		}
		break;
	case PipeOperation::CONNECT_TARGET:
		debug_out("connected to target\nstarting pipe..... skip shandshake\n");
		OpRef();
		RecvSource(0, -1, 0);
		RecvTarget(0, -1, 0);
		break;
	default:
		info_out("unknow operation %d. must be a coding error", Type);
		break;
	}
	return 0;
}

int Pipe::HandShake(DWORD byteTransferred, PipeOperation * Operation) {

	int Type = Operation->Type;
	// assume the handshake is done
	Operation->transferred += byteTransferred;
	Operation->end += byteTransferred;
	if (Operation->remain) {
		Operation->remain -= byteTransferred;
	}
	switch (Type) {
	case  PipeOperation::RECV_SOURCE:
		if (!byteTransferred) {
			OpRelease();
			break;
		}
		if (Operation->remain) {
			RecvSource(Operation->transferred, Operation->remain + Operation->transferred, 0);
			break;
		}
		ShakingIt(Operation);
		break;
	case PipeOperation::RECV_TARGET:
		if (!byteTransferred) {
			OpRelease();
			break;
		}
		if (Operation->remain) {
			RecvTarget(Operation->transferred, Operation->remain + Operation->transferred, 0);
			break;
		}
		ShakingIt(Operation);
		break;
	case PipeOperation::SEND_SOURCE:
		if (Operation->remain) {
			// send the remain data
			SendSource(Operation->buffer + byteTransferred, Operation->remain);
		} else {
			// the send is finished, issue another recv
			ShakingIt(Operation);
		}
		break;
	case PipeOperation::SEND_TARGET:
		if (Operation->remain) {
			// send the remain data
			SendTarget(Operation->buffer + byteTransferred, Operation->remain);
		} else {
			// the send is finished, issue another recv
			ShakingIt(Operation);
		}
		break;
	case PipeOperation::CONNECT_TARGET:
		info_out("connected to target\nstarting pipe..... initial handshake \n");
		StartHandshake();
		break;
	default:
		info_out("unknow operation %d. must be a coding error", Type);
		break;
	}
	return 0;
}

int Pipe::Process(DWORD byteTransferred, PipeOperation * Operation) {
	//info_out("processing  %d bytes\n", byteTransferred);
	memset(&Operation->overlapped, 0, sizeof(OVERLAPPED));
	// HandshakeDone = 0;
	if (!HandshakeDone) {
		HandShake(byteTransferred, Operation);
	} else {
		Pipeling(byteTransferred, Operation);
	}
	return 0;
}

int Pipe::ConnectTarget() {
	// get ConnectEx
	sockaddr_in remote = conf->target_addr;
	DWORD numBytes = 0;
	GUID guid = WSAID_CONNECTEX;
	LPFN_CONNECTEX ConnectExPtr = NULL;
	int success = ::WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		(void*)&guid, sizeof(guid), (void*)&ConnectExPtr, sizeof(ConnectExPtr),
		&numBytes, NULL, NULL);
	// Check WSAGetLastError()!
	// bound t

	sockaddr_in addr;
	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0;
	int ret = bind(t, (SOCKADDR*)&addr, sizeof(addr));
	if (ret != 0) {
		info_out("bind failed: %d\n", WSAGetLastError());
		return 1;
	}
	// Assuming the pointer isn't NULL, you can call it with the correct parameters.
	PipeOperation * operation = InitOperation(PipeOperation::CONNECT_TARGET);
	OpRef();
	ret = ConnectExPtr(t, (sockaddr*)&remote, sizeof(remote), NULL,
		0, 0, (OVERLAPPED*)operation);
	if (!ret) {
		int code = WSAGetLastError();
		if (code == ERROR_IO_PENDING) {
			debug_out("pending\n");
		}
		else {
			OpRelease();
			debug_out("error\n");
		}
	}
	info_out("connecting to remote end\n");
	return 0;
}


void Pipe::OpRef() {
	InterlockedIncrement(&op_ref);
}


void Pipe::OpRelease() {
	DWORD value = InterlockedDecrement(&op_ref);
	Close();
	if (!value) {
		info_out("release a pipe\n");
		delete this;
	}
}

void Pipe::Close() {
	// close all the sockets
	if (s != -1) {
		closesocket(s);
		s = -1;
	}
	if (t != -1) {
		closesocket(t);
		t = -1;
	}
}