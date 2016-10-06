#ifndef __PIPE__
#define __PIPE__


/*
	the pipe. contain 2 sockets
*/



#include "winsock2.h"
#include "Mswsock.h"
#include "Ws2tcpip.h"
// #include "windows.h"


extern "C" {
	#include "crypto\proto_crypt.h"
	#include "crypto\crypto_entropy.h"
}



#define BUFFER_SIZE (4096)
#define PACKAGE_SIZE (1024)

typedef struct PipeOperation {
	OVERLAPPED overlapped;
	int socket;
	enum OpType {
		CONNECT_TARGET = 0,
		RECV_SOURCE = 1,
		SEND_SOURCE = 2,
		RECV_TARGET = 3,
		SEND_TARGET = 4
	} Type;
	char buffer[BUFFER_SIZE];
	DWORD transferred;
	DWORD remain;
	char * end;
} PipeOperation;

typedef struct PipeConfig {
	char * source;
	char * target;
	sockaddr_in target_addr;
	sockaddr_in source_addr;
	int decr;
	proto_secret * K;
}PipeConfig;


class Pipe;

typedef int (Pipe::*pipefunc)(PipeOperation *);

/*
	handshake FSM, transform by incrementing the status value
*/
typedef struct HandshakeStatus {
	enum hsStatus {
		SENDING_NONCE = 0,
		RECVING_NONCE = 1,
		SENDING_DMAC = 2,
		RECVING_DMAC = 3,
		MIXING = 4,
		TOTAL = 5,
	};
	int trans_condition;
	pipefunc fp;
} HandshakeStatus;

class Pipe {

private:
	DWORD op_ref;
	int s;
	int t;
	PipeOperation Ops[5];
	int Decr;
	proto_secret * K;
	int HandshakeDone;
	HandshakeStatus::hsStatus CurrentShaking;
	HandshakeStatus Handshakes[HandshakeStatus::TOTAL];
	uint8_t nonce_local[PCRYPT_NONCE_LEN];
	uint8_t nonce_remote[PCRYPT_NONCE_LEN];
	uint8_t dhmac_local[PCRYPT_DHMAC_LEN];
	uint8_t dhmac_remote[PCRYPT_DHMAC_LEN];
	uint8_t yh_local[PCRYPT_YH_LEN];
	uint8_t yh_remote[PCRYPT_YH_LEN];
	uint8_t x[PCRYPT_X_LEN];
	proto_keys * client_key;
	proto_keys * server_key;
	PipeConfig * conf;
private:
	PipeOperation * InitOperation(PipeOperation::OpType type);
	void CheckError(int code, int line);
	int Pipeling(DWORD byteTransferred, PipeOperation * Operation);
	int HandShake(DWORD byteTransferred, PipeOperation * Operation);
	int ShakingIt(PipeOperation * Operation);
	int SendNonce(PipeOperation * preOperation);
	int RecvNonce(PipeOperation * preOperation);
	int SendDmac(PipeOperation * preOperation);
	int RecvDmac(PipeOperation * preOperation);
	int Mixing(PipeOperation * preOperation);
	int ShakeItOff();
	int StartHandshake();
	int StartPipeling();

public:
	int RecvSource(int offset, int need_size, int max_size);
	int RecvTarget(int offset, int need_size, int max_size);
	int SendSource(char * buffer, int len);
	int SendTarget(char * buffer, int len);
	int ConnectTarget();
	int Process(DWORD byteTransferred, PipeOperation * Operation);
	Pipe(int s, int t, PipeConfig * conf);
	void OpRelease();
	void OpRef();
	void Close();
	int Init();
	virtual ~Pipe();
};

#endif
