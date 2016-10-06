#ifndef __CORE__
#define __CORE__


//#include "windows.h"
#include "winsock2.h"

#include "Pipe.h"


extern "C" {
#include "crypto\proto_crypt.h"
}


/*
	network core class
*/

class Core {

private:
	// the completion port
	HANDLE hCompletionPort;
	int listen_socket;
private:
	// on accept
	virtual int OnAccept(int s, sockaddr_in * client, PipeConfig * conf);
	static int WINAPI Loop(Core * core);
public:
	int Init(sockaddr_in * addr);
	int Start(PipeConfig * conf);
	Core();
	virtual ~Core();
};

#endif
