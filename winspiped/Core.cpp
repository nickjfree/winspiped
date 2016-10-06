#include "stdafx.h"
#include "Core.h"

// #include "Mswsock.h"
#include "Pipe.h"
#include "info.h"


Core::Core()
{
}


Core::~Core()
{
}

/*
	worker loop
*/
int WINAPI Core::Loop(Core * core) {
	while (1) {
		int ret = 0;
		PipeOperation * Operation = NULL;
		DWORD Transferred = 0;
		Pipe * pipe = 0;
		ret = GetQueuedCompletionStatus(core->hCompletionPort, &Transferred, (PULONG_PTR)&pipe, (LPOVERLAPPED *)&Operation, INFINITE);
		if (!ret) {
			int code = GetLastError();
			info_out("something wrong with  %d in pipe %x\n", code, pipe);
			switch (code) {
			case ERROR_CONNECTION_REFUSED:
				info_out("connected to remote end failed ERROR_CONNECTION_REFUSED\n");
				pipe->OpRelease();
				break;
			default:
				pipe->OpRelease();
				break;
			}
		} else {
			if (pipe) {
				// process data
				pipe->Process(Transferred, Operation);
			}

		}


	}
	return 0;
}


/*
	Listen on port
*/
int Core::Init(sockaddr_in * addrServer) {
	WSADATA wsadata = {};
	WSAStartup(0x201, &wsadata);

	listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	int ret = 0;
	ret = bind(listen_socket, (SOCKADDR*)addrServer, sizeof(SOCKADDR));
	ret = listen(listen_socket, 128);

	// create iocompletion port
	hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 4);

	// worker threads
	int cores = 4;
	while (cores--) {
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop, this, 0, 0);
	}
	return 0;
}


int Core::OnAccept(int s, sockaddr_in * client, PipeConfig * conf) {
	char addr_str[128];
	inet_ntop(AF_INET, &client->sin_addr, addr_str, 128);
	info_out("connection from %s\n", addr_str);

	// create pip structure and issue a connection to remote end
	int t = socket(AF_INET, SOCK_STREAM, 0);
	Pipe * pipe = new Pipe(s, t, conf);
	// associate s and t to port
	int ret = 0;
	DWORD opvalue = 1;
	ret = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opvalue, sizeof(opvalue));
	ret = setsockopt(t, SOL_SOCKET, SO_KEEPALIVE, (char*)&opvalue, sizeof(opvalue));
	HANDLE hPort = CreateIoCompletionPort((HANDLE)t, hCompletionPort, (ULONG_PTR)pipe, 0);
	hPort = CreateIoCompletionPort((HANDLE)s, hCompletionPort, (ULONG_PTR)pipe, 0);
	pipe->ConnectTarget();
	return 0;
}


int Core::Start(PipeConfig * conf) {
	SOCKET Accepted = -1;
	sockaddr_in addr = {};
	int addr_len = sizeof(addr);
	while (1) {
		Accepted = accept(listen_socket, (sockaddr *)&addr, &addr_len);
		OnAccept(Accepted, &addr, conf);
	}
	return 0;
}
