// winspiped.cpp : 定义控制台应用程序的入口点。
//

// #include "stdafx.h"


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include "Core.h"
#include "Pipe.h"


#define VERSION "1.0"


void usage(void)
{
	fprintf(stderr,
		"usage: spiped {-e | -d} -s <source socket> "
		"-t <target socket> -k <key file>\n"
		"       spiped -v\n");
	exit(1);
}

void version(void)
{
	fprintf(stderr,
		"The windows version spiped, winspiped %s\n"
		"https://github.com/Tarsnap/spiped\n",
		VERSION);
	exit(1);
}



char * read_arg(int argc, char *argv[]) {
	static int position = 1;
	if (position > argc - 1) {
		return NULL;
	}
	char * arg = argv[position++];
	return arg;
}



int main(int argc, char * argv[])
{ 
	char * source_str = 0;
	char * target_str = 0;
	int decr = -1;
	char * key_file = 0;
	int show_version = 0;
	while (1) {
		char * arg = read_arg(argc, argv);
		if (!arg) {
			break;
		} else if (!strcmp(arg, "-d")) {
			decr = 1;
		} else if (!strcmp(arg, "-e")) {
			decr = 0;
		} else if (!strcmp(arg, "-s")) {
			char * value = read_arg(argc, argv);
			if (!value) {
				break;
			}
			source_str = value;
		} else if (!strcmp(arg, "-t")) {
			char * value = read_arg(argc, argv);
			if (!value) {
				break;
			}
			target_str = value;
		} else if (!strcmp(arg, "-k")) {
			char * value = read_arg(argc, argv);
			if (!value) {
				break;
			}
			key_file = value;
		} else if (!strcmp(arg, "-v")) {
			show_version = 1;
		} else {
			// some invalid args
			usage();
			exit(-1);
		}

	}
	// check that all args are parsed
	if (!show_version && (!source_str || !target_str || ! key_file || decr == -1)) {
		usage();
		exit(-1);
	}
	if (show_version) {
		version();
		exit(0);
	}
	// check that all args are parsed
	PipeConfig  conf = {};
	// read the keyfile
	conf.K = proto_crypt_secret(key_file);
	if (!conf.K) {
		printf("can't read the keyfile %s\n", key_file);
		exit(-1);
	}
	conf.decr = decr;
	conf.target = target_str;
	conf.source = source_str;
	
	char * target_port = strrchr(target_str, ':') + 1;
	*(target_port - 1) = 0;
	char * source_port = strrchr(source_str, ':') + 1;
	*(source_port - 1) = 0;
	conf.source_addr.sin_family = AF_INET;
	conf.target_addr.sin_family = AF_INET;
	inet_pton(AF_INET, source_str, &conf.source_addr.sin_addr);
	inet_pton(AF_INET, target_str, &conf.target_addr.sin_addr);

	unsigned short port = atoi(source_port);
	conf.source_addr.sin_port =  htons(port);
	port = atoi(target_port);
	conf.target_addr.sin_port = htons(port);


	Core * server = new Core();
	server->Init(&conf.source_addr);
	server->Start(&conf);
	return 0;
}


