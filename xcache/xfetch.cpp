#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <mutex>
#include <condition_variable>
#include <string>
#include <thread>
#include <vector>
#include <iostream>
#include <fstream>
#include "chunkapi.h"
#include "xcache_quic_client.h"

bool verbose = false;				// minimal output
bool waiting = true;
std::string manifest;
std::string dag;
std::mutex mtx;
std::condition_variable cv;


void help()
{
	printf("usage: xfetch [-v] [-m manifest] [-d dag]]\n");
	printf("where:\n");
	printf("  -v          : enable verbose output\n");
	printf("  -m manifest : fetch chunks listed in the manifest file\n");
	printf("  -d dag      : fetch the chunk specified by dag\n");
	printf("  -h          : display this help\n");
	exit(1);
}



void say(const char *fmt, ...)
{
	if (verbose) {
		va_list args;

		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}
}



void warn(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);

}




void die(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	exit(1);
}



int config(int argc, char **argv)
{
    int opt;
	while ((opt = getopt(argc, argv, "hvm:d:")) != -1) {
		switch (opt) {
		case 'h':
			help();
			break;
		case 'm':
			manifest = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'd':
			dag = optarg;
			break;
		}
	}

	if (manifest.empty() && dag.empty()) {
		// nothing specified
		help();
	}
}


//
// simple example callback that just writes the chunk to disk
//
void my_callback(uint32_t status, std::string cid, std::string data, void *user_context)
{

	switch(status) {
		case success:
			std::cout << "success!: " << cid << std::endl;
			break;
		case queued:
			// shouldn't be valid here!
			std::cout << "queued: " << cid << std::endl;
			break;
		case timeout:
			std::cout << "timeout: " << cid << std::endl;
			break;
		case failure:
			std::cout << "fetch failed: " << cid << std::endl;
			break;
		default:
			std::cout << "unknown: " << cid << std::endl;
	}

	// write the chunk to the current directory using the cid as the name
	if (status == success && !data.empty()) {
		std::ofstream f( "/tmp/" + cid);
		f << data;
	}

	printf("\nUNLOCKING\n");
	std::unique_lock<std::mutex> lck(mtx);
	waiting = false;
	cv.notify_all();
	printf("\nUNLOCKED\n");
}



int fetch(std::string dag)
{
	chunk_context_t cc;

	std::cout << "fetching: " << dag << std::endl;
	waiting = true;

	cc.dag = dag;
	cc.cb = my_callback;
	cc.user_data = NULL;

	std::thread worker(get_chunk, (void *)&cc);
	worker.detach();

	std::unique_lock<std::mutex> lck(mtx);
	printf("\nBLOCKING wiating = %d\n", waiting);
	while (waiting) {
		cv.wait(lck);
	}
	printf("UNBLOCKED\n");
}



int main(int argc, char **argv)
{
	config(argc, argv);

	if (!manifest.empty()) {
		cid_list_t cids = load_manifest(manifest);
		for (std::vector<std::string>::iterator it = cids.begin(); it != cids.end(); it++) {
			fetch(*it);
		}
	} else if (!dag.empty()) {
		fetch(dag);
	} else {
		help();
	}

//	quicclient();

	return 0;
}

