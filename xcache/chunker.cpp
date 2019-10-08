#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <string>
#include <vector>
#include <iostream>

#include "chunkapi.h"


bool verbose = false;				// minimal output
bool create_manifest = false;		// don't create manifest by default
unsigned chunk_size = 1024 * 1024;	// default chunk size = 1mb
unsigned ttl = 0;					// chunks live forever
std::string dag;

void help()
{
	printf("usage: chunker [-v] [-m [-t ttl] [-d dag]] [-s size] filename [filename ...]\n");
	printf("where:\n");
	printf("  -v      : enable verbose output\n");
	printf("  -m      : create a manifest file\n");
	printf("  -s size : specify chunk size (default = 1m)\n");
	printf("  -t ttl  : time to live in seconds (0=infinite)\n");
	printf("  -d dag  : root DAG to use to create fully qualified addresses\n");
	printf("  -h      : display this help\n");
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
	while ((opt = getopt(argc, argv, "hmvs:d:t:")) != -1) {
		switch (opt) {
		case 'h':
			help();
			break;
		case 'm':
			create_manifest = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 's':
		{
			unsigned cs = atoi(optarg);
			if (cs > 0) {
				chunk_size = cs;
			} else {
				die("invalid chunk size %s", optarg);
			}
		}
		break;
		case 't':
		{
			unsigned t = atoi(optarg);
			if (t > 0) {
				ttl = t;
			} else {
				die("invalid ttl duration: %s", optarg);
			}
		}
		break;
		case 'd':
			dag = optarg;
			break;
		}
	}

	if (argc == optind) {
		// no files specified!
		help();
	}

	say("chunk size : %u\n", chunk_size);
	return optind;
}




int chunk(std::string filename)
{
	say("chunking: %s...\n", filename.c_str());

	cid_list_t chunks = put_file(filename, chunk_size, ttl);

	if (create_manifest == true) {
		make_manifest(chunks, dag, filename, ttl);
	}

	return 0;
}



int main(int argc, char **argv)
{
	int next = config(argc, argv);

	// loop through filenames
	while (next < argc) {
		std::string fname = argv[next];

		std::cout << fname << std::endl;
		chunk(fname);

		std::vector<std::string>dags = load_manifest(fname + ".manifest");
		for (std::vector<std::string>::iterator it = dags.begin(); it != dags.end(); it++) {
			std::cout << *it << std::endl;

		}
		next++;
	}

	return 0;
}
