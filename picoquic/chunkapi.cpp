#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/pem.h>
#include "chunkapi.h"
#include "chunkapi.pb.h"
#include "Xsecurity.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string content_dir = "/tmp/content/";
const uint32_t default_chunk_size = 1024 * 1024;
const uint32_t default_ttl = 0;
const char *xcache_api_port = "6666";

void hex_digest(const unsigned char* digest, unsigned digest_len, char* hex_string, int hex_string_len)
{
    int i;
	assert(digest != NULL);
	assert(hex_string != NULL);
	assert(hex_string_len == SHA_DIGEST_LENGTH*2+1);
	assert(digest_len == SHA_DIGEST_LENGTH);
    for(i=0; i < digest_len; i++) {
        sprintf(&hex_string[2*i], "%02x", (unsigned int)digest[i]);
    }
    hex_string[hex_string_len-1] = '\0';
}



bool chunk_is_valid(std::string cid, const unsigned char *data, uint32_t length)
{
	unsigned char digest[SHA_DIGEST_LENGTH];
	char digest_string[SHA_DIGEST_LENGTH*2+1];

	SHA1(data, length, digest);
	hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));

	return cid == digest_string;
}



int load_chunk(std::string cid, std::vector<uint8_t>& data)
{
	struct stat info;
	int rc;
	std::string path = content_dir + cid;

	if (stat(path.c_str(), &info) < 0 || info.st_size == 0) {
		return -2;
	}
	printf("\n\nfetching %s: size = %ld\n", path.c_str(), info.st_size);

	FILE *f = fopen(path.c_str(), "rb");

	printf("found file\n");

	data.reserve(info.st_size);
	int offset = 0;

	if (!f) {
		return -3;
	}


	while (!feof(f)) {
		printf("reading offset = %d\n", offset);
		unsigned char *p = data.data();
		rc = fread(p + offset, 1, info.st_size, f);
		offset += rc;
	}

	printf("done,  offset = %d data %d\n", offset, (int)data.size());
	return info.st_size;
}



std::string write_chunk(const unsigned char *buf, uint32_t byte_count)
{
	unsigned char digest[SHA_DIGEST_LENGTH];
	char digest_string[SHA_DIGEST_LENGTH*2+1];

	SHA1(buf, byte_count, digest);

	// FIXME: this doesn't check for file vs dir problem
	if (mkdir(content_dir.c_str(), 0777) < 0 && errno != EEXIST) {
		printf( "%s\n", strerror(errno));
		return "";
	}
	hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));

	std::string chunk_name = content_dir + digest_string;

	FILE *cf = fopen(chunk_name.c_str(), "wb");
	if (cf == NULL) {
		return "";
	}

	fwrite(buf, 1, byte_count, cf);
	fclose(cf);

	return std::string(digest_string);
}



cid_list_t make_chunks(std::string filename, uint32_t chunk_size)
{
	struct stat fs;
	cid_list_t cids;

	if (stat(filename.c_str(), &fs) != 0) {
		return cids;
	}

	FILE *f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		return cids;
	}

	unsigned count = fs.st_size / chunk_size;
	if (fs.st_size % chunk_size) {
		count ++;
	}

	unsigned char *buf = (unsigned char *)malloc(chunk_size);
	if (!buf) {
		fclose(f);
		return cids;
	}

	unsigned byte_count;
	std::string cid;

	while (!feof(f)) {
		if ((byte_count = fread(buf, sizeof(unsigned char), chunk_size, f)) > 0) {
			if ((cid = write_chunk(buf, byte_count)) == "") {
				fclose(f);
				// FIXME: this leaves orphan chunks on disk, delete what's in the list?
				//  but could potentially delete valid chunk from other file
				cids.clear();
				return cids;
			}

			cids.emplace_back(cid);
		}
	}

	free(buf);
	fclose(f);
	return cids;
}



//
// Tell the xcache daemon about the chunks and add them to the routing table
//
//
chunk_status post_cids(cid_list_t cids, uint32_t ttl)
{
	int rc;

	if (cids.empty()) {
		return failure;
	}

	ChunkAPI::chunk_list list;

	list.set_ttl(ttl);

	for (cid_list_t::iterator it = cids.begin(); it != cids.end(); it++) {

		list.add_cids(*it);
	}

	std::string message;
	list.SerializeToString(&message);

	struct addrinfo *ai;
	int s = socket(AF_INET, SOCK_STREAM, 0);

	getaddrinfo("localhost", xcache_api_port, NULL, &ai);

	rc = connect(s, ai->ai_addr, sizeof(sockaddr_in));

	int l = htonl(message.length());
	rc = send(s, &l, sizeof(l), 0);

	rc = send(s, message.c_str(), message.length(), 0);
	close(s);
	freeaddrinfo(ai);
	return success;
}



cid_list_t put(const char *buffer, uint32_t size, uint32_t chunk_size, uint32_t ttl)
{
	cid_list_t cids;
	std::string cid;

	uint32_t num_chunks = size / chunk_size;
	if (size % chunk_size) {
		num_chunks++;
	}

	const unsigned char *p = (const unsigned char *)buffer;
	uint32_t bytes_remaining = size;
	for (uint32_t i = 0; i < num_chunks; ++i) {

		uint32_t count = (bytes_remaining < chunk_size) ? bytes_remaining : chunk_size;
		if ((cid = write_chunk(p, count)) == "") {
			cids.clear();
			return cids;
		}
		cids.emplace_back(cid);
		p += chunk_size;
		bytes_remaining -= chunk_size;
	}

	post_cids(cids, ttl);
	return cids;
}


void get_chunk(const void *data)
{

	const callback_context *cc = (callback_context *)data;

	// strip everything but the cid hash from the sting
	std::string dag = cc->dag;
	size_t found = dag.find("CID:");
    if (found != std::string::npos) {

		// skip over the CID: part too
		found += 4;

		dag.replace(0, found, "");
    }


	// FIXME: temp place holder, invoke new interface to quic instead
	// quic will actuall be who makes this callbaxck call
	cc->cb(success, dag, "data", cc->user_data);
}



cid_list_t put_file(std::string filename, uint32_t chunk_size, uint32_t ttl)
{
	cid_list_t cids;

	cids = make_chunks(filename, chunk_size);

	post_cids(cids, ttl);
	return cids;
}



chunk_status push(std::string cid, std::string *dest, chunk_callback callback, void *user_context)
{
	return success;
}



chunk_status push_list(cid_list_t cids, std::string dest, chunk_callback callback, void *user_context)
{

	return queued;
}



chunk_status pull(std::string dag, chunk_callback callback, void *user_context)
{

	return success;
}



void make_manifest(cid_list_t cids, std::string dag, std::string src_file, uint32_t ttl)
{
	json j;
	json cid_array;

	// name of the source file that was chunked
	j["file"] = src_file;

	// time to live before purging
	if (ttl > 0) {
		j["ttl"] = ttl;
	}

	// the chunk list is just bare chunch hashes, so convert to a useable address
	if (dag.empty()) {
		dag = "CID:";
	} else {
		dag += " CID:";
	}

	// list of chunk DAG/CIDs
	for (cid_list_t::iterator it = cids.begin(); it != cids.end(); it++) {

		std::string cid_dag = dag + *it;
		cid_array.emplace_back(cid_dag);
	}

	j["chunks"] = cid_array;

	std::ofstream f(src_file + ".manifest");
	f << j.dump(3) << std::endl;
}



std::vector<std::string> load_manifest(std::string manifest)
{
	// FIXME: this should also return base filename and ttl
	std::ifstream f(manifest);
	std::stringstream buf;
	buf << f.rdbuf();

	json j = json::parse(buf);
	std::vector<std::string> dags = j["chunks"];

//	std::cout << j.dump(3) << std::endl;
	return dags;
}

