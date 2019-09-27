#ifndef _chunkapi_h
#define _chunkapi_h

#include <string>
#include <vector>

// user defined callback
typedef void (*chunk_callback)(uint32_t status, std::string cid, std::string data, void *user_context);

enum chunk_status {
	success = 1,
	queued,
	timeout,
	failure
};

typedef struct {

	std::string dag;
	chunk_callback cb;
	void *user_data;
	bool block;
} callback_context;

typedef std::vector <std::string> cid_list_t;

cid_list_t put(const char *buffer, uint32_t size, uint32_t chunk_size, uint32_t ttl);
cid_list_t put_file(std::string filename, uint32_t chunk_size, uint32_t ttl);

chunk_status push(std::string cid, std::string *dest, chunk_callback callback, void *user_context);
chunk_status push_list(cid_list_t cids, std::string dest, chunk_callback callback, void *user_context);
chunk_status pull(std::string dag, chunk_callback callback, void *user_context);
void get_chunk(const void *cc);

void make_manifest(cid_list_t cids, std::string dag, std::string src_file, uint32_t ttl = 0);
std::vector<std::string> load_manifest(std::string manifest);

bool chunk_is_valid(std::string cid, const unsigned char *data, uint32_t length);

int load_chunk(std::string cid, std::vector<uint8_t>& data);

#endif // _chunkapi_h

