#ifndef _chunkapi_h
#define _chunkapi_h

#include <string>
#include <vector>
#include <map>
//#include <sqlite3.h>

using namespace std;
#include "chunkhash.h"

struct chunkMeta {
    std::string chunkid;
	std::string fpath;
	int fsize;
};

typedef std::vector <std::string> cid_list_t;

void print_chunklst(const vector<string>& cid_list_t);
cid_list_t put(const char *buffer, uint32_t size, uint32_t chunk_size, uint32_t ttl);
cid_list_t put_file(std::string filename, uint32_t chunk_size, uint32_t ttl);
bool valid_chunk_signature (std::string ncid_sign, std::string publisherName, std::string contentName, std::vector<uint8_t>& data);
bool valid_chunk_data (std::string sCid, std::vector<uint8_t>& chunk_data);
std::string load_chunk(std::string cid, std::vector<uint8_t>& data);
map<std::string, chunkMeta> get_mapOfchunks (std::string path);
chunkhash_table* initHashtable (const vector<string>& cid_list_t);

#endif // _chunkapi_h