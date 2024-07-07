#pragma once

#include <global.h>

typedef struct {
	int help;
	int mode;       /* 0 - encryption ; 1 - decryption */
	int security;   /* 0 - interactive ; 1 - moderate ; 2 - sensitive */
	int mesh_key;
	size_t files_count;
	std::vector<char*> files;
} ETHANIUM_ARGS;

extern std::string ETHANIUM_HELP;

class ArgsParser {
private:
	ETHANIUM_ARGS args;

public:
	ArgsParser();
	bool StructArgs(int argc, char* argv[]);
	ETHANIUM_ARGS GetArgs();
};