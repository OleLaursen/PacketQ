#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <errno.h>
#include <unistd.h>

#include "cache.h"
#include "md5.h"

namespace se
{

int mkpath(std::string path)
{
    struct stat sb;
    if (stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)) // fast path
        return 0;

    mode_t mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;
    size_t pre = 0, pos;
    std::string dir;
    int mdret = 0;

    if (path[path.size() - 1] != '/') {
        // force trailing / so we can handle everything in loop
        path += '/';
    }

    while ((pos = path.find_first_of('/', pre)) != std::string::npos)
    {
        dir = path.substr(0, pos++);
        pre = pos;
        if (dir.size() == 0)
            continue; // if leading / first time is 0 length
        if ((mdret = mkdir(dir.c_str(), mode)) && errno != EEXIST)
            return mdret;
    }
    return mdret;
}

std::string compute_cache_path(std::string cache_dir,
                               std::vector<std::string> queries,
                               std::vector<std::string> in_files,
                               PacketQ::OutputOpts output_opts)
{
    // cache_dir is assumed to end with a /

    std::string cache_key = "";

    for (auto i = queries.begin(); i != queries.end(); ++i)
    {
        cache_key += *i + "|";
    }

    for (auto i = in_files.begin(); i != in_files.end(); ++i)
    {
        cache_key += *i + "|";
    }

    cache_key += std::to_string(output_opts) + "|";

    // hash key
    unsigned char md5_result[16];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, cache_key.c_str(), cache_key.size());
    MD5_Final(md5_result, &ctx);

    char hash[33];
    for (int i = 0; i < 16; ++i)
        sprintf(&hash[i * 2], "%02x", (unsigned int)md5_result[i]);
    hash[32] = '\0';

    // add extension
    std::string cache_path = cache_dir + std::string(hash);
    switch (output_opts)
    {
    case PacketQ::json: cache_path += ".json"; break;
    case PacketQ::csv: cache_path += ".csv"; break;
    case PacketQ::csv_format: cache_path += ".csv"; break;
    case PacketQ::xml: cache_path += ".xml"; break;
    }

    return cache_path;
}

// returns false if cache input couldn't be read
bool write_output_from_cache_input(std::string cache_file_path, std::ostream &output)
{
    std::ifstream cache_input(cache_file_path.c_str(), std::ios::binary);
    if (!cache_input)
        return false;

    const int BUFSIZE = 4096;
    char buf[BUFSIZE];
    do {
        cache_input.read(buf, BUFSIZE);
        if (cache_input.gcount() > 0)
            output.write(buf, cache_input.gcount());
    }
    while (cache_input);

    return true;
}

}
