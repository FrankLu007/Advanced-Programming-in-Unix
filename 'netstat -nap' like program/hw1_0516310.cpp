#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string.h>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <arpa/inet.h>
#include <regex>
#include <vector>
#include <getopt.h>

typedef std::string string;

class INFO
{
public:
	string local, foreign, command, pid;
	void clear()
	{
		local.clear();
		foreign.clear();
		command.clear();
		pid.clear();
	}
}info;

std::vector <std::regex> filter;
std::unordered_map <unsigned, INFO> data[4]; // tcp, tcp6, udp, udp6
char str[10000];

void collect(const char *path, std::unordered_map <unsigned, INFO> &data_set)
{
	FILE *fp = fopen(path, "r");
	unsigned addr[4], port, af = path[strlen(path)-1] == '6' ? AF_INET6 : AF_INET, inode;
	data_set.clear();
	std::fgets(str, 10000, fp);
	while(std::fscanf(fp, "%s", str) != EOF)
	{
		info.clear();
		if(af == AF_INET) std::fscanf(fp, "%x:%x", &addr[0], &port);
		else std::fscanf(fp, "%8x%8x%8x%8x:%x", &addr[0], &addr[1], &addr[2], &addr[3], &port);
		info.local = string(inet_ntop(af, &addr, str, 10000));
		info.local += string(":") + (port ? std::to_string(port) : string("*"));
		
		if(af == AF_INET) std::fscanf(fp, "%x:%x", &addr[0], &port);
		else std::fscanf(fp, "%8x%8x%8x%8x:%x", &addr[0], &addr[1], &addr[2], &addr[3], &port);
		info.foreign = string(inet_ntop(af, &addr, str, 10000));
		info.foreign += string(":") + (port ? std::to_string(port) : string("*"));
		
		for(int i = 0 ; i < 6 ; i++) fscanf(fp, "%s", str);
		std::fscanf(fp, "%u", &inode);
		std::fgets(str, 10000, fp);
		data_set[inode] = info;
	}
}
int find(unsigned inode)
{
	for(int i = 0 ; i < 4 ; i++) if(data[i].find(inode) != data[i].end()) return i;
	return -1;
}
bool match(const char *str)
{
	for(int i = 0 ; i < filter.size() ; i++) if(regex_match(str, filter[i])) return true;
	return false;
}
int main(int argc, const char **argv)
{
	const char opt[] = "tu";
	const struct option opts[] = {
        {"tcp", 0, NULL, 't'},
        {"udp", 0, NULL, 'u'},
        {0, 0, 0, 0}
    };
	bool show_tcp = 1, show_udp = 1;
	filter.clear();
	for(int arg = getopt_long(argc, (char *__getopt_argv_const *)argv, opt, opts, NULL) ; arg != -1 ; arg = getopt_long(argc, (char *__getopt_argv_const *)argv, opt, opts, NULL))
	{
		if(arg == 'u') show_tcp = 0;
		else if(arg == 't') show_udp = 0;
	}
	for(int i = 1 ; i < argc ; i++) if(argv[i][0] != '-') filter.push_back(std::regex(argv[i]));
	if(!(show_tcp || show_udp)) show_udp = show_tcp = true;
	
	if(show_tcp) {collect("/proc/net/tcp", data[0]); collect("/proc/net/tcp6", data[1]);}
	if(show_udp) {collect("/proc/net/udp", data[2]); collect("/proc/net/udp6", data[3]);}

	FILE *cmdline;
	string path("/proc/"), path_link;
	struct dirent *file, *link;
	DIR *dir = opendir(path.c_str()), *fd;
	unsigned inode;
	int type;
	while(file = readdir(dir))
	{
		if(file->d_name[0] < '0' || file->d_name[0] > '9') continue;
		path_link = path + string(file->d_name) + string("/fd/");
		fd = opendir(path_link.c_str());
		while(link = readdir(fd))
		{
			std::memset(str, 0, 10000);
			if(readlink((path_link + string(link->d_name)).c_str(), str, 10000) == -1) continue;
			if(std::strncmp(str, "socket:[", 8) && std::strncmp(str, "[0000]:", 7)) continue;
			if(!std::strncmp(str, "socket:[", 8))
			{
				std::strtok(str, "[");
				inode = std::atoi(std::strtok(NULL, "]"));
			}
			else
			{
				std::strtok(str, ":");
				inode = std::atoi(std::strtok(NULL, "]"));
			}
			if((type = find(inode)) == -1) continue;
			cmdline = std::fopen((path + string(file->d_name) + string("/cmdline")).c_str(), "r");
			fgets(str, 10000, cmdline);
			data[type][inode].command = string(str);
			data[type][inode].command.erase(0, data[type][inode].command.find_last_of("/") + 1);
			data[type][inode].pid = string(file->d_name);

		}
	}

	std::unordered_map <unsigned, INFO>::iterator it;
	if(show_tcp)
	{
		std::printf("List of TCP connections:\nProto Local Address           Foreign Address         PID/Program name and arguments\n");
		for(it = data[0].begin() ; it != data[0].end() ; it++) if(!filter.size() || match(it->second.command.c_str())) std::printf("%-5s %-23s %-23s %s/%s\n", "tcp", it->second.local.c_str(), it->second.foreign.c_str(), it->second.pid.c_str(), it->second.command.c_str());
		for(it = data[1].begin() ; it != data[1].end() ; it++) if(!filter.size() || match(it->second.command.c_str())) std::printf("%-5s %-23s %-23s %s/%s\n", "tcp6", it->second.local.c_str(), it->second.foreign.c_str(), it->second.pid.c_str(), it->second.command.c_str());
	}
	if(show_udp)
	{
		if(show_tcp) std::printf("\n");
		std::printf("List of UDP connections:\nProto Local Address           Foreign Address         PID/Program name and arguments\n");
		for(it = data[2].begin() ; it != data[2].end() ; it++) if(!filter.size() || match(it->second.command.c_str())) std::printf("%-5s %-23s %-23s %s/%s\n", "udp", it->second.local.c_str(), it->second.foreign.c_str(), it->second.pid.c_str(), it->second.command.c_str());
		for(it = data[3].begin() ; it != data[3].end() ; it++) if(!filter.size() || match(it->second.command.c_str())) std::printf("%-5s %-23s %-23s %s/%s\n", "udp6", it->second.local.c_str(), it->second.foreign.c_str(), it->second.pid.c_str(), it->second.command.c_str());
	}
	return 0;
}