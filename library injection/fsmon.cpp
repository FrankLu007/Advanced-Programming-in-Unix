#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h> 
#include <fcntl.h>

FILE * output = NULL;
int (* printer)(FILE *fp, const char * str, ...) = (int (*)(FILE *fp, const char * str, ...))dlsym(RTLD_NEXT, "fprintf");//, trash = setvbuf(output, NULL, _IOFBF, 0);

void init()
{
	char * file = getenv("MONITOR_OUTPUT");
	if(file)
	{
		if(access(file, F_OK) != -1) (* (int (*)(const char * filename)) dlsym(RTLD_NEXT, "remove"))(file);
		(* (int (*)(int fd1, int fd2)) dlsym(RTLD_NEXT, "dup2"))((* (int (*)(const char * filename, int flag, ...)) dlsym(RTLD_NEXT, "open"))(file, O_WRONLY | O_CREAT, 0777), 2);
	}
	printer = (int (*)(FILE *fp, const char * str, ...)) dlsym(RTLD_NEXT, "fprintf");
	output = stderr;
}
char * convert(int fd)
{
	static char tmp[1024], path[128];
	memset(tmp, 0, 1024);
	memset(path, 0, 128);
	sprintf(path, "/proc/self/fd/%d", fd);
	(* (ssize_t (*)(const char * filename, char * buffer, size_t size)) dlsym(RTLD_NEXT, "readlink"))(path, tmp, 1024);
	return strdup(tmp);
}
char * convert(FILE *fp)
{
	if(fp == stdin) return strdup("<STDIN>");
	else if(fp == stdout) return strdup("<STDOUT>");
	else if(fp == stderr) return strdup("<STDERR>");
	return convert(fileno(fp));
}
char * convert(DIR * dir) {return convert(dirfd(dir));}
char * convert(struct stat * state)
{
	static char str[1024];
	memset(str, 0, 1024);
	sprintf(str, "%p {mode=%05o, size=%ld}", state, state->st_mode & 07777, state->st_size);
	return strdup(str);
}
int closedir(DIR * dir)
{
	if(!output) init();
	(* printer)(output, "# closedir(\"%s\")", convert(dir));
	int ret = (* (int (*)(DIR * dir)) dlsym(RTLD_NEXT, "closedir"))(dir);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
DIR * opendir(const char * filename)
{
	if(!output) init();
	(* printer)(output, "# opendir(\"%s\")", filename);
	DIR * ret = (* (DIR * (*)(const char * filename)) dlsym(RTLD_NEXT, "opendir"))(filename);
	(* printer)(output, " = %s\n", strtok(convert(ret), "\""));
	return ret;
}
struct dirent * readdir(DIR * dir)
{
	if(!output) init();
	(* printer)(output, "# readdir(\"%s\")", convert(dir));
	struct dirent * ret = (* (struct dirent * (*)(DIR * dir)) dlsym(RTLD_NEXT, "readdir"))(dir);
	if(ret) (* printer)(output, " = %s\n", ret->d_name);
	else (* printer)(output, " = NULL\n");
	return ret;
}
int creat(const char * filename, mode_t mode)
{
	if(!output) init();
	(* printer)(output, "# creat(\"%s\", %05o)", filename, mode);
	int ret = (* (int (*)(const char * filename, mode_t mode)) dlsym(RTLD_NEXT, "creat"))(filename, mode);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int open(const char * filename, int flag, ...)
{
	if(!output) init();
	mode_t mode;
	int ret;
	va_list al;
	va_start(al, flag);
	mode = va_arg(al, mode_t);
	va_end(al);
	if(mode > 0777) 
	{
		(* printer)(output, "# open(\"%s\", %d)", filename, flag);
		ret = (* (int (*)(const char * filename, int flag, ...)) dlsym(RTLD_NEXT, "open"))(filename, flag);
	}
	else 
	{
		(* printer)(output, "# open(\"%s\", %d, %05o)", filename, flag, mode);
		ret = (* (int (*)(const char * filename, int flag, ...)) dlsym(RTLD_NEXT, "open"))(filename, flag, mode);
	}
	(* printer)(output, " = %d\n", ret);
	return ret;
}
ssize_t read(int fd, void * buffer, size_t count)
{
	if(!output) init();
	(* printer)(output, "# read(\"%s\", %p, %u)", convert(fd), buffer, count);
	ssize_t ret = (* (ssize_t (*)(int fd, void * buffer, size_t count)) dlsym(RTLD_NEXT, "read"))(fd, buffer, count);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
ssize_t write(int fd, const void * buffer, size_t count)
{
	if(!output) init();
	(* printer)(output, "# write(\"%s\", %p, %u)", convert(fd), buffer, count);
	ssize_t ret = (* (ssize_t (*)(int fd, const void * buffer, size_t count)) dlsym(RTLD_NEXT, "write"))(fd, buffer, count);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int dup(int fd)
{
	if(!output) init();
	(* printer)(output, "# dup(\"%s\")", convert(fd));
	int ret = (* (int (*)(int fd)) dlsym(RTLD_NEXT, "dup"))(fd);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int dup2(int fd1, int fd2)
{
	if(!output) init();
	(* printer)(output, "# dup2(\"%s\", \"%s\")", convert(fd1), convert(fd2));
	int ret = (* (int (*)(int fd1, int fd2)) dlsym(RTLD_NEXT, "dup2"))(fd1, fd2);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int close(int fd)
{
	if(!output) init();
	if(fd == fileno(output))
	{
		(* printer)(output, "# close(\"%s\") = 0\n", convert(fd));
		(* (int (*)(int fd)) dlsym(RTLD_NEXT, "close"))(fd);
		return 0;
	}
	(* printer)(output, "# close(\"%s\")", convert(fd));
	int ret = (* (int (*)(int fd)) dlsym(RTLD_NEXT, "close"))(fd);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int __lxstat(int ver, const char * filename, struct stat * state)
{
	if(!output) init();
	int ret = (* (int (*)(int ver, const char * filename, struct stat * state)) dlsym(RTLD_NEXT, "__lxstat"))(ver, filename, state);
	(* printer)(output, "# lstat(\"%s\", %s) = %d\n", filename, convert(state), ret);
	return ret;
}
int __xstat(int ver, const char * filename, struct stat * state)
{
	if(!output) init();
	int ret = (* (int (*)(int ver, const char * filename, struct stat * state)) dlsym(RTLD_NEXT, "__xstat"))(ver, filename, state);
	(* printer)(output, "# stat(\"%s\", %s) = %d\n", filename, convert(state), ret);
	return ret;
}
ssize_t pwrite(int fd, const void * buffer, size_t count, off_t offset)
{
	if(!output) init();
	ssize_t ret = (* (ssize_t (*)(int fd, const void * buffer, size_t count, off_t offset)) dlsym(RTLD_NEXT, "pwrite"))(fd, buffer, count, offset);
	(* printer)(output, "# pwrite(\"%s\", %p, %u, %u) = %d\n", convert(fd), buffer, count, offset, ret);
	return ret;
}
FILE * fopen(const char * filename, const char * mode)
{
	if(!output) init();
	FILE * ret = (* (FILE * (*)(const char * filename, const char * mode)) dlsym(RTLD_NEXT, "fopen"))(filename, mode);
	(* printer)(output, "# fopen(\"%s\", \"%s\") = %s\n", filename, mode, convert(ret));
	return ret;
}
int fclose(FILE * fp)
{
	if(!output) init();
	if(fp == stderr)
	{
		(* printer)(output, "# fclose(\"<STDERR>\") = 0\n");
		return 0;
	}
	else (* printer)(output, "# fclose(\"%s\")", convert(fp));
	int ret = (* (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fclose"))(fp);
	if (fp != stderr) (* printer)(output, " = %d\n", ret);
	return ret;
}
int fgetc(FILE * fp)
{
	if(!output) init();
	int ret = (* (int (*)(FILE * fp)) dlsym(RTLD_NEXT, "fgetc"))(fp);
	(* printer)(output, "# fgetc(\"%s\") = %d\n", convert(fp), ret);
	return ret;
}
char * fgets(char * buffer, int size, FILE * fp)
{
	if(!output) init();
	char * ret = (* (char * (*)(char * buffer, int size, FILE * fp)) dlsym(RTLD_NEXT, "fgets"))(buffer, size, fp);
	(* printer)(output, "# fgets(%p, %d, \"%s\") = %s\n", buffer, size, convert(fp), ret);
	return ret;
}
int fprintf(FILE *fp, const char * str, ...)
{
	if(!output) init();
	(* printer)(output, "# fprintf(\"%s\", \"%s\", ...)", convert(fp), str);
	va_list al;
	va_start(al, str);
	int ret = (* (int (*)(FILE *fp, const char * str, va_list arg)) dlsym(RTLD_NEXT, "vfprintf"))(fp, str, al);
	va_end(al);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int fscanf(FILE * fp, const char * str, ...)
{
	if(!output) init();
	(* printer)(output, "# fscanf(\"%s\", \"%s\", ...)", convert(fp), str);
	va_list al;
	va_start(al, str);
	int ret = (* (int (*)(FILE *fp, const char * str, va_list arg)) dlsym(RTLD_NEXT, "vfscanf"))(fp, str, al);
	va_end(al);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
extern "C"{
	int __isoc99_fscanf(FILE * fp, const char * str, ...)
	{
		if(!output) init();
		(* printer)(output, "# fscanf(\"%s\", \"%s\", ...)", convert(fp), str);
		va_list al;
		va_start(al, str);
		int ret = (* (int (*)(FILE *fp, const char * str, va_list arg)) dlsym(RTLD_NEXT, "vfscanf"))(fp, str, al);
		va_end(al);
		(* printer)(output, " = %d\n", ret);
		return ret;
	}
}
size_t fwrite(const void * buffer, size_t size, size_t count, FILE * fp)
{
	if(!output) init();
	(* printer)(output, "# fwrite(%p, %u, %u, \"%s\")", buffer, size, count, convert(fp));
	size_t ret = (* (size_t (*)(const void * buffer, size_t size, size_t count, FILE * fp)) dlsym(RTLD_NEXT, "fwrite"))(buffer, size, count, fp);
	(* printer)(output, " = %u\n", ret);
	return ret;
}
size_t fread(const void * buffer, size_t size, size_t count, FILE * fp)
{
	if(!output) init();
	(* printer)(output, "# fread(%p, %u, %u, \"%s\")", buffer, size, count, convert(fp));
	size_t ret = (* (size_t (*)(const void * buffer, size_t size, size_t count, FILE * fp)) dlsym(RTLD_NEXT, "fread"))(buffer, size, count, fp);
	(* printer)(output, " = %u\n", ret);
	return ret;
}
int chdir(const char * filename)
{
	if(!output) init();
	(* printer)(output, "# chdir(\"%s\")", filename);
	int ret = (* (int (*)(const char * filename)) dlsym(RTLD_NEXT, "chdir"))(filename);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int chown(const char * filename, uid_t owner, gid_t group)
{
	if(!output) init();
	(* printer)(output, "# chown(\"%s\", %u, %u)", filename, owner, group);
	int ret = (* (int (*)(const char * filename, uid_t owner, gid_t group)) dlsym(RTLD_NEXT, "chown"))(filename, owner, group);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int chmod(const char * filename, mode_t mode)
{
 	if(!output) init();
 	(* printer)(output, "# chmod(\"%s\", %05o)", filename, mode);
	int ret = (* (int (*)(const char * filename, mode_t mode)) dlsym(RTLD_NEXT, "chmod"))(filename, mode);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int remove(const char * filename)
{
 	if(!output) init();
 	(* printer)(output, "# remove(\"%s\")", filename);
	int ret = (* (int (*)(const char * filename)) dlsym(RTLD_NEXT, "remove"))(filename);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int rename(const char * filename1, const char * filename2)
{
 	if(!output) init();
	(* printer)(output, "# rename(\"%s\", \"%s\")", filename1, filename2);
	int ret = (* (int (*)(const char * filename1, const char * filename2)) dlsym(RTLD_NEXT, "rename"))(filename1, filename2);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int link(const char * filename1, const char * filename2)
{
	if(!output) init();
	(* printer)(output, "# link(\"%s\", \"%s\")", filename1, filename2);
	int ret = (* (int (*)(const char * filename1, const char * filename2)) dlsym(RTLD_NEXT, "link"))(filename1, filename2);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int unlink(const char * filename)
{
	if(!output) init();
	(* printer)(output, "# unlink(\"%s\")", filename);
	int ret = (* (int (*)(const char * filename)) dlsym(RTLD_NEXT, "unlink"))(filename);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
ssize_t readlink(const char * filename, char * buffer, size_t size)
{
	if(!output) init();
	(* printer)(output, "# readlink(\"%s\", %p, %u)", filename, buffer, size);
	ssize_t ret = (* (ssize_t (*)(const char * filename, char * buffer, size_t size)) dlsym(RTLD_NEXT, "readlink"))(filename, buffer, size);
	(* printer)(output, " = %u\n", ret);
	return ret;
}
int symlink(const char * filename1, const char * filename2)
{
	if(!output) init();
	(* printer)(output, "# symlink(\"%s\", \"%s\")", filename1, filename2);
	int ret = (* (int (*)(const char * filename1, const char * filename2)) dlsym(RTLD_NEXT, "symlink"))(filename1, filename2);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int mkdir(const char * filename, mode_t mode)
{
	if(!output) init();
	(* printer)(output, "# mkdir(\"%s\", %05o)", filename, mode);
	int ret = (* (int (*)(const char * filename, mode_t mode)) dlsym(RTLD_NEXT, "mkdir"))(filename, mode);
	(* printer)(output, " = %d\n", ret);
	return ret;
}
int rmdir(const char * filename)
{
	if(!output) init();
	(* printer)(output, "# rmdir(\"%s\")", filename);
	int ret = (* (int (*)(const char * filename)) dlsym(RTLD_NEXT, "rmdir"))(filename);
	(* printer)(output, " = %d\n", ret);
	return ret;
}