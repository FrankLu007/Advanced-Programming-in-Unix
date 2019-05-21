#include "libmini.h"

void QQ(int n) {write(1, "QQ\n", 3);}
void GG(int n) {write(1, "GG\n", 3);}

int main()
{
	sigset_t s;
	signal(SIGINT, QQ);
	signal(SIGALRM, GG);
	alarm(3);
	sigemptyset(&s);
	sigaddset(&s, SIGALRM);
	sigprocmask(SIG_BLOCK, &s, NULL);
	pause();
}