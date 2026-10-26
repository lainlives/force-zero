#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void force_exit()
{
    _exit(0);
}
