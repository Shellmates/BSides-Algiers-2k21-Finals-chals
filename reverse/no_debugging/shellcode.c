//#include <fcntl.h>
int main()
{

int fd = open("/proc/self/status", O_RDONLY, 0);

char buf[32];
int i;

while (1)
{
  if (read(fd, buf, 4) != 4) break;
  if (*(unsigned int*) buf == 0x63617254)
  {
    if (read(fd, buf, 7) != 7) break;
    if (*(unsigned int*) buf == 0x69507265 && buf[4] == 'd')
    {
       i = 0;
       while (1)
       {
         if (read(fd, buf+i, 1) != 1) break;
         if (buf[i] == 0xa) break;
         i++;
       }
       int pid = 0;
       int pow = 1;
       while (--i >= 0)
       {
          pid += (buf[i] - '0') * pow;
          pow *= 10;
       }
       if (pid != 0) kill(pid, 14);
       return pid ^ 0x44190000;
    }
  }
  else
  {
    while (read(fd, buf, 1) == 1 && buf[0] != 0xa);
  }
}
  return 0x44190000;
}
