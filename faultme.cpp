#include <assert.h>
#include <err.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <link.h>
#include <getopt.h>
#include <pinktrace/pink.h>
#include "link_locate.h"
#include <asm/ptrace.h>
#include <iostream>
#include <fstream>
#include <set>
#include <string.h>
using namespace std;

#define MAX_STRING_LEN 128

struct child {
	pid_t pid;
	pink_bitness_t bitness;
	bool insyscall;
	bool dead;
};


set<string> syscalls;
set<string> callsites;

void corrupt_return(pid_t pid)
{
  struct pt_regs *regs = (struct pt_regs *)malloc(sizeof(struct pt_regs) *2);
  pink_util_get_regs(pid, regs);
  printf("Old RAX: %ld\n", (long)(regs->rax)); 
  regs->rax = -1;
  printf("New RAX: %ld\n", (long)(regs->rax)); 
  
  pink_util_set_regs(pid, regs);
  free(regs);
}

/* Utility functions */
static void
print_ret(pid_t pid)
{
	long ret;

	if (!pink_util_get_return(pid, &ret)) {
		perror("pink_util_get_return");
		return;
	}

	if (ret >= 0)
		printf("= %ld", ret);
	else
		printf("= %ld (%s)", ret, strerror(-ret));
}

static void
print_open_flags(long flags)
{
	long aflags;
	bool found;

	found = true;

	/* Check out access flags */
	aflags = flags & 3;
	switch (aflags) {
	case O_RDONLY:
		printf("O_RDONLY");
		break;
	case O_WRONLY:
		printf("O_WRONLY");
		break;
	case O_RDWR:
		printf("O_RDWR");
		break;
	default:
		/* Nothing found */
		found = false;
	}

	if (flags & O_CREAT) {
		printf("%s | O_CREAT", found ? "" : "0");
		found = true;
	}

	if (!found)
		printf("%#x", (unsigned)flags);
}

/* A very basic decoder for open(2) system call. */
static void
decode_open(pid_t pid, pink_bitness_t bitness)
{
	long flags;
	char buf[MAX_STRING_LEN];

	if (!pink_decode_string(pid, bitness, 0, buf, MAX_STRING_LEN)) {
		perror("pink_decode_string");
		return;
	}
	if (!pink_util_get_arg(pid, bitness, 1, &flags)) {
		perror("pink_util_get_arg");
		return;
	}

	printf("open(\"%s\", ", buf);
	print_open_flags(flags);
	fputc(')', stdout);
}

/* A very basic decoder for execve(2) system call. */
static void
decode_execve(pid_t pid, pink_bitness_t bitness)
{
	bool nil;
	unsigned i;
	long arg;
	char buf[MAX_STRING_LEN];
	const char *sep;

	if (!pink_decode_string(pid, bitness, 0, buf, MAX_STRING_LEN)) {
		perror("pink_decode_string");
		return;
	}
	if (!pink_util_get_arg(pid, bitness, 1, &arg)) {
		perror("pink_util_get_arg");
		return;
	}

	printf("execve(\"%s\", [", buf);

	for (i = 0, nil = false, sep = "";;sep = ", ") {
		if (!pink_decode_string_array_member(pid, bitness, arg, ++i, buf, MAX_STRING_LEN, &nil)) {
			perror("pink_decode_string_array_member");
			return;
		}
		printf("%s", sep);
		fputc('"', stdout);
		printf("%s", buf);
		fputc('"', stdout);

		if (nil) {
			printf("], envp[])");
			break;
		}
	}
}

/* A very basic decoder for bind() and connect() calls */
static void
decode_socketcall(pid_t pid, pink_bitness_t bitness, const char *scname)
{
	long fd, subcall;
	const char *path, *subname;
	char ip[100];
	pink_socket_address_t addr;

	subcall = -1;
	if (pink_has_socketcall(bitness) && !pink_decode_socket_call(pid, bitness, &subcall)) {
		perror("pink_decode_socket_call");
		return;
	}

	if (subcall > 0) {
	  subname = pink_name_socket_subcall((pink_socket_subcall_t)subcall);
		if (!(!strcmp(subname, "bind") || !strcmp(subname, "connect"))) {
			/* Print the name only */
			printf("%s()", subname);
			return;
		}
	}

	if (!pink_decode_socket_address(pid, bitness, 1, &fd, &addr)) {
		perror("pink_decode_socket_address");
		return;
	}

	printf("%s(%ld, ", (subcall > 0) ? subname : scname, fd);

	switch (addr.family) {
	case -1: /* NULL */
		printf("NULL");
		break;
	case AF_UNIX:
		printf("{sa_family=AF_UNIX, path=");
		path = addr.u.sa_un.sun_path;
		if (path[0] == '\0' && path[1] != '\0') /* Abstract UNIX socket */
			printf("\"@%s\"}", ++path);
		else
			printf("\"%s\"}", path);
		break;
	case AF_INET:
		inet_ntop(AF_INET, &addr.u.sa_in.sin_addr, ip, sizeof(ip));
		printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}", ntohs(addr.u.sa_in.sin_port), ip);
		break;
#if PINKTRACE_HAVE_IPV6
	case AF_INET6:
		inet_ntop(AF_INET6, &addr.u.sa6.sin6_addr, ip, sizeof(ip));
		printf("{sa_family=AF_INET6, sin_port=htons(%d), sin6_addr=inet_addr(\"%s\")}", ntohs(addr.u.sa6.sin6_port), ip);
		break;
#endif /* PINKTRACE_HAVE_IPV6 */
#if PINKTRACE_HAVE_NETLINK
	case AF_NETLINK:
		printf("{sa_family=AF_NETLINK, nl_pid=%d, nl_groups=%08x}", addr.u.nl.nl_pid, addr.u.nl.nl_groups);
		break;
#endif /* PINKTRACE_HAVE_NETLINK */
	default: /* Unknown family */
		printf("{sa_family=???}");
		break;
	}

	printf(", %u)", addr.length);
}

static int
handle_syscall(struct child *son)
{
	long scno;
	const char *scname;

	if (!pink_util_get_syscall(son->pid, son->bitness, &scno)) {
	  perror("pink_util_get_syscall");
	  return 0;
	}

	scname = pink_name_syscall(scno, son->bitness);
	if(!syscalls.empty() && !syscalls.count(scname)){
	  return 0;
	}

	string res = get_callchain_id(son->pid);
	if(callsites.count(res) && !son->insyscall){
	 
	  printf("%s Seen it before\n", scname);
	  return 0;
	}
	callsites.insert(res);
	
	/* We get this event twice, one at entering a
	 * system call and one at exiting a system
	 * call. */
	if (son->insyscall) {
		/* Exiting the system call, print the
		 * return value. */

	  
		son->insyscall = false;
		fputc(' ', stdout);
		print_ret(son->pid);
		fputc('\n', stdout);
		printf("Should corrupt now\n");
		corrupt_return(son->pid);
		return 1;
	}
	else {
		/* Get the system call number and call
		 * the appropriate decoder. */
		son->insyscall = true;
		
		if (!scname)
			printf("%ld()", scno);
		else if (!strcmp(scname, "open"))
			decode_open(son->pid, son->bitness);
		else if (!strcmp(scname, "execve"))
			decode_execve(son->pid, son->bitness);
		else if (!strcmp(scname, "socketcall") || !strcmp(scname, "bind") || !strcmp(scname, "connect"))
			decode_socketcall(son->pid, son->bitness, scname);
		else
			printf("%s()", scname);
		
		
		return 0;
	}
}

void print_usage() {
  printf("Usage: faultme [-a pid | program [arguments ...]]");
}


int
main(int argc, char **argv)
{
	int sig, status, exit_code;
	pink_event_t event;
	struct child son;
	char *syscall_file = NULL;
	int option = 0;
	int result = 0;
	int callsites_tracked = 0;
	while ((option = getopt(argc, argv,"s:")) != -1) {
	  switch (option) {
	  case 's' : syscall_file = optarg;
	    break;

	  default: print_usage(); 
	    exit(EXIT_FAILURE);
	  }
	}

	
	int x = 0;
	
	if(syscall_file){
	  string line;
	  ifstream infile (syscall_file);
	  if(infile.is_open()){
	    while(getline(infile, line)){
	      syscalls.insert(line);
	    }
	    infile.close();
	  }
	}


	/* Parse arguments */
	while (callsites_tracked == 0 || callsites_tracked != callsites.size()){
	    /* Fork */
	  callsites_tracked = callsites.size();
	    if ((son.pid = fork()) < 0) {
	      perror("fork");
	      return EXIT_FAILURE;
	    }
	    else if (!son.pid) { /* child */
	      /* Set up for tracing */
	      if (!pink_trace_me()) {
		perror("pink_trace_me");
		_exit(EXIT_FAILURE);
	      }
	      /* Stop and let the parent continue the execution. */
	      kill(getpid(), SIGSTOP);
	      
	      //++argv;
	      personality(ADDR_NO_RANDOMIZE);
	      char *filename = (char *) malloc(2000);
	      time_t rawtime;
	      struct tm * timeinfo;

	      time (&rawtime);
	      timeinfo = localtime (&rawtime);

	      strftime (filename,2000,"output_%F_%I%M%p",timeinfo);

	      int fd = open(filename,O_RDWR | O_APPEND | O_CREAT, 0666);
	      if(fd == -1){
		perror("couldn't open output file\n");
		_exit(EXIT_FAILURE);
	      }
	      free(filename);
	      /* handle failure of open() somehow */ 
	      write(fd,"--CHILD--\n", 11);
	      //dup2(fd,1); 
	      //dup2(fd,2);
	      execvp(argv[optind], &argv[optind]);
	      perror("execvp");
	      _exit(-1);
	    }

	//This becomes straightline code now :)
	      waitpid(son.pid, &status, 0);
	      unsigned long symtab;
	      unsigned long strtab;
	      int nchains;

	      //	      unsigned long addr = find_sym_in_tables(son.pid, map, "malloc", symtab, strtab, nchains);
	      //printf("Address %x\n", addr);
	      event = pink_event_decide(status);
	      assert(event == PINK_EVENT_STOP);
	      
	      /* Set up the tracing options. */
	      if (!pink_trace_setup(son.pid, PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC)) {
		perror("pink_trace_setup");
		pink_trace_kill(son.pid);
		return EXIT_FAILURE;
	      }
	      
	      /* Figure out the bitness of the traced child. */
	      son.bitness = pink_bitness_get(son.pid);
	      if (son.bitness == PINK_BITNESS_UNKNOWN)
		err(EXIT_FAILURE, "pink_bitness_get");
	      printf("Child %i runs in %s mode\n", son.pid, pink_bitness_name(son.bitness));
	      
	      son.dead = son.insyscall = false;
	      sig = exit_code = 0;


	      struct link_map *map = locate_linkmap(son.pid);
	      resolv_tables(son.pid, map, &symtab, &strtab, &nchains);
	      unsigned long addr = find_sym_in_tables(son.pid, map, "malloc", symtab, strtab, nchains);


	      for (;;) {
		/* At this point the traced child is stopped and needs
		 * to be resumed.
		 */
		if(!result){
		  if (!pink_trace_syscall(son.pid, sig)) {
		    perror("pink_trace_syscall");
		    return (errno == ESRCH) ? 0 : 1;
		  }
		}
		else{
		  printf("Syscall recorded on first run...we continue now\n");
		  //if (!pink_trace_syscall(son.pid, sig)) {
		  if(!pink_trace_cont(son.pid, sig, NULL)){
		    perror("pink_trace_cont");
		    return (errno == ESRCH) ? 0 : 1;
		  }
		}
		sig = 0;
		
		/* Wait for the child */
		if ((son.pid = waitpid(son.pid, &status, 0)) < 0) {
		  perror("waitpid");
		  return (errno == ECHILD) ? 0 : 1;
		}
		
		/* Check the event. */
		event = pink_event_decide(status);
		switch (event) {
		case PINK_EVENT_SYSCALL:

		  result = handle_syscall(&son);
		  //printf("result is %d\n", result);
		  break;
		  break;

		case PINK_EVENT_EXEC:
		  /* Update bitness */
		  son.bitness = pink_bitness_get(son.pid);
		  if (son.bitness == PINK_BITNESS_UNKNOWN)
		    err(EXIT_FAILURE, "pink_bitness_get");
		  else
		    printf(" (Updating the bitness of child %i to %s mode)\n",
			   son.pid, pink_bitness_name(son.bitness));

		  break;
		case PINK_EVENT_GENUINE:
		case PINK_EVENT_UNKNOWN:
		  /* Send the signal to the traced child as it
		   * was a genuine signal.
		   */
		  printf("UNKNOWN\n");
		  sig = WSTOPSIG(status);
		  break;
		case PINK_EVENT_EXIT_GENUINE:

		  exit_code = WEXITSTATUS(status);
		  printf("Child %i exited normally with return code %d\n",
			 son.pid, exit_code);
		  result = 0;
		  son.dead = true;
		  break;
		case PINK_EVENT_EXIT_SIGNAL:
		  exit_code = 128 + WTERMSIG(status);
		  printf("Child %i exited with signal %d\n",
			 son.pid, WTERMSIG(status));
		  result = 0;
		  son.dead = true;
		  break;
		default:
		  /* Nothing */
		  printf("default\n");
		}
		if (son.dead)
		  break;
	      }
	      x++;
	}	      
	printf("Had %ld unique callsites\n", callsites.size());
	return exit_code;	  
}
