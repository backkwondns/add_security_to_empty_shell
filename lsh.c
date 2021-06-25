/***************************************************************************//**

  @file         main.c

  @author       Stephen Brennan

  @date         Thursday,  8 January 2015

  @brief        LSH (Libstephen SHell)

*******************************************************************************/

#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termio.h>
#include <dirent.h>
#include <time.h>

#define MAX_LOGIN 1
#define BUF_SIZE 1024

/*
  Function Declarations for builtin shell commands:
 */
int lsh_cd(char **args);
int lsh_help(char **args);
int lsh_exit(char **args);

/*
  추가함수선언
*/
int get_pid(char *s);
int check_logon(char* ip_addr);
void login(char* ip_addr);
int white_list(char* ip_addr);
void store_login_log(char* log);
void store_failed_log(char* log);

/*
  List of builtin commands, followed by their corresponding functions.
 */
char *builtin_str[] = {
  "cd",
  "help",
  "exit",
};

int (*builtin_func[]) (char **) = {
  &lsh_cd,
  &lsh_help,
  &lsh_exit,
};

int lsh_num_builtins() {
  return sizeof(builtin_str) / sizeof(char *);
}

/*
  Builtin function implementations.
*/

/**
   @brief Bultin command: change directory.
   @param args List of args.  args[0] is "cd".  args[1] is the directory.
   @return Always returns 1, to continue executing.
 */
int lsh_cd(char **args)
{
  if (args[1] == NULL) {
    fprintf(stderr, "lsh: expected argument to \"cd\"\n");
  } else {
    if (chdir(args[1]) != 0) {
      perror("lsh");
    }
  }
  return 1;
}

/**
   @brief Builtin command: print help.
   @param args List of args.  Not examined.
   @return Always returns 1, to continue executing.
 */
int lsh_help(char **args)
{
  int i;
  printf("Stephen Brennan's LSH\n");
  printf("Type program names and arguments, and hit enter.\n");
  printf("The following are built in:\n");

  for (i = 0; i < lsh_num_builtins(); i++) {
    printf("  %s\n", builtin_str[i]);
  }

  printf("Use the man command for information on other programs.\n");
  return 1;
}

/**
   @brief Builtin command: exit.
   @param args List of args.  Not examined.
   @return Always returns 0, to terminate execution.
 */
int lsh_exit(char **args)
{
  return 0;
}

/**
  @brief Launch a program and wait for it to terminate.
  @param args Null terminated list of arguments (including program).
  @return Always returns 1, to continue execution.
 */
int lsh_launch(char **args)
{
  pid_t pid;
  int status;

  pid = fork();
  if (pid == 0) {
    // Child process
    if (execvp(args[0], args) == -1) {
      perror("lsh");
    }
    exit(EXIT_FAILURE);
  } else if (pid < 0) {
    // Error forking
    perror("lsh");
  } else {
    // Parent process
    do {
      waitpid(pid, &status, WUNTRACED);
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }

  return 1;
}

/**
   @brief Execute shell built-in or launch program.
   @param args Null terminated list of arguments.
   @return 1 if the shell should continue running, 0 if it should terminate
 */
int lsh_execute(char **args)
{
  int i;

  if (args[0] == NULL) {
    // An empty command was entered.
    return 1;
  }

  for (i = 0; i < lsh_num_builtins(); i++) {
    if (strcmp(args[0], builtin_str[i]) == 0) {
      return (*builtin_func[i])(args);
    }
  }

  return lsh_launch(args);
}

/**
   @brief Read a line of input from stdin.
   @return The line from stdin.
 */
char *lsh_read_line(void)
{
#ifdef LSH_USE_STD_GETLINE
  char *line = NULL;
  ssize_t bufsize = 0; // have getline allocate a buffer for us
  if (getline(&line, &bufsize, stdin) == -1) {
    if (feof(stdin)) {
      exit(EXIT_SUCCESS);  // We recieved an EOF
    } else  {
      perror("lsh: getline\n");
      exit(EXIT_FAILURE);
    }
  }
  return line;
#else
#define LSH_RL_BUFSIZE 1024
  int bufsize = LSH_RL_BUFSIZE;
  int position = 0;
  char *buffer = malloc(sizeof(char) * bufsize);
  int c;

  if (!buffer) {
    fprintf(stderr, "lsh: allocation error\n");
    exit(EXIT_FAILURE);
  }

  while (1) {
    // Read a character
    c = getchar();

    if (c == EOF) {
      exit(EXIT_SUCCESS);
    } else if (c == '\n') {
      buffer[position] = '\0';
      return buffer;
    } else {
      buffer[position] = c;
    }
    position++;

    // If we have exceeded the buffer, reallocate.
    if (position >= bufsize) {
      bufsize += LSH_RL_BUFSIZE;
      buffer = realloc(buffer, bufsize);
      if (!buffer) {
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
      }
    }
  }
#endif
}

#define LSH_TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"
/**
   @brief Split a line into tokens (very naively).
   @param line The line.
   @return Null-terminated array of tokens.
 */
char **lsh_split_line(char *line)
{
  int bufsize = LSH_TOK_BUFSIZE, position = 0;
  char **tokens = malloc(bufsize * sizeof(char*));
  char *token, **tokens_backup;

  if (!tokens) {
    fprintf(stderr, "lsh: allocation error\n");
    exit(EXIT_FAILURE);
  }

  token = strtok(line, LSH_TOK_DELIM);
  while (token != NULL) {
    tokens[position] = token;
    position++;

    if (position >= bufsize) {
      bufsize += LSH_TOK_BUFSIZE;
      tokens_backup = tokens;
      tokens = realloc(tokens, bufsize * sizeof(char*));
      if (!tokens) {
		free(tokens_backup);
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
      }
    }

    token = strtok(NULL, LSH_TOK_DELIM);
  }
  tokens[position] = NULL;
  return tokens;
}

/**
   @brief Loop getting input and executing it.
 */
void lsh_loop(void)
{
  char *line;
  char **args;
  int status;

  do {
    printf("> ");
    line = lsh_read_line();
    args = lsh_split_line(line);
    status = lsh_execute(args);

    free(line);
    free(args);
  } while (status);
}

int get_pid(char *s)
{
	int len, i;
	
	len = strlen(s);
	for(i=0;i<len;i++)
	{
	  if((s[i] < '0' || s[i] > '9'))
		{
			return -1;
		}
	}
	return atoi(s);
}

int getch(void)
{
	int ch;							 
	struct termios buf;
	struct termios save;

	tcgetattr(0, &save);
	buf = save;
	buf.c_lflag &= ~(ICANON|ECHO);
	buf.c_cc[VMIN] = 1;
	buf.c_cc[VTIME] = 0;
	tcsetattr(0, TCSAFLUSH, &buf);
	ch = getchar();	
	tcsetattr(0, TCSAFLUSH, &save);
	return ch;
}

int check_logon(char* ip_addr)
{
	DIR *dp;
	struct dirent *dir;
	char buf[BUF_SIZE], line[BUF_SIZE], tag[BUF_SIZE], name[BUF_SIZE], log[BUF_SIZE];
	char program_name[BUF_SIZE] = "lsh";
	int pid;
	int logon_count = 0;
	FILE *fp;
	time_t now;
	char *cur_time;

	dp = opendir("/proc");
	if(!dp)
	{
		return -1;
	}
	
	
	while((dir = readdir(dp)) != NULL)
	{
		pid = get_pid(dir->d_name);

		if(pid == -1)
		{
			continue;
		}

		snprintf(buf, 100, "/proc/%d/status", pid);
		fp = fopen(buf, "r");
		if(fp == NULL)
		{
			continue;
		}

		fgets(line, BUF_SIZE, fp);
		fclose(fp);
		sscanf(line, "%s %s", tag, name);
		
		if(strcmp(name, program_name) == 0)
		{
			logon_count += 1;
			if(logon_count == MAX_LOGIN + 1)
			{
				printf("이미실행중입니다.\n");
				time(&now);
				cur_time = ctime(&now);
				cur_time[strlen(cur_time)-1]='\0';
				sprintf(log, "%s FULL LOGIN %s\n", cur_time, ip_addr);
				store_failed_log(log);
				return 1;
			}
		}
	}
	closedir(dp);
	return 0;
}

int white_list(char* ip_addr)
{
	FILE *fp;
	char list_ip[BUF_SIZE][BUF_SIZE];
	char log[BUF_SIZE];
	char *cur_time;
	time_t now;
	int i, lines;

	fp = fopen("list", "r");
	
	if(fp == NULL)
	{
		printf("error! block all IP\n");
		exit(0);
	}

	i = 0;

	while(fgets(list_ip[i], BUF_SIZE, fp))
	{
		list_ip[i][strlen(list_ip[i]) - 1] = '\0';
		i++;
	}


	for (int lines=0;lines<i;lines++)
	{
		if(strcmp(list_ip[lines], ip_addr) == 0)
		{
			return 0;
		}
	}
  printf("NOT ALLOWED IP\n");
	
	time(&now);
	cur_time = ctime(&now);
	cur_time[strlen(cur_time)-1]='\0';
	sprintf(log, "%s NOT ALLOWED IP %s\n", cur_time, ip_addr);
	store_failed_log(log);
	return 1;
}



void store_login_log(char* log)
{
	FILE *fp;
	fp = fopen("login_log", "a");
	
	if(fp == NULL)
	{
		printf("error! failed to write log\n");
		exit(0);
	}

	fwrite(log, strlen(log), 1,fp);
}

void store_failed_log(char* log)
{
	FILE *fp;
	fp = fopen("failed_log", "a");

	if(fp == NULL)
	{
		printf("error! failed to write log\n");
		exit(0);
	}

	fwrite(log, strlen(log), 1, fp);
}


void login(char* ip_addr)
{
	FILE *fp;
	char data_account[BUF_SIZE], data_id[BUF_SIZE * 2], data_pw[BUF_SIZE * 2];
	char input_id[BUF_SIZE], input_pw[BUF_SIZE*2], enc_str_pw[BUF_SIZE*2], log[BUF_SIZE], single_pw;
	int i, n;
	char *cur_time;
	time_t now;

	fp = fopen("data", "r");	
	fgets(data_account, BUF_SIZE, fp);
	fclose(fp);
	sscanf(data_account, "%s : %s", data_id, data_pw);
	
	printf("ID : ");
	fgets(input_id, sizeof(input_id), stdin);
	input_id[strlen(input_id)-1]='\0'; //개행문자제거
	printf("PW : ");
	
	for(i=0; i<11; i++)
	{
		single_pw = getch();
		if((int)single_pw == 10)
		{
			break;
		}
		input_pw[i] = single_pw;
	}

	int enc_pw[strlen(input_pw)*2];

	for(i=0;i<strlen(input_pw);i++)
	{
		enc_pw[2*i] = (input_pw[i]-1);
		enc_pw[2*i+1] = 46-1;
	}

	for(i = 0;i<sizeof(enc_pw)/sizeof(int);i++)
	{
		sprintf(enc_str_pw, "%s%d", enc_str_pw, enc_pw[i]);
	}
	
	if((strcmp(data_id, input_id)) == 0 && (strcmp(data_pw, enc_str_pw)) == 0)
	{
		printf("\n로그인완료\n");
		time(&now);
		cur_time = ctime(&now);
		cur_time[strlen(cur_time)-1]='\0';
		sprintf(log, "%s Login at %s\n", cur_time, ip_addr);
		printf("%s", log);
		store_login_log(log);
	}
	else
	{
		printf("\n로그인실패\n");
		time(&now);
		cur_time = ctime(&now);
		cur_time[strlen(cur_time)-1]='\0';
		sprintf(log, "%s Login failed at %s\n", cur_time, ip_addr);
		store_failed_log(log);
		exit(0);
	}
}

/**
   @brief Main entry point.
   @param argc Argument count.
   @param argv Argument vector.
   @return status code
 */
int main(int argc, char **argv)
{

	int check_result, IP_result;
	char* s = getenv("SSH_CLIENT");
	char CLIENT_IP[BUF_SIZE], CLIENT_PORT[BUF_SIZE], SERVER_PORT[BUF_SIZE];
	
	sscanf(s, "%s %s %s", CLIENT_IP, CLIENT_PORT, SERVER_PORT);

	IP_result = white_list(CLIENT_IP);
	if(IP_result ==1)
	{
		exit(0);
	}

	check_result = check_logon(CLIENT_IP);
	if(check_result == 1)
	{
		exit(0);
	}

	login(CLIENT_IP);


  // Load config files, if any.

  // Run command loop.
  lsh_loop();

  // Perform any shutdown/cleanup.

  return EXIT_SUCCESS;
}

