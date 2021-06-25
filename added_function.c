#include <stdio.h>
#include <stdlib.h>
#include <termio.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#define MAX_LOGIN 1
#define BUF_SIZE 1024

int get_pid(char *s);
int check_logon(char* ip_addr);
void login(char* ip_addr);
int white_list(char* ip_addr);
void store_login_log(char* log);
void store_failed_log(char* log);

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

void main()
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
	
}
