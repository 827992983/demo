#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/wait.h> 
#include <sys/stat.h>

#define MAX_LINE 80

int getInput(char input[], char history[]){
	printf("osh>");
	fflush(stdout);
	fgets(input,MAX_LINE,stdin);
	input[strlen(input)-1]='\0';
	if(strcmp(input, "!!") == 0){
		if(strlen(history) != 0){
			printf("%s\n", history);
			strcpy(input, history);
		}
		else{
			printf("No command in history!!!\n");
			return -1;
		}
	}
	else if(strcmp(input,"exit")==0)
		return 0;
	if(strlen(input) > 0){
		strcpy(history, input);
	}
	return 1;
}

void execArgs(char *args[], int len){
	__pid_t child_pid;
	int flag=0;
	if(*args[len-1]=='&'){
		flag=1;
		args[len-1]=NULL;
		len--;
	}
	child_pid=fork();
	if(child_pid == 0) {
		if(len >= 3){
			if(strcmp(args[len - 2], ">" ) == 0){
				args[len - 2] = NULL;
				int out = open(args[len - 1], O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IRGRP | S_IWGRP | S_IWUSR);
				dup2(out, STDOUT_FILENO);
				close(out);
			}            
			else if(strcmp(args[len- 2], "<" ) == 0){ 
				args[len - 2] = NULL;
				int in = open(args[len - 1], O_RDONLY);
				dup2(in, STDIN_FILENO);
				close(in);
			}
		}
		if (execvp(args[0], args) < 0){
			printf("\nCould not execute in command...");
		}
		exit(1);

	}
	else if(child_pid > 0){
		if (flag==0)
		{
			wait(NULL);
		}
		return;
	}else {
		printf("\nCan't fork!!!");
		return;
	}
}

int parseInput(char *args[], char input[]){
	int count = 0;
	char *tok = strtok(input," ");
	while(tok != NULL){
		args[count++] = tok;
		tok = strtok(NULL, " ");
	}
	args[count] = tok;
	return count;
}

int checkPipe(char *args[], int len){
	for(int i = 0; i < len; i++){
		if(strcmp(args[i], "|") == 0)
			return i;
	}
	return -1;
}

void execArgsPipe(char *args[], char *argsPipe[], int flag){
	__pid_t pid;

	int fd[2];
	if(pipe(fd) < 0){
		printf("\nCan't init pipe!!!!");
		return;
	}
	pid = fork();

	if(pid == 0){
		dup2(fd[1], STDOUT_FILENO);
		close(fd[0]);
		close(fd[1]);
		if(execvp(args[0],args) < 0){
			printf("\nCan't execute pipe 1...");
		}
		exit(1);
	}else if(pid >0){

		pid = fork();
		if(pid == 0){
			dup2(fd[0], STDIN_FILENO);
			close(fd[1]);
			close(fd[0]);
			if(execvp(argsPipe[0], argsPipe) < 0){
				printf("\nCan't execute pipe 2...");
			}

			exit(1);
		}
		else if(pid > 0){
			int status;
			close(fd[0]);
			close(fd[1]);
			if(flag==0)
				waitpid(pid, &status, 0);
			return;
		}
		else {
			printf("\nCan't fork!!!");
			return;
		}
	}
	else{
		printf("\nCan't fork!!!");
		return;
	}
}

void exec(char *args[], int len){
	int flag=0;
	int iPipe = checkPipe(args, len);
	if(iPipe == -1){
		execArgs(args, len);
		return;
	} else {
		char *argsPipe[MAX_LINE / 2 + 1];
		int i;
		for(i = 0; i < len - iPipe - 1; i++){
			argsPipe[i] = strdup(args[iPipe + i +1]);
		}

		argsPipe[i] = NULL; 
		if(*argsPipe[i-1]=='&'){
			flag=1;
			argsPipe[i-1] = NULL;
		}
		args[iPipe] = NULL;
		execArgsPipe(args, argsPipe,flag);
		return;
	}
}

int main(void)
{
	char *args[MAX_LINE / 2 + 1];
	char history[100];
	history[0] = '\0';
	int shouldRun = 1;
	int status = 0;

	while(shouldRun) {
		char input[100];
		int len;
		int res=getInput(input, history);
		if( res== 1){
			len = parseInput(args, input);
			exec(args, len);
		}
		else if(res==0)
		{
			shouldRun=0;
		}
	}
	return 0;
}
