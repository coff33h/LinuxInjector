#include <stdio.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <string.h>
#include<sys/user.h>
#include<dlfcn.h>
#include<sys/mman.h>

#define MAX_PATH  1024
#define LIBDL_PATH "/usr/lib/x86_64-linux-gnu/libdl-2.31.so"
#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc-2.31.so"
pid_t FindPidByProcessName(const char * process_name);
int ptrace_attach(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_continue(pid_t pid);
int ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_writedata(pid_t pid, void* addr, void* data, int size);
int ptrace_readdata(pid_t pid, void* addr, unsigned char* data, int size);
int ptrace_call(pid_t pid, void* ExecuteAddr, unsigned long *parameters, unsigned long num, struct user_regs_struct *regs);
int GetPidCmdline(pid_t pid, char* ProcessName);
unsigned long ptrace_getret(struct user_regs_struct* regs);
void* GetRemoteFuncAddr(pid_t pid, const char * ModuleName, void*LocalFuncAddr);
void* GetModuleBaseAddr(pid_t pid, const char* ModuleName);
int inject_remote_process(pid_t pid, char* InjectLibPath,char* FunctionName,unsigned long *FuncParameter,unsigned long NumParameter);



int main(int argc,char* argv[])
{	
	//./injector pid .so FuncName FuncArg

	if(argc < 4)
	{
		printf("usage: ./injector PID LibPath FuncName\n");
		exit(0);
	}

	char InjectProcessName[MAX_PATH] = {0};
	char InjectLibPath[MAX_PATH] = {0};
	char InjectFuncName[MAX_PATH] = {0};
	// pid_t pid = FindPidByProcessName(InjectProcessName);
	pid_t pid = atoi(argv[1]);
	GetPidCmdline(pid, InjectProcessName);
	printf("--------------------------------------------\n");
	printf("pid: %d\nProcess Name: %s\n",(unsigned int)pid,InjectProcessName);
	memcpy(InjectLibPath, argv[2], 1024);
	memcpy(InjectFuncName, argv[3], 1024);
	printf("InjectLibPath: %s\n", InjectLibPath);
	printf("InjectFuncName: %s\n",InjectFuncName);
	printf("--------------------------------------------\n");


	unsigned long parameters[6];
	// parameters[0] = 0x61;
	// inject_remote_process(pid, "/usr/lib/x86_64-linux-gnu/libmenu.so", "putchar",parameters, 1); //cant reopen .so
	inject_remote_process(pid, InjectLibPath, InjectFuncName, parameters, 0); //cant reopen .so

}


/*************************************************
  Description:    获得程序的pid
  Input:          程序名
  Output:         无
  Return:         成功返回程序的PID，失败返回-1。
  Others:         无
*************************************************/ 
int GetPidCmdline(pid_t pid, char* ProcessName)
{
	FILE *fp = NULL;
	struct dirent * entry = NULL;
	char CmdlineFilePath[MAX_PATH];

	snprintf(CmdlineFilePath,MAX_PATH,"/proc/%d/cmdline",pid);

	fp = fopen(CmdlineFilePath,"r");
	if( fp == NULL)
	{
		printf("can't open %s.\n",CmdlineFilePath);
		return -1;
	}
	fgets(ProcessName, 1024, fp);
	fclose(fp);


}
pid_t FindPidByProcessName(const char * process_name)
{
	int ProcessDirID =0;
	pid_t pid =-1;
	FILE* fp = NULL;
	char filename[MAX_PATH] = {0};
	char cmdline[MAX_PATH] = {0};

	struct dirent * entry = NULL;

	if(process_name == NULL)
	{
		printf("process name NULL.\n");
		return -1;
	}

	DIR *dir =opendir("/proc");
	if(dir == NULL)
	{
		printf("can't open /proc.\n");
		return -1;
	}

	while((entry = readdir(dir)) != NULL)  //遍历/proc
	{
		ProcessDirID = atoi(entry->d_name);//将数字文件名转换为int ,转换失败的话返回0;
		if( ProcessDirID != 0)
		{
			snprintf(filename,MAX_PATH,"/proc/%d/cmdline",ProcessDirID);// 文件/proc/<pid>/cmdline 为进程的启动命令行。安卓平台的为app包名;
			fp = fopen(filename,"r");
			if(fp)
			{
				fgets(cmdline,1024,fp);
				fclose(fp);
				if(strncmp(process_name, cmdline, strlen(process_name)) == 0)
				{
					pid = ProcessDirID;
					break;
				}
			}
		}
	}
	closedir(dir);
	return pid;
}



/*************************************************
  Description:    使用ptrace远程call函数
  Input:          pid表示远程进程的ID，ExecuteAddr为远程进程函数的地址
				  parameters为函数参数的地址，regs为远程进程call前的寄存器环境
  Output:         无
  Return:         返回0表示call函数成功，返回-1表示失败
  Others:         无
*************************************************/ 
int ptrace_call(pid_t pid, void* ExecuteAddr, unsigned long *parameters, unsigned long num, struct user_regs_struct *regs)
{
	
	// rdi rsi rdx rcx r8 r9 x64 假设最多6个参数，不用栈
	regs->rax = 0;
	if(num == 0)
	{
		;
	}
	else if(num == 1)
	{
		regs->rdi = parameters[0];
	}
	else if(num == 2)
	{
		regs->rdi = parameters[0];
		regs->rsi = parameters[1];
	}
	else if(num == 3)
	{
		regs->rdi = parameters[0];
		regs->rsi = parameters[1];
		regs->rdx = parameters[2];
	}
	else if(num == 4)
	{
		regs->rdi = parameters[0];
		regs->rsi = parameters[1];
		regs->rdx = parameters[2];
		regs->rcx = parameters[3];
	}
	else if(num == 5)
	{
		regs->rdi = parameters[0];
		regs->rsi = parameters[1];
		regs->rdx = parameters[2];
		regs->rcx = parameters[3];
		regs->r8  = parameters[4];
	}
	else if(num == 6)
	{
		regs->rdi = parameters[0];
		regs->rsi = parameters[1];
		regs->rdx = parameters[2];
		regs->rcx = parameters[3];
		regs->r8  = parameters[4];
		regs->r9  = parameters[5];
	}

	
	// 函数返回地址入栈 
	regs->rsp -= 8;
	unsigned long tmp = 0;
	ptrace_writedata(pid, (void*)regs->rsp, &tmp, 8);//当函数返回时，进程会接受到异常信号而停止运行。

	regs->rip = (unsigned long)ExecuteAddr;	

	if(ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1)
	{
		printf("ptrace set regs or continue error, pid:%d", pid);
		return -1;
	}

	int status = 0;
	waitpid(pid,&status,WUNTRACED);
	while(status != 0xb7f) //0x7f代表子进程为暂停状态，0xb代表sigsegv，也就是为什么函数的返回地址设为0引起的。
	{
		if (waitpid(pid, &status, WUNTRACED) == -1)
		{
			printf("waitpid error");
			return -1;
		}
		waitpid(pid,&status,WUNTRACED);
	}

	if(ptrace_getregs(pid, regs) == -1)
	{
		printf("get regs failed.\n");
		return -1;
	}
	return 0;

}



int inject_remote_process(pid_t pid, char* InjectLibPath,char* FunctionName,unsigned long *FuncParameter,unsigned long NumParameter)
{
	int iRet = -1;
	struct user_regs_struct CurrentRegs; //表示远程进程中当前的寄存器值
	struct user_regs_struct OriginalRegs; //存储注入前的寄存器值，方便恢复。
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr; 
	void *RemoteMapMemoryAddr; //远程进程空间中映射的内存基址，即mmap的返回值。
	void *RemoteModuleAddr; // 远程注入的so模块加载基址
	void *RemoteModuleFuncAddr; // 注入模块中要调用的函数地址
	unsigned long parameters[6];

	if(ptrace_attach(pid) == -1)
		return iRet;

	if(ptrace_getregs(pid, &CurrentRegs) == -1)
	{
		ptrace_detach(pid);
		return iRet;
	}

	/*	
	test readdata()
	long addr = 0x404040;
	unsigned char *data = malloc(0x10); 
	ptrace_readdata(pid,(void *) addr, data,0x10);
	printf("%s\n", data);
	getchar();*/

/*	
	test writedata()
	long addr = 0x404060;
	char tobewritten[] = "new string!!!~~~";
	ptrace_writedata(pid,(void*)addr,tobewritten,sizeof(tobewritten));

	getchar();
	ptrace_detach(pid);
	return 0;*/
	
	// 保存远程进程空间中当前的上下文环境
	memcpy(&OriginalRegs, &CurrentRegs,sizeof(struct user_regs_struct));

	// 获取mmap在远程进程中的地址
	mmap_addr = GetRemoteFuncAddr(pid, LIBC_PATH, (void*)mmap);
	printf("remote mmap() address:0x%lx.\n",(unsigned long)mmap_addr);
	
	// mmap的参数
	parameters[0] = 0;   //设置为NULL，代表让系统自动选择分配的内存的地址
	parameters[1] = 0x1000;  //内存大小
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC; //rwx权限
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射(不太懂)
	parameters[4] = 0; // 若需要映射文件到内存中，则为文件的fd
	parameters[5] = 0; // 文件映射偏移量
	printf("-----------------------------------------\n");
	printf("### call remote mmap() ###\n");
	
	if(ptrace_call(pid, mmap_addr, parameters, 6, &CurrentRegs) == -1)
	{
		printf("Call Remote mmap failed.\n");
		ptrace_detach(pid);
		return iRet;
	}
	RemoteMapMemoryAddr = (void*)ptrace_getret(&CurrentRegs);
	printf("mmap result:0x%lx\n", (unsigned long)RemoteMapMemoryAddr);
	printf("-----------------------------------------\n");




	//分别获取dlopen、dlsym、dlclose\dlerror等函数的地址
	printf("Get dl* func addr.\n");
	dlopen_addr = GetRemoteFuncAddr(pid, LIBDL_PATH, (void *)dlopen);
	dlsym_addr = GetRemoteFuncAddr(pid, LIBDL_PATH, (void *)dlsym);
	dlclose_addr = GetRemoteFuncAddr(pid, LIBDL_PATH, (void *)dlclose);
	dlerror_addr = GetRemoteFuncAddr(pid, LIBDL_PATH, (void *)dlerror);

	//将要注入的动态链接库路径写入到远程进程内存空间中
	printf("write injected lib path to remote process memory. \n");
	if(ptrace_writedata(pid, RemoteMapMemoryAddr, InjectLibPath, strlen(InjectLibPath)+1 ) == -1)
	{
		ptrace_detach(pid);
		return iRet;
	}

	//设置dlopen的参数，返回值为模块的加载基址
	// void *dlopen(const char *filename, int flag);
	parameters[0] = (unsigned long)RemoteMapMemoryAddr;
	parameters[1] = RTLD_NOW| RTLD_GLOBAL;

	printf("-----------------------------------------\n");
	printf("### call dlopen ### \n");
	printf("dlopen addr:0x%lx\n",(long)dlopen_addr );
	if(ptrace_call(pid, dlopen_addr, parameters, 2, &CurrentRegs) == -1)
	{
		ptrace_detach(pid);
		return iRet;
	}

	// RemoteModuleAddr为待注入模块的加载基址

	RemoteModuleAddr = (void*) ptrace_getret(&CurrentRegs);
	printf("remote module addr(dlopen result):0x%lx\n", (unsigned long)RemoteModuleAddr);
	


	if((unsigned long)RemoteModuleAddr == 0)
	{
		printf("dlopen failed\n");
		ptrace_detach(pid);
		return iRet;
	}

	printf("-----------------------------------------\n");
	//将要注入的动态链接库的函数名称写入mmap得到的空间中
	printf("write func name to remote process memory.\n");
	if(ptrace_writedata(pid, RemoteMapMemoryAddr+strlen(InjectLibPath)+0x10, FunctionName, strlen(FunctionName)+1) == -1)
	{
		ptrace_detach(pid);
		printf("write function name error");
		return iRet;
	}

	//设置dlsym的参数，返回值为远程进程中函数的地址
	// void *dlsym(void *handle, const char *symbol);
	printf("call dlsym.\n");
	parameters[0] = (unsigned long)RemoteModuleAddr;
	parameters[1] = (unsigned long)RemoteMapMemoryAddr +  strlen(InjectLibPath) + 0x10;
	if(ptrace_call(pid, dlsym_addr, parameters, 2, &CurrentRegs) == -1)
	{
		printf("call remote dlsym failed. \n");
		ptrace_detach(pid);
		return iRet;
	}


	RemoteModuleFuncAddr = (void*) ptrace_getret(&CurrentRegs);
	printf("%s - %s addr - %lx\n",InjectLibPath, FunctionName,(unsigned long)RemoteModuleFuncAddr);


	printf("call remote function.\n");
	if(ptrace_call(pid, RemoteModuleFuncAddr, FuncParameter, NumParameter, &CurrentRegs) == -1)
	{
		printf("call remote injected func failed.\n");
		return iRet;
	}

	//恢复环境
	printf("recover original regs\n");
	if(ptrace_setregs(pid, &OriginalRegs) == -1)
	{
		printf("recover regs failed.\n");
		return iRet;
	}

	ptrace_getregs(pid, &CurrentRegs);
	if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0)
	{
		printf("Set Regs Error.\n");
		return iRet;
	}
	ptrace_detach(pid);

	return 0;

}




int ptrace_attach(pid_t pid)
{
	int status = 0;
	if(ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0)
	{
		printf("attach process error, pid:%d.\n", pid);
		return -1;
	}

	printf("attach process success, pid:%d.\n",pid );
	waitpid(pid, &status, WUNTRACED);
	return 0;
}

unsigned long ptrace_getret(struct user_regs_struct* regs)
{
	return regs->rax;
}


int ptrace_detach(pid_t pid)
{
	if(ptrace(PTRACE_DETACH, pid, NULL, 0) < 0)
	{
		printf("detach process error, pid:%d\n", pid);
		return -1;
	}

	printf("detach process pid:%d\n", pid);
	return 0;
}



int ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
	if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0)
	{	
		printf("get regs error.\n");
		return -1;
	}

	return 0;
}
int ptrace_continue(pid_t pid)
{
	if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
	{
		printf("continue process error, pid:%d\n", pid);
		return -1;
	}

	printf("continue process pid:%d\n", pid);
	return 0;
}

int ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
	{
		printf("set regs error, pid:%d\n", pid);
		return -1;
	}

	printf("set regs, pid:%d\n", pid);
	return 0;
}

int ptrace_writedata(pid_t pid, void* addr, void* data, int size)
{
	unsigned long originAddr = (unsigned long)addr;
	int write_count = size / sizeof(unsigned long);
	int remain_count = write_count % sizeof(unsigned long);
	unsigned long write_buffer;

	for(int i = 0 ; i < write_count; i++)
	{
		memcpy(&write_buffer, data, 8);
		if(ptrace(PTRACE_POKEDATA, pid, addr,write_buffer) < 0)
		{	
			printf("write data error, pid:%d\n", pid);
			return -1;
		}
		write_buffer = ptrace(PTRACE_PEEKDATA, pid, addr,NULL);
		data = ((unsigned long*)data) + 1;
		addr = ((unsigned long*)addr) + 1;
	}

	if(remain_count > 0)
	{
		if(write_buffer = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL) < 0)
		{
			printf("read data error, pid:%d.",pid);
			return -1;
		}

		memcpy(&write_buffer, data, remain_count);
		if(ptrace(PTRACE_POKETEXT, pid, addr, write_buffer) < 0)
		{	
			printf("write data error, pid:%d\n", pid);
			return -1;
		}
	}

	unsigned char * checkarr = (unsigned char*)malloc(size);
	memset(checkarr,0,size);
	ptrace_readdata(pid, (void*)originAddr, checkarr, size);
	printf("checkarray: %s\n", checkarr);
	return 0;

}

int ptrace_readdata(pid_t pid, void* addr, unsigned char*data, int size)
{
	int read_count = size / sizeof(long);
	int remain = size % sizeof(long);
	
	union x{
		long val; //
		char chars[sizeof(long)];
	}d;

	unsigned char * p = data;
	for(int i=0; i<read_count; i++)
	{
		d.val = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
		// printf("read:0x%lx\n",d.val );
		// printf("%s\n", &tmp);
		memcpy(p,d.chars,8);
		p = p + 8;
		addr = ((unsigned long*)addr) + 1;
	}

	if(remain > 0)
	{
		d.val = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
		memcpy(p,d.chars,remain);
	}

	return 0;
}

//获得远程进程函数的地址。
void * GetRemoteFuncAddr(pid_t pid, const char * ModuleName, void*LocalFuncAddr)
{
	void *LocalModuleAddr;
	void *RemoteModuleAddr;
	void *RemoteFuncAddr;


	LocalModuleAddr = GetModuleBaseAddr(-1, ModuleName);
	RemoteModuleAddr = GetModuleBaseAddr(pid, ModuleName);

	//远程进程函数的地址 = 函数相对于模块的偏移 + 远程进程模块的地址
	RemoteFuncAddr =(void*)((unsigned long)LocalFuncAddr - (unsigned long)LocalModuleAddr + (unsigned long)RemoteModuleAddr);

	return RemoteFuncAddr;
}


/*
	获得程序的模块基址。
	pid为-1则获取本程序的模块基址。
	通过读取/proc/self/maps或/proc/pid/maps获得
*/
void* GetModuleBaseAddr(pid_t pid, const char* ModuleName)
{
	FILE *fp = NULL;
	unsigned long ModuleBaseAddr = 0;
	char *ModulePath;
	char FileName[1024] = {0};
	char MapFileLine[1024]= {0};
	char ProcessInfo[1024] = {0};

	if(pid < 0)
	{
		snprintf(FileName, sizeof(FileName), "/proc/self/maps"); //pid为-1，读取本程序的基址
	}
	else
	{
		snprintf(FileName, sizeof(FileName), "/proc/%d/maps", pid);
	}

	fp = fopen(FileName,"r");
	if(fp != NULL)
	{
		while(fgets(MapFileLine,sizeof(MapFileLine),fp))
		{
			if(strstr(MapFileLine,ModuleName))
			{
				char * Addr = strtok(MapFileLine,"-");
				ModuleBaseAddr = strtoul(Addr, NULL,16);

				if(ModuleBaseAddr == 0x8000) //不太懂这一步判断的原因
				{
					ModuleBaseAddr = 0;
				}

				break;
			}
		}
		fclose(fp);
	}

	// if(pid == -1)
	// 	printf("local: ");
	// else
	// 	printf("remote: ");
	// printf("%s : 0x%lx\n",ModuleName, (unsigned long)ModuleBaseAddr);
	return (void*)ModuleBaseAddr;
}

