// WebSocketServ.cpp : Definiert den Einstiegspunkt f�r die Konsolenanwendung.
//
#include <iostream>
#include <signal.h>
#include <codecvt>
#include <fcntl.h>
#include <regex>
#include <deque>

#if defined(_WIN32) || defined(_WIN64)
#include <conio.h>
#include <io.h>
#else
#include <syslog.h>
#pragma message("TODO!!! Folge Zeile wieder entfernen.")
#include <termios.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#include "ConfFile.h"
#include "WebSockHandler.h"

#if defined(_WIN32) || defined(_WIN64)
#include "SvrLib/BaseSvr.h"
#include "SvrLib/svrctrl.h"
#include "Psapi.h"
#pragma comment(lib, "Psapi.lib")

void se_translator(size_t e, _EXCEPTION_POINTERS* p)
{
    throw e;
}
#else
class CBaseSrv
{
public:
    explicit CBaseSrv(const wchar_t*) {}
    virtual int Run(void) { Start(); return 0; }
    virtual void Start(void) = 0;
};
#endif

const static wregex s_rxSepComma(L"\\s*,\\s*");

class Service : public CBaseSrv
{
public:
    static Service& GetInstance(const wchar_t* szSrvName = nullptr)
    {
        if (s_pInstance == 0)
            s_pInstance.reset(new Service(szSrvName));
        return *s_pInstance.get();
    }

    virtual void Start(void)
    {
        // Set the Exception Handler-function
        //_set_se_translator(se_translator);

        m_bIsStopped = false;

        m_strModulePath = wstring(FILENAME_MAX, 0);
#if defined(_WIN32) || defined(_WIN64)
        if (GetModuleFileName(NULL, &m_strModulePath[0], FILENAME_MAX) > 0)
            m_strModulePath.erase(m_strModulePath.find_last_of(L'\\') + 1); // Sollte der Backslash nicht gefunden werden wird der ganz String gel�scht

        if (_wchdir(m_strModulePath.c_str()) != 0)
            m_strModulePath = L"./";
#else
        string strTmpPath(FILENAME_MAX, 0);
        if (readlink(string("/proc/" + to_string(getpid()) + "/exe").c_str(), &strTmpPath[0], FILENAME_MAX) > 0)
            strTmpPath.erase(strTmpPath.find_last_of('/'));

        //Change Directory
        //If we cant find the directory we exit with failure.
        if ((chdir(strTmpPath.c_str())) < 0) // if ((chdir("/")) < 0)
            strTmpPath = ".";
        m_strModulePath = wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().from_bytes(strTmpPath) + L"/";
#endif

        const ConfFile& conf = ConfFile::GetInstance(m_strModulePath + L"websock.cfg");
        vector<wstring>&& vListen = conf.get(L"Listen");
        if (vListen.empty() == true)
            vListen.push_back(L"127.0.0.1"), vListen.push_back(L"::1");

        map<string, vector<wstring>> mIpPortCombi;
        for (const auto& strListen : vListen)
        {
            string strIp = wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strListen);
            vector<wstring>&& vPort = conf.get(L"Listen", strListen);
            if (vPort.empty() == true)
                vPort.push_back(L"9090");
            for (const auto& strPort : vPort)
            {   // Default Werte setzen
                if (mIpPortCombi.find(strIp) == end(mIpPortCombi))
                    mIpPortCombi.emplace(strIp, vector<wstring>({ strPort }));
                else
                    mIpPortCombi.find(strIp)->second.push_back(strPort);
                if (find_if(begin(m_vServers), end(m_vServers), [strPort, strIp](auto& HttpProxy) { return HttpProxy.GetPort() == stoi(strPort) && HttpProxy.GetBindAdresse() == strIp ? true : false; }) != end(m_vServers))
                    continue;
                m_vServers.emplace_back(strIp, stoi(strPort));
            }
        }

        for (WebSocket& wSocket : m_vServers)
        {
            function<void(wstring)> fnReadHostParam = [&](wstring strSektion)
            {
                WebSocket::HOSTPARAM& HostParam = wSocket.GetParameterBlockRef(wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strSektion));

                vector<wstring>&& vListen = conf.get(strSektion);
                for (const wstring& strItem : vListen)
                {
                    string strValue = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().to_bytes(conf.getUnique(strSektion, strItem));
                    if (strItem == L"SSL")
                    {
                        transform(begin(strValue), end(strValue), begin(strValue), ::toupper);
                        HostParam.m_bSSL = strValue == "TRUE" ? true : false;
                    }
                    else if (strItem == L"SSL_DH_ParaFile")
                        HostParam.m_strDhParam = strValue;
                    else if (strItem == L"KeyFile")
                        HostParam.m_strHostKey = strValue;
                    else if (strItem == L"CertFile")
                        HostParam.m_strHostCertificate = strValue;
                    else if (strItem == L"CaBundle")
                        HostParam.m_strCAcertificate = strValue;
                    else if (strItem == L"SSLCipher")
                        HostParam.m_strSslCipher = strValue;
                    else if (strItem == L"VirtualHost")
                    {
                        const wstring& strValue = conf.getUnique(strSektion, strItem);
                        wsregex_token_iterator token(begin(strValue), end(strValue), s_rxSepComma, -1);
                        while (token != wsregex_token_iterator() && token->str().empty() == false)
                            fnReadHostParam(token->str() + L":" + to_wstring(wSocket.GetPort())), token++;

                    }
                }
            };

            wstring strSektion = wstring_convert<codecvt_utf8<wchar_t>, wchar_t>().from_bytes(wSocket.GetBindAdresse() + ":" + to_string(wSocket.GetPort()));
            fnReadHostParam(strSektion);
        }

        // Server starten
        for (auto& WebSocket : m_vServers)
            WebSocket.Start();

        unique_lock<mutex> lock(m_mxStop);
        m_cvStop.wait(lock, [&]() { return m_bStop; });

        // Server stoppen
        for (auto& WebSocket : m_vServers)
            WebSocket.Stop();

        // Warten bis alle Verbindungen / Ressourcen geschlossen sind
        for (auto& WebSocket : m_vServers)
        {
            while (WebSocket.IsStopped() == false)
                this_thread::sleep_for(chrono::milliseconds(10));
        }

        m_bIsStopped = true;
    };

    virtual void Stop(void)
    {
        m_bStop = true;
        m_cvStop.notify_all();
    }

    bool IsStopped(void) { return m_bIsStopped; }

    static void SignalHandler(int iSignal)
    {
        signal(iSignal, Service::SignalHandler);

        if (iSignal == SIGTERM)
            Service::GetInstance().Stop();
//        Service::GetInstance().ReadConfiguration();

#if defined(_WIN32) || defined(_WIN64)
        OutputDebugString(L"STRG+C-Signal empfangen\r\n");
#else
        OutputDebugString(L"Signal SIGHUP empfangen\r\n");
#endif
    }

private:
    explicit Service(const wchar_t* szSrvName) : CBaseSrv(szSrvName), m_bStop(false), m_bIsStopped(true) { }

private:
    static shared_ptr<Service> s_pInstance;
    wstring m_strModulePath;
    deque<WebSockHandler> m_vServers;
    bool m_bStop;
    bool m_bIsStopped;
    mutex              m_mxStop;
    condition_variable m_cvStop;
};

shared_ptr<Service> Service::s_pInstance = nullptr;


#if defined(_WIN32) || defined(_WIN64)
DWORD WINAPI RemoteThreadProc(LPVOID/* lpParameter*/)
{
    return raise(SIGINT);
}
#endif

int main(int argc, const char* argv[])
{
#if defined(_WIN32) || defined(_WIN64)
    // Detect Memory Leaks
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));
    _setmode(_fileno(stdout), _O_U16TEXT);

    static const wchar_t szDspName[] = { L"WebSockServ" };
    static wchar_t szDescrip[] = { L"Web-Socket Server by Thomas Hauck" };

    signal(SIGINT, Service::SignalHandler);

#else

    signal(SIGHUP, Service::SignalHandler);
    signal(SIGTERM, Service::SignalHandler);

    auto _kbhit = []() -> int
    {
        struct termios oldt, newt;
        int ch;
        int oldf;

        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

        ch = getchar();

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fcntl(STDIN_FILENO, F_SETFL, oldf);

        if (ch != EOF)
        {
            ungetc(ch, stdin);
            return 1;
        }

        return 0;
    };
#endif

    static const wchar_t szSvrName[] = { L"WebSockServ" };
    int iRet = 0;

    if (argc > 1)
    {
        while (++argv, --argc)
        {
            if (argv[0][0] == '-')
            {
                switch ((argv[0][1] & 0xdf))
                {
#if defined(_WIN32) || defined(_WIN64)
                case 'I':
                    iRet = CSvrCtrl().Install(szSvrName, szDspName, szDescrip);
                    //CSvrCtrl().SetServiceDescription(szSvrName, szDescrip);
                    break;
                case 'R':
                    iRet = CSvrCtrl().Remove(szSvrName);
                    break;
                case 'S':
                    iRet = CSvrCtrl().Start(szSvrName);
                    break;
                case 'E':
                    iRet = CSvrCtrl().Stop(szSvrName);
                    break;
                case 'P':
                    iRet = CSvrCtrl().Pause(szSvrName);
                    break;
                case 'C':
                    iRet = CSvrCtrl().Continue(szSvrName);
                    break;
#endif
                case 'F':
                {
                    wcout << L"WebSockServ gestartet" << endl;

                    Service::GetInstance(szSvrName);

                    thread th([&]() {
                        Service::GetInstance().Start();
                    });

                    const wchar_t caZeichen[] = L"\\|/-";
                    int iIndex = 0;
                    while (_kbhit() == 0)
                    {
                        wcout << L'\r' << caZeichen[iIndex++] /*<< L"  Sockets:" << setw(3) << BaseSocket::s_atRefCount << L"  SSL-Pumpen:" << setw(3) << SslTcpSocket::s_atAnzahlPumps << L"  HTTP-Connections:" << setw(3) << nHttpCon*/ << flush;
                        if (iIndex > 3) iIndex = 0;
                        this_thread::sleep_for(chrono::milliseconds(100));
                    }

                    wcout << L"WebSockServ gestoppt" << endl;
                    Service::GetInstance().Stop();
                    th.join();
                }
                break;
                case 'K':
                {
                    //raise(SIGINT);
#if defined(_WIN32) || defined(_WIN64)
                    wstring strPath(MAX_PATH, 0);
                    GetModuleFileName(NULL, &strPath[0], MAX_PATH);
                    strPath.erase(strPath.find_first_of(L'\0'));
                    strPath.erase(0, strPath.find_last_of(L'\\') + 1);

                    if (strPath.empty() == false)
                    {
                        DWORD dwInitSize = 1024;
                        DWORD dwIdReturned = 0;
                        unique_ptr<DWORD[]> pBuffer = make_unique<DWORD[]>(dwInitSize);
                        while (dwInitSize < 16384 && EnumProcesses(pBuffer.get(), sizeof(DWORD) * dwInitSize, &dwIdReturned) != 0)
                        {
                            if (dwIdReturned == sizeof(DWORD) * dwInitSize) // Buffer to small
                            {
                                dwInitSize *= 2;
                                pBuffer = make_unique<DWORD[]>(dwInitSize);
                                continue;
                            }
                            dwIdReturned /= sizeof(DWORD);

                            for (DWORD n = 0; n < dwIdReturned; ++n)
                            {
                                HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pBuffer.get()[n]);
                                if (hProcess != NULL)
                                {
                                    wstring strEnumPath(MAX_PATH, 0);
                                    if (GetModuleBaseName(hProcess, NULL, &strEnumPath[0], MAX_PATH) > 0)
                                        strEnumPath.erase(strEnumPath.find_first_of(L'\0'));
                                    else
                                    {
                                        strEnumPath.erase(GetProcessImageFileName(hProcess, &strEnumPath[0], MAX_PATH));
                                        strEnumPath.erase(0, strEnumPath.find_last_of('\\') + 1);
                                    }

                                    if (strEnumPath.empty() == false && strEnumPath == strPath) // Same Name
                                    {
                                        if (GetCurrentProcessId() != pBuffer.get()[n])          // but other process
                                        {
                                            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, RemoteThreadProc, nullptr, 0, nullptr);
                                            CloseHandle(hProcess);
                                            DWORD dwExitCode;
                                            while (GetExitCodeThread(hThread, &dwExitCode) && dwExitCode == STILL_ACTIVE)
                                                this_thread::sleep_for(chrono::milliseconds(10));
                                            CloseHandle(hThread);
                                            break;
                                        }
                                    }
                                    CloseHandle(hProcess);
                                }
                            }
                            break;
                        }
                    }
#else
                    pid_t nMyId = getpid();
                    string strMyName(64, 0);
                    FILE* fp = fopen("/proc/self/comm", "r");
                    if (fp)
                    {
                        if (fgets(&strMyName[0], strMyName.size(), fp) != NULL)
                        {
                            strMyName.erase(strMyName.find_last_not_of('\0') + 1);
                            strMyName.erase(strMyName.find_last_not_of('\n') + 1);
                            //wcout << "Meine PID = " << nMyId << " = " << strMyName.c_str() << endl;
                        }
                        fclose(fp);
                    }

                    DIR* dir = opendir("/proc");
                    if (dir != nullptr)
                    {
                        struct dirent* ent;
                        char* endptr;

                        while ((ent = readdir(dir)) != NULL)
                        {
                            // if endptr is not a null character, the directory is not entirely numeric, so ignore it
                            long lpid = strtol(ent->d_name, &endptr, 10);
                            if (*endptr != '\0')
                                continue;

                            // if the number is our own pid we ignore it
                            if ((pid_t)lpid == nMyId)
                                continue;

                            // try to open the cmdline file
                            FILE* fp = fopen(string("/proc/" + to_string(lpid) + "/comm").c_str(), "r");
                            if (fp != nullptr)
                            {
                                string strName(64, 0);
                                if (fgets(&strName[0], strName.size(), fp) != NULL)
                                {
                                    strName.erase(strName.find_last_not_of('\0') + 1);
                                    strName.erase(strName.find_last_not_of('\n') + 1);
                                    if (strName == strMyName)
                                    {
                                        //wcout << strName.c_str() << L" = " << (pid_t)lpid << endl;
                                        kill((pid_t)lpid, SIGHUP);
                                        break;
                                    }
                                }
                                fclose(fp);
                            }
                        }
                        closedir(dir);
                    }
#endif
                }
                break;
                case 'H':
                case '?':
                    wcout << L"\r\n";
#if defined(_WIN32) || defined(_WIN64)
                    wcout << L"-i   Istalliert den Systemdienst\r\n";
                    wcout << L"-r   Entfernt den Systemdienst\r\n";
                    wcout << L"-s   Startet den Systemdienst\r\n";
                    wcout << L"-e   Beendet den Systemdienst\r\n";
                    wcout << L"-p   Systemdienst wird angehaltet (Pause)\r\n";
                    wcout << L"-c   Systemdienst wird fortgesetzt (Continue)\r\n";
#endif
                    wcout << L"-f   Start die Anwendung als Konsolenanwendung\r\n";
                    //wcout << L"-k   Konfiguration neu laden\r\n";
                    wcout << L"-h   Zeigt diese Hilfe an\r\n";
                    return iRet;
                }
            }
        }
    }
    else
    {
        Service::GetInstance(szSvrName);

#if !defined(_WIN32) && !defined(_WIN64)
        //Set our Logging Mask and open the Log
        setlogmask(LOG_UPTO(LOG_NOTICE));
        openlog("websockserv", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);

        syslog(LOG_NOTICE, "Starting WebSockServ");
        pid_t pid, sid;
        //Fork the Parent Process
        pid = fork();

        if (pid < 0)
            exit(EXIT_FAILURE);

        //We got a good pid, Close the Parent Process
        if (pid > 0)
            exit(EXIT_SUCCESS);

        //Create a new Signature Id for our child
        sid = setsid();
        if (sid < 0)
            exit(EXIT_FAILURE);

        //Fork second time the Process
        pid = fork();

        if (pid < 0)
            exit(EXIT_FAILURE);

        //We got a good pid, Close the Parent Process
        if (pid > 0)
            exit(EXIT_SUCCESS);

        //Change File Mask
        umask(0);

        //Close Standard File Descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        thread([&]()
        {
            while (Service::GetInstance().IsStopped() == false)
                this_thread::sleep_for(chrono::milliseconds(100));
        }).detach();

#endif
        iRet = Service::GetInstance().Run();
    }

    return iRet;
}

