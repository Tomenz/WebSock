
#include <unordered_map>
#include <map>
#include <mutex>

#include "SocketLib/SocketLib.h"

using namespace std;

class WebSocket
{
    typedef struct
    {
        string strBuffer;
        vector<pair<string, string>> HeaderList;
        bool bNew;
    } CONNECTIONDETAILS;

    typedef unordered_map<TcpSocket*, CONNECTIONDETAILS> CONNECTIONLIST;

    typedef struct
    {
        uint8_t OpCode : 4;
        uint8_t RSV3 : 1;
        uint8_t RSV2 : 1;
        uint8_t RSV1 : 1;
        uint8_t FIN : 1;

        uint8_t PLoad : 7;
        uint8_t Mask : 1;
    }HEADER;

    typedef struct
    {
        HEADER stHeader;
        uint64_t nLen;
        uint32_t uiMask;
        //shared_ptr<TempFile> pTmpFile;
        uint64_t nReceived;
        wstring strPath;
    }SOCKETPARAM;

public:
    typedef struct
    {
        bool    m_bSSL;
        string  m_strCAcertificate;
        string  m_strHostCertificate;
        string  m_strHostKey;
        string  m_strDhParam;
        string  m_strSslCipher;
    } HOSTPARAM;

public:
    WebSocket(const string& strBindIp = string("127.0.0.1"), short sPort = 9090);
    WebSocket(const WebSocket&) = delete;
    WebSocket(WebSocket&& other) noexcept;
    WebSocket& operator=(const WebSocket&) = delete;
    WebSocket& operator=(WebSocket&& other) noexcept;
    virtual ~WebSocket();
    virtual bool Start();
    virtual bool Stop();
    virtual bool IsStopped() noexcept;
    const string& GetBindAdresse() const noexcept;
    short GetPort() const noexcept;
    HOSTPARAM& GetParameterBlockRef(const string& szHostName);

    virtual void Connected(const void* pId) { ; }
    virtual void Closeing(const void* pId) { ; }
    virtual void TextDataRecieved(const void* pId, const wstring strPath, uint8_t* szData, uint32_t nDataLen) { ; }
    virtual void BinaryDataRecieved(const void* pId, const wstring strPath, uint8_t* szData, uint32_t nDataLen, bool bIsLast) { ; }
    size_t WriteData(const void* pId, const uint8_t* szData, const uint32_t nDataLen);

private:
    void OnNewConnection(const vector<TcpSocket*>& vNewConnections);
    void OnDataRecieved(TcpSocket* const pTcpSocket);
    void OnSocketError(BaseSocket* const pBaseSocket);
    void OnSocketCloseing(BaseSocket* const pBaseSocket);
    void OnDataRecievedWebSocket(TcpSocket* pTcpSocket);
    void OnSocketErrorWebSocket(BaseSocket* pBaseSocket);
    void OnSocketCloseingWebSocket(BaseSocket* pBaseSocket);

private:
    TcpServer*             m_pSocket;
    CONNECTIONLIST         m_vConnections;
    mutex                  m_mtxConnections;

    map<BaseSocket*, SOCKETPARAM> SocketList;
    mutex mxList;

    string                 m_strBindIp;
    short                  m_sPort;
    map<string, HOSTPARAM> m_vHostParam;
};
