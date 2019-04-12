
#include <memory>
#include <thread>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <functional>
#include <regex>
#include <fstream>
#include <iomanip>

#include "CommonLib/Base64.h"
#include "socketlib/SslSocket.h"
#include "TempFile.h"
#include "sha1.h"

using namespace std;
using namespace std::placeholders;

#if defined (_WIN32) || defined (_WIN64)
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "x64/Debug/socketlib64d")
#else
#pragma comment(lib, "Debug/socketlib32d")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "x64/Release/socketlib64")
#else
#pragma comment(lib, "Release/socketlib32")
#endif
#endif
#else
#include <arpa/inet.h>
#include <fcntl.h>
#define ConvertToByte(x) wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().to_bytes(x)
extern void OutputDebugString(const wchar_t* pOut);
// {   // mkfifo /tmp/dbgout
    // int fdPipe = open("/tmp/dbgout", O_WRONLY | O_NONBLOCK);
    // if (fdPipe >= 0)
    // {
        // wstring strTmp(pOut);
        // write(fdPipe, ConvertToByte(strTmp).c_str(), strTmp.size());
        // close(fdPipe);
    // }
// }
#endif

#define ntohll(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl(((uint32_t)(x >> 32))))
#define htonll(x) ntohll(x)

std::string decodeHex(const std::string & source)
{
    if (std::string::npos != source.find_first_not_of("0123456789ABCDEFabcdef"))
    {
        // you can throw exception here
        return "";
    }

    union
    {
        uint64_t binary;
        char byte[8];
    } value{};

    auto size = source.size(), offset = (size % 16);
    std::vector<uint8_t> binary{};
    binary.reserve((size + 1) / 2);

    if (offset)
    {
        value.binary = std::stoull(source.substr(0, offset), nullptr, 16);

        for (auto index = (offset + 1) / 2; index--; )
        {
            binary.emplace_back(value.byte[index]);
        }
    }

    for (; offset < size; offset += 16)
    {
        value.binary = std::stoull(source.substr(offset, 16), nullptr, 16);
        for (auto index = 8; index--; )
        {
            binary.emplace_back(value.byte[index]);
        }
    }

    string ret(128, 0);
    copy(binary.begin(), binary.end(), &ret[0]);
    return ret;
}

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
        shared_ptr<TempFile> pTmpFile;
        uint64_t nRecived;
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
    WebSocket(const string& strBindIp = string("127.0.0.1"), short sPort = 9090) : m_pSocket(nullptr), m_strBindIp(strBindIp), m_sPort(sPort)
    {
    }
    WebSocket(const WebSocket&) = delete;
    WebSocket(WebSocket&& other) {
        *this = move(other);
    }
    WebSocket& operator=(const WebSocket&) = delete;
    WebSocket& operator=(WebSocket&& other)
    {
        swap(m_pSocket, other.m_pSocket);
        other.m_pSocket = nullptr;
        swap(m_vConnections, other.m_vConnections);
        swap(m_strBindIp, other.m_strBindIp);
        swap(m_sPort, other.m_sPort);

        return *this;
    }

    virtual ~WebSocket()
    {
        Stop();

        while (IsStopped() == false)
            this_thread::sleep_for(chrono::milliseconds(10));
    }

    bool Start()
    {
        string strParamBlock(m_strBindIp + ":" + to_string(m_sPort));
        if (m_vHostParam[strParamBlock].m_bSSL == true)
        {
            SslTcpServer* pSocket = new SslTcpServer();

            if (m_vHostParam[strParamBlock].m_strCAcertificate.empty() == false && m_vHostParam[strParamBlock].m_strHostCertificate.empty() == false && m_vHostParam[strParamBlock].m_strHostKey.empty() == false && m_vHostParam[strParamBlock].m_strDhParam.empty() == false)
            {
                if (pSocket->AddCertificat(m_vHostParam[strParamBlock].m_strCAcertificate.c_str(), m_vHostParam[strParamBlock].m_strHostCertificate.c_str(), m_vHostParam[strParamBlock].m_strHostKey.c_str()) == false
                || pSocket->SetDHParameter(m_vHostParam[strParamBlock].m_strDhParam.c_str()) == false)
                {
                    delete pSocket;
                    return false;
                }
                if (m_vHostParam[strParamBlock].m_strSslCipher.empty() == false)
                    pSocket->SetCipher(m_vHostParam[strParamBlock].m_strSslCipher.c_str());
            }

            for (auto& Item : m_vHostParam)
            {
                if (Item.first != "" && Item.first != strParamBlock && Item.second.m_bSSL == true)
                {
                    if (pSocket->AddCertificat(Item.second.m_strCAcertificate.c_str(), Item.second.m_strHostCertificate.c_str(), Item.second.m_strHostKey.c_str()) == false
                    || pSocket->SetDHParameter(Item.second.m_strDhParam.c_str()) == false)
                    {
                        delete pSocket;
                        return false;
                    }
                    if (Item.second.m_strSslCipher.empty() == false)
                        pSocket->SetCipher(Item.second.m_strSslCipher.c_str());
                }
            }

            m_pSocket = pSocket;
        }
        else
            m_pSocket = new TcpServer();

        m_pSocket->BindNewConnection(function<void(const vector<TcpSocket*>&)>(bind(&WebSocket::OnNewConnection, this, _1)));
        m_pSocket->BindErrorFunction(bind(&WebSocket::OnSocketError, this, _1));
        return m_pSocket->Start(m_strBindIp.c_str(), m_sPort);
    }

    bool Stop()
    {
        if (m_pSocket != nullptr)
        {
            m_pSocket->Close();
            delete m_pSocket;
            m_pSocket = nullptr;
        }

        m_mtxConnections.lock();
        for (auto& item : m_vConnections)
            item.first->Close();
        m_mtxConnections.unlock();

        mxList.lock();
        for (auto& item : SocketList)
            item.first->Close();
        mxList.unlock();

        return true;
    }

    bool IsStopped() noexcept
    {
        return m_vConnections.size() == 0 && SocketList.size() == 0 ? true : false;
    }

    const string& GetBindAdresse() const noexcept
    {
        return m_strBindIp;
    }

    short GetPort() const noexcept
    {
        return m_sPort;
    }

    HOSTPARAM& GetParameterBlockRef(const string& szHostName)
    {
        if (szHostName != string() && m_vHostParam.find(szHostName) == end(m_vHostParam))
            m_vHostParam[szHostName] = m_vHostParam[string()];

        return m_vHostParam[szHostName];
    }

private:
    void OnNewConnection(const vector<TcpSocket*>& vNewConnections)
    {
        vector<TcpSocket*> vCache;
        for (auto& pSocket : vNewConnections)
        {
            if (pSocket != nullptr)
            {
                pSocket->BindFuncBytesRecived(bind(&WebSocket::OnDataRecieved, this, _1));
                pSocket->BindErrorFunction(bind(&WebSocket::OnSocketError, this, _1));
                pSocket->BindCloseFunction(bind(&WebSocket::OnSocketCloseing, this, _1));

                vCache.push_back(pSocket);
            }
        }
        if (vCache.size())
        {
            m_mtxConnections.lock();
            for (auto& pSocket : vCache)
            {
                m_vConnections.emplace(pSocket, CONNECTIONDETAILS({ string(), vector<pair<string, string>>(), true }));
                pSocket->StartReceiving();
            }
            m_mtxConnections.unlock();
        }
    }

    void OnDataRecieved(TcpSocket* const pTcpSocket)
    {
        uint32_t nAvalible = pTcpSocket->GetBytesAvailible();

        if (nAvalible == 0)
        {
            pTcpSocket->Close();
            return;
        }

        shared_ptr<char> spBuffer(new char[nAvalible]);

        uint32_t nRead = pTcpSocket->Read(spBuffer.get(), nAvalible);

        if (nRead > 0)
        {
            bool bFirstCall = false;
            m_mtxConnections.lock();
            CONNECTIONLIST::iterator item = m_vConnections.find(pTcpSocket);
            if (item != end(m_vConnections))
            {
                CONNECTIONDETAILS* pConDetails = &item->second;
                bFirstCall = pConDetails->bNew;
                pConDetails->bNew = false;
            }
            m_mtxConnections.unlock();

            if (spBuffer.get()[0] < 32 && bFirstCall == true) // 1. Byte < Ascii(32) && das erste mal aufgerufen wir gehen von einem SSl Client hello aus
            {
                SslTcpSocket* pSslTcpSocket = new SslTcpSocket(pTcpSocket);
                for (const auto& itParam : m_vHostParam)
                {
                    if (itParam.second.m_strCAcertificate.empty() == false && itParam.second.m_strHostCertificate.empty() == false && itParam.second.m_strHostKey.empty() == false)
                        pSslTcpSocket->AddServerCertificat(itParam.second.m_strCAcertificate.c_str(), itParam.second.m_strHostCertificate.c_str(), itParam.second.m_strHostKey.c_str(), itParam.second.m_strDhParam.c_str());
                    if (itParam.second.m_strSslCipher.empty() == false)
                        pSslTcpSocket->SetCipher(itParam.second.m_strSslCipher.c_str());
                }

                pSslTcpSocket->PutBackRead(spBuffer.get(), nRead);

                m_mtxConnections.lock();
                m_vConnections.emplace(pSslTcpSocket, m_vConnections.find(pTcpSocket)->second);
                m_vConnections.erase(pTcpSocket);
                m_mtxConnections.unlock();
                pTcpSocket->SelfDestroy();

                pSslTcpSocket->SetAcceptState();

                pSslTcpSocket->StartReceiving();
                return;
            }

            m_mtxConnections.lock();
            item = m_vConnections.find(pTcpSocket);
            if (item != end(m_vConnections))
            {
                CONNECTIONDETAILS* pConDetails = &item->second;
                pConDetails->strBuffer.append(spBuffer.get(), nRead);

                size_t nPosEndOfHeader = pConDetails->strBuffer.find("\r\n\r\n");
                if (nPosEndOfHeader != string::npos)
                {
                    vector<pair<string, string>>::iterator parLastHeader = end(pConDetails->HeaderList);
                    const static regex crlfSeperator("\r\n");
                    sregex_token_iterator line(begin(pConDetails->strBuffer), begin(pConDetails->strBuffer) + nPosEndOfHeader, crlfSeperator, -1);

                    while (line != sregex_token_iterator())
                    {
                        if (pConDetails->HeaderList.size() == 0)    // 1 Zeile
                        {
                            const string& strLine = line->str();
                            const static regex SpaceSeperator(" ");
                            sregex_token_iterator token(begin(strLine), end(strLine), SpaceSeperator, -1);
                            if (token != sregex_token_iterator() && token->str().empty() == false)
                                pConDetails->HeaderList.emplace_back(make_pair(":method", token++->str()));
                            if (token != sregex_token_iterator() && token->str().empty() == false)
                                pConDetails->HeaderList.emplace_back(make_pair(":path", token++->str()));
                            if (token != sregex_token_iterator() && token->str().empty() == false)
                            {
                                auto parResult = pConDetails->HeaderList.emplace(pConDetails->HeaderList.end(), make_pair(":version", token++->str()));
                                if (parResult != end(pConDetails->HeaderList))
                                    parResult->second.erase(0, parResult->second.find_first_of('.') + 1);
                            }

                            if (pConDetails->HeaderList.size() != 3)    // The first line should have 3 part. method, path and HTTP/1.x version
                            {
                                pConDetails->HeaderList.emplace_back(make_pair(":1stline", strLine));
                                //SendErrorRespons(pTcpSocket, pConDetails->pTimer, 400, HTTPVERSION11, pConDetails->HeaderList);
                                pTcpSocket->Write("HTTP/1.1 400 Bad request\r\nServer: WebSockServ/1.0\r\n\r\n", 53);
                                pTcpSocket->Close();
                                m_mtxConnections.unlock();
                                return;
                            }
                        }
                        else
                        {
                            size_t nPos1 = line->str().find(':');
                            if (nPos1 != string::npos)
                            {
                                string strTmp = line->str().substr(0, nPos1);
                                transform(begin(strTmp), begin(strTmp) + nPos1, begin(strTmp), ::tolower);

                                auto parResult = pConDetails->HeaderList.emplace(pConDetails->HeaderList.end(), make_pair(strTmp, line->str().substr(nPos1 + 1)));
                                if (parResult != end(pConDetails->HeaderList))
                                {
                                    parResult->second.erase(parResult->second.find_last_not_of(" \r\n\t") + 1);
                                    parResult->second.erase(0, parResult->second.find_first_not_of(" \t"));
                                    parLastHeader = parResult;

                                }
                            }
                            else if (line->str().find(" \t") == 0 && parLastHeader != end(pConDetails->HeaderList)) // Multi line Header
                            {
                                line->str().erase(line->str().find_last_not_of(" \r\n\t") + 1);
                                line->str().erase(0, line->str().find_first_not_of(" \t"));
                                parLastHeader->second += " " + line->str();
                            }
                            else
                            {   // header without a : char are a bad request
                                parLastHeader = end(pConDetails->HeaderList);
                                //SendErrorRespons(pTcpSocket, pConDetails->pTimer, 400, 0, pConDetails->HeaderList);
                                pTcpSocket->Write("HTTP/1.1 400 Bad request\r\nServer: WebSockServ/1.0\r\n\r\n", 53);
                                pTcpSocket->Close();
                                m_mtxConnections.unlock();
                                return;
                            }
                        }
                        ++line;
                    }
                    pConDetails->strBuffer.erase(0, nPosEndOfHeader + 4);




                    // Connection: Upgrade
                    // Upgrade: websocket
                    if (find_if(begin(pConDetails->HeaderList), end(pConDetails->HeaderList), [&](auto pr) { return (pr.first == "connection" && pr.second.find("Upgrade") != string::npos) ? true : false;  }) != end(pConDetails->HeaderList))
                    {
                        if (find_if(begin(pConDetails->HeaderList), end(pConDetails->HeaderList), [&](auto pr) { return (pr.first == "upgrade" && pr.second == "websocket") ? true : false;  }) != end(pConDetails->HeaderList))
                        {
                            vector<pair<string, string>> vHeaderList = { { make_pair("X-Powerd-By", "http2serv-websocket-modul/0.1") } };

                            string strWebSockKey;
                            if (find_if(begin(pConDetails->HeaderList), end(pConDetails->HeaderList), [&](auto pr) { return (pr.first == "sec-websocket-key") ? strWebSockKey = pr.second, true : false;  }) != end(pConDetails->HeaderList))
                            {
                                SOCKETPARAM sp{ 0 };
                                pTcpSocket->BindFuncBytesRecived(bind(&WebSocket::OnDataRecievedWebSocket, this, _1));
                                pTcpSocket->BindErrorFunction(bind(&WebSocket::OnSocketErrorWebSocket, this, _1));
                                pTcpSocket->BindCloseFunction(bind(&WebSocket::OnSocketCloseingWebSocket, this, _1));
                                auto itPath = find_if(begin(pConDetails->HeaderList), end(pConDetails->HeaderList), [&](auto pr) { return (pr.first == ":path") ? true : false;  });
                                if (itPath != end(pConDetails->HeaderList))
                                    sp.strPath = wstring(begin(itPath->second), end(itPath->second));
                                //sp.pTmpFile = pp->pTmpFile;
                                mxList.lock();
                                SocketList.emplace(pTcpSocket, sp);
                                mxList.unlock();

                                strWebSockKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                                string hash = decodeHex(sha1(strWebSockKey));
                                strWebSockKey = Base64::Encode(&hash[0], 20, false);

                                vHeaderList.push_back(make_pair("Connection", "Upgrade"));
                                vHeaderList.push_back(make_pair("Upgrade", "websocket"));
                                vHeaderList.push_back(make_pair("Sec-WebSocket-Accept", strWebSockKey));
                                find_if(begin(pConDetails->HeaderList), end(pConDetails->HeaderList), [&](auto pr) { return (pr.first == "sec-websocket-protocol") ? vHeaderList.push_back(make_pair("Sec-WebSocket-Protocol", pr.second)), true : false; });

                                string strRespons("HTTP/1.1 101 Switching Protocols\r\nServer: WebSockServ/1.0\r\n");
                                strRespons += "Date: ";
                                auto in_time_t = chrono::system_clock::to_time_t(chrono::system_clock::now());

                                stringstream ss;
                                ss.imbue(locale("C"));
                                ss << put_time(::gmtime(&in_time_t), "%a, %d %b %Y %H:%M:%S GMT\r\n");
                                strRespons += ss.str();

                                for (const auto& item : vHeaderList)
                                    strRespons += item.first + ": " + item.second + "\r\n";
                                strRespons += "Connection: keep-alive\r\n";
                                strRespons += "\r\n";

                                pTcpSocket->Write(&strRespons[0], strRespons.size());

                                m_vConnections.erase(pTcpSocket);
                            }
                            else
                            {
                                pTcpSocket->Write("HTTP/1.1 400 Bad request\r\nServer: WebSockServ/1.0\r\n\r\n", 53);
                                pTcpSocket->Close();
                            }
                        }
                    }


                }
                else
                    OutputDebugString(L"Destination Socket besteht bereits\r\n");
            }
            else
                OutputDebugString(L"Socket nicht in ConectionList (1)\r\n");

            m_mtxConnections.unlock();
        }
    }

    void OnSocketError(BaseSocket* const pBaseSocket)
    {
        //        MyTrace("Error: Network error ", pBaseSocket->GetErrorNo());

        m_mtxConnections.lock();
        auto item = m_vConnections.find(reinterpret_cast<TcpSocket*>(pBaseSocket));
        if (item != end(m_vConnections))
        {
        }
        else
            OutputDebugString(L"Socket nicht in ConectionList (2)\r\n");
        m_mtxConnections.unlock();

        pBaseSocket->Close();
    }

    void OnSocketCloseing(BaseSocket* const pBaseSocket)
    {
        m_mtxConnections.lock();
        auto item = m_vConnections.find(reinterpret_cast<TcpSocket* const>(pBaseSocket));
        if (item != end(m_vConnections))
        {
            m_vConnections.erase(item->first);
        }
        else
            OutputDebugString(L"Socket nicht in ConectionList (4)\r\n");
        m_mtxConnections.unlock();
    }

    void OnDataRecievedWebSocket(TcpSocket* pTcpSocket)
    {
        uint32_t nAvalible = pTcpSocket->GetBytesAvailible();

        if (nAvalible == 0)
        {
            pTcpSocket->Close();
            return;
        }

        shared_ptr<uint8_t> spBuffer(new uint8_t[nAvalible]);

        uint32_t nRead = pTcpSocket->Read(spBuffer.get(), nAvalible);

        if (nRead > 0)
        {
            OutputDebugString(wstring(L"Read:" + to_wstring(nRead) + L"\r\n").c_str());

            mxList.lock();
            auto iter = SocketList.find(pTcpSocket);
            if (iter == end(SocketList))
            {
                mxList.unlock();
                return;
            }

            uint8_t* pBuffer = spBuffer.get();
            uint8_t* pBufferEnd = spBuffer.get() + nRead;

            do
            {
                size_t iOffset = 0;
                if (iter->second.nLen == 0) // No Header, first call on this socket
                {
                    iter->second.stHeader = *(reinterpret_cast<HEADER*>(pBuffer));
                    iOffset = 2;
                    iter->second.nLen = iter->second.stHeader.PLoad;
                    if (iter->second.nLen == 126)
                        iter->second.nLen = ntohs(*(reinterpret_cast<short*>(pBuffer + iOffset))), iOffset += 2;
                    else if (iter->second.nLen == 127)
                        iter->second.nLen = ntohll(*(reinterpret_cast<uint64_t*>(pBuffer + iOffset))), iOffset += 8;
                    if (iter->second.stHeader.Mask == 1)
                        iter->second.uiMask = *(reinterpret_cast<uint32_t*>(pBuffer + iOffset)), iOffset += 4;
                }

                uint8_t* szData = pBuffer + iOffset;
                size_t nBlockSize = min(static_cast<size_t>(iter->second.nLen - iter->second.nRecived), nRead - iOffset);
#if defined(_WIN32) || defined(_WIN64)
                OutputDebugString(wstring(L"Read:" + to_wstring(nRead) + L", OpCode:" + to_wstring(iter->second.stHeader.OpCode) + L", FIN:" + to_wstring(iter->second.stHeader.FIN) + L", Len:" + to_wstring(iter->second.nLen) + L", BlockSize:" + to_wstring(nBlockSize) + L"\r\n").c_str());
#endif
                if (iter->second.stHeader.Mask == 1)
                {
                    for (size_t n = 0; n < nBlockSize; ++n)
                    {
                        size_t m = n % 4;
                        szData[n] = szData[n] ^ reinterpret_cast<char*>(&iter->second.uiMask)[m];  // original-octet-i XOR masking-key-octet-j
                    }
                }

                iter->second.nRecived += nBlockSize;

                switch (iter->second.stHeader.OpCode)
                {
                case 0: // continue
#if defined(_WIN32) || defined(_WIN64)
                    OutputDebugString(L"continue frame\r\n");
#endif
                    if (iter->second.pTmpFile != 0)
                        iter->second.pTmpFile->Write(szData, nBlockSize);

                    if (iter->second.nRecived == iter->second.nLen)
                    {
                        if (iter->second.stHeader.FIN == 1)
                        {
                            if (iter->second.pTmpFile != 0)
                            {
                                iter->second.pTmpFile->Close();
                                iter->second.pTmpFile.reset();
                            }
                        }

                        iter->second.stHeader = { 0 };
                        iter->second.nRecived = iter->second.nLen = 0;
                    }
                    break;

                case 1: // Text
                {
                    if (iter->second.nRecived == iter->second.nLen)
                    {
                        if (iter->second.stHeader.FIN == 1)
                        {
                            if (iter->second.strPath == L"/broadcast")
                            {
                                int iHeaderLen = 2;
                                if (iter->second.nLen > 125)
                                    iHeaderLen += 2;
                                if (iter->second.nLen > 65535)
                                    iHeaderLen += 6;

                                shared_ptr<uint8_t> spOutput(new uint8_t[iter->second.nLen + iHeaderLen]);
                                copy(szData, szData + iter->second.nLen, &spOutput.get()[iHeaderLen]);

                                HEADER* sHeader = reinterpret_cast<HEADER*>(spOutput.get());
                                *sHeader = { 0 };
                                sHeader->FIN = 1;
                                sHeader->OpCode = 1;
                                sHeader->Mask = 0;
                                sHeader->PLoad = (iHeaderLen > 2 ? (iHeaderLen == 10 ? 127 : 126) : iter->second.nLen);
                                if (iHeaderLen == 10)
                                    *(reinterpret_cast<uint64_t*>(spOutput.get() + 2)) = htonll(iter->second.nLen);
                                else if (iHeaderLen > 2)
                                    *(reinterpret_cast<short*>(spOutput.get() + 2)) = htons(static_cast<short>(iter->second.nLen));

                                for (auto item : SocketList)
                                {
                                    if (reinterpret_cast<TcpSocket*>(item.first) != pTcpSocket)
                                        reinterpret_cast<TcpSocket*>(item.first)->Write(spOutput.get(), iter->second.nLen + iHeaderLen);
                                }
                            }
                            else
                            {
                                shared_ptr<uint8_t> spOutput(new uint8_t[pTcpSocket->GetClientAddr().size() + 1 + iter->second.nLen + 2]);
                                copy(&pTcpSocket->GetClientAddr()[0], &pTcpSocket->GetClientAddr()[pTcpSocket->GetClientAddr().size()], &spOutput.get()[2]);
                                spOutput.get()[2 + pTcpSocket->GetClientAddr().size()] = ':';
                                copy(szData, szData + iter->second.nLen, &spOutput.get()[2 + pTcpSocket->GetClientAddr().size() + 1]);

                                HEADER* sHeader = reinterpret_cast<HEADER*>(spOutput.get());
                                *sHeader = { 0 };
                                sHeader->FIN = 1;
                                sHeader->OpCode = 1;
                                sHeader->Mask = 0;
                                sHeader->PLoad = pTcpSocket->GetClientAddr().size() + 1 + iter->second.nLen;
                                //*(reinterpret_cast<uint32_t*>(spOutput.get() + 2)) = uiMask;

                                //for (size_t n = 0; n < sHeader->PLoad; ++n)
                                //{
                                //    size_t m = n % 4;
                                //    strBuffer[n] = strBuffer[n] ^ reinterpret_cast<char*>(&uiMask)[m];  // original-octet-i XOR masking-key-octet-j
                                //}

                                //mxList.lock();
                                for (auto item : SocketList)
                                    reinterpret_cast<TcpSocket*>(item.first)->Write(spOutput.get(), pTcpSocket->GetClientAddr().size() + 1 + iter->second.nLen + 2);
                                //mxList.unlock();

                                //pTcpSocket->Write(spOutput.get(), strBuffer.size() + 2);
                            }
                        }

                        iter->second.stHeader = { 0 };
                        iter->second.nRecived = iter->second.nLen = 0;
                    }
                }
                break;

                case 2: // binary
#if defined(_WIN32) || defined(_WIN64)
                    OutputDebugString(L"binary frame\r\n");
#endif
                    if (iter->second.pTmpFile == 0)
                    {
                        iter->second.pTmpFile = make_shared<TempFile>();
                        iter->second.pTmpFile->Open();
                    }

                    iter->second.pTmpFile->Write(szData, nBlockSize);

                    if (iter->second.nRecived == iter->second.nLen)
                    {
                        if (iter->second.stHeader.FIN == 1)
                        {
                            iter->second.pTmpFile->Close();
                            iter->second.pTmpFile.reset();
                        }

                        iter->second.stHeader = { 0 };
                        iter->second.nRecived = iter->second.nLen = 0;
                    }
                    break;

                case 8: // close
                {
                    short sCode = ntohs(*(reinterpret_cast<short*>(szData)));
                    szData += 2;

                    shared_ptr<uint8_t> spOutput(new uint8_t[iter->second.nLen + 2]);

                    HEADER* sHeader = reinterpret_cast<HEADER*>(spOutput.get());
                    *sHeader = { 0 };
                    sHeader->FIN = 1;
                    sHeader->OpCode = 8;
                    sHeader->Mask = 0;
                    sHeader->PLoad = iter->second.nLen;

                    *(reinterpret_cast<short*>(spOutput.get() + 2)) = htons(sCode);
                    copy(szData, szData + iter->second.nLen - 2, spOutput.get() + 4);
                    pTcpSocket->Write(spOutput.get(), iter->second.nLen + 2);
                }
                pTcpSocket->Close();
                break;

                case 9: // ping
                    reinterpret_cast<HEADER*>(pBuffer)->OpCode = 0xA;
                    pTcpSocket->Write(pBuffer, nRead);
                    iter->second.nRecived = iter->second.nLen = 0;
                    break;

                case 10:// pong
#if defined(_WIN32) || defined(_WIN64)
                    OutputDebugString(L"pong frame\r\n");
#endif
                    iter->second.nRecived = iter->second.nLen = 0;
                    break;
                }

                pBuffer += nBlockSize + iOffset;
                nRead -= nBlockSize + iOffset;
            } while (pBuffer < pBufferEnd);

            mxList.unlock();
        }
    }

    void OnSocketErrorWebSocket(BaseSocket* pBaseSocket)
    {
        //mxList.lock();
        //auto iter = SocketList.find(pBaseSocket);
        //if (iter != end(SocketList))
        //    iter->second.fOnError(pBaseSocket);
        //mxList.unlock();
        pBaseSocket->Close();
    }

    void OnSocketCloseingWebSocket(BaseSocket* pBaseSocket)
    {
        mxList.lock();
        auto iter = SocketList.find(pBaseSocket);
        if (iter != end(SocketList))
        {
            //iter->second.fOnClosing(pBaseSocket);
            SocketList.erase(iter);
        }
        mxList.unlock();
    }

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
