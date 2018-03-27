// WebSocket.cpp : Definiert die exportierten Funktionen für die DLL-Anwendung.
//

#include <map>
#include <algorithm>
#include <sstream>
#include "CommonLib/Base64.h"
#include "sha1.h"
#include "TempFile.h"
#include "WebSocket.h"

#if defined(_WIN32) || defined(_WIN64)
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

using namespace std;

#define ntohll(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl(((uint32_t)(x >> 32))))
#define htonll(x) ntohll(x)

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
    function<void(BaseSocket*)> fOnError;
    function<void(BaseSocket*)> fOnClosing;
    HEADER stHeader;
    uint64_t nLen;
    uint32_t uiMask;
    shared_ptr<TempFile> pTmpFile;
    uint64_t nRecived;
    wstring strPath;
}SOCKETPARAM;

map<BaseSocket*, SOCKETPARAM> SocketList;
mutex mxList;

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

void OnDataRecieved(TcpSocket* pTcpSocket)
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
                    copy(szData, szData + iter->second.nLen, spOutput.get() + 4);
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

void OnSocketError(BaseSocket* pBaseSocket)
{
    mxList.lock();
    auto iter = SocketList.find(pBaseSocket);
    if (iter != end(SocketList))
        iter->second.fOnError(pBaseSocket);
    mxList.unlock();
}

void OnSocketCloseing(BaseSocket* pBaseSocket)
{
    mxList.lock();
    auto iter = SocketList.find(pBaseSocket);
    if (iter != end(SocketList))
    {
        iter->second.fOnClosing(pBaseSocket);
        SocketList.erase(iter);
    }
    mxList.unlock();
}
/*
int HandleRequest(PLUGINPARA* pp)
{
    // Connection: Upgrade
    // Upgrade: websocket
    if (find_if(begin(pp->HeaderList), end(pp->HeaderList), [&](auto pr) { return (pr.first == "connection" && pr.second.find("Upgrade") != string::npos) ? true : false;  }) != end(pp->HeaderList))
    {
        if (find_if(begin(pp->HeaderList), end(pp->HeaderList), [&](auto pr) { return (pr.first == "upgrade" && pr.second == "websocket") ? true : false;  }) != end(pp->HeaderList))
        {
            char caBuffer[2048];
            vector<pair<string, string>> vHeaderList = { { make_pair("X-Powerd-By", "http2serv-websocket-modul/0.1") } };

            string strWebSockKey;
            if (find_if(begin(pp->HeaderList), end(pp->HeaderList), [&](auto pr) { return (pr.first == "sec-websocket-key") ? strWebSockKey = pr.second, true : false;  }) != end(pp->HeaderList))
            {
                SOCKETPARAM sp{ 0 };
                pp->pTcpSocket->BindFuncBytesRecived(OnDataRecieved);
                sp.fOnError   = pp->pTcpSocket->BindErrorFunction(OnSocketError);
                sp.fOnClosing = pp->pTcpSocket->BindCloseFunction(OnSocketCloseing);
                sp.strPath    = pp->szPath;
                //sp.pTmpFile = pp->pTmpFile;
                mxList.lock();
                SocketList.emplace(pp->pTcpSocket, sp);
                mxList.unlock();
                pp->pTimer->Stop();

                strWebSockKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                string hash = decodeHex(sha1(strWebSockKey));
                strWebSockKey = Base64::Encode(&hash[0], 20, false);

                vHeaderList.push_back(make_pair("Connection", "Upgrade"));
                vHeaderList.push_back(make_pair("Upgrade", "websocket"));
                vHeaderList.push_back(make_pair("Sec-WebSocket-Accept", strWebSockKey));
                find_if(begin(pp->HeaderList), end(pp->HeaderList), [&](auto pr) { return (pr.first == "sec-websocket-protocol") ? vHeaderList.push_back(make_pair("Sec-WebSocket-Protocol", pr.second)), true : false; });
                size_t nHeaderLen = pp->fnBuildHeader(pp->nConnId, caBuffer, sizeof(caBuffer), pp->iFlag, 101, vHeaderList, 0);
                pp->fnSocketWrite(pp->nConnId, caBuffer, nHeaderLen);

                return 1;
            }

            pp->iFlag &= ~2;    // Remove Connection keep-alive, add connection close
            size_t nHeaderLen = pp->fnBuildHeader(pp->nConnId, caBuffer, sizeof(caBuffer), pp->iFlag, 400, vHeaderList, 0);
            pp->fnSocketWrite(pp->nConnId, caBuffer, nHeaderLen);
            pp->pTcpSocket->Close();
            return 1;
        }
    }

    return 0;
}
*/