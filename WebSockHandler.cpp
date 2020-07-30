#include "WebSockHandler.h"

WebSockHandler::WebSockHandler(const string& strBindIp/* = string("127.0.0.1")*/, short sPort/* = 9090*/) : WebSocket(strBindIp, sPort)
{
}

WebSockHandler::~WebSockHandler()
{

}

void WebSockHandler::Connected(const void* pId)
{
    lock_guard<mutex> lock(m_mxSockets);
    m_vSocket.push_back(pId);
}

void WebSockHandler::Closeing(const void* pId)
{
    lock_guard<mutex> lock(m_mxSockets);
    for (auto iter = m_vSocket.begin(); iter != m_vSocket.end(); ++iter)
    {
        if (*iter == pId)
        {
            m_vSocket.erase(iter);
            break;
        }
    }
}

void WebSockHandler::TextDataRecieved(const void* pId, const wstring strPath, uint8_t* szData, uint32_t nDataLen)
{
    //WriteData(pId, szData, nDataLen);
}

void WebSockHandler::BinaryDataRecieved(const void* pId, const wstring strPath, uint8_t* szData, uint32_t nDataLen, bool bLastPaket)
{
    //OutputDebugString(wstring(L"Bytes received:" + to_wstring(nDataLen) + L"\r\n").c_str());
}
