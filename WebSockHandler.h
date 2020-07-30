#pragma once
#include <string>

#include "WebSocket.h"

class WebSockHandler : public WebSocket
{
public:
    WebSockHandler(const std::string& strBindIp = std::string("127.0.0.1"), short sPort = 9090);
    virtual ~WebSockHandler();

    virtual void Connected(const void* pId) override;
    virtual void Closeing(const void* pId) override;
    virtual void TextDataRecieved(const void* pId, const wstring strPath, uint8_t* szData, uint32_t nDataLen) override;
    virtual void BinaryDataRecieved(const void* pId, const wstring strPath, uint8_t* szData, uint32_t nDataLen, bool bLastPaket) override;

private:
    vector<const void*> m_vSocket;
    mutex               m_mxSockets;
};
