/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbusadapter_fuzzer.h"

#include "dscreen_constants.h"
#include "dscreen_errcode.h"
#include "dscreen_util.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "isoftbus_listener.h"
#include "socket.h"
#include "softbus_adapter.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const std::string PEER_SESSION_NAME = "ohos.dhardware.dscreen.session8647073e02e7a78f09473aa324";
const std::string REMOTE_DEV_ID = "f6d4c0864707aefte7a78f09473aa122ff57fc81c00981fcf5be989e7d112324";
const std::string DSCREEN_PKG_NAME_TEST = "ohos.dhardware.dscreen";
}
void SoftbusAdapterFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    int32_t sessionId = dataProvider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = dataProvider.ConsumeIntegral<uint32_t>();
    unsigned int dataLen1 = dataProvider.ConsumeIntegral<unsigned int>();

    PeerSocketInfo peerSocketInfo = {
        .name = const_cast<char *>(PEER_SESSION_NAME.c_str()),
        .networkId = const_cast<char *>(REMOTE_DEV_ID.c_str()),
        .pkgName = const_cast<char *>(DSCREEN_PKG_NAME_TEST.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;

    void *adapterData = nullptr;
    StreamData *stream = nullptr;
    StreamData *ext = nullptr;
    StreamFrameInfo *info = nullptr;

    std::shared_ptr<SoftbusAdapter> adapter = std::make_shared<SoftbusAdapter>();
    adapter->sessListener_.OnBind(sessionId, peerSocketInfo);
    adapter->sessListener_.OnShutdown(sessionId, reason);
    adapter->sessListener_.OnBytes(sessionId, adapterData, dataLen);
    adapter->sessListener_.OnStream(sessionId, stream, ext, info);
    adapter->sessListener_.OnMessage(sessionId, adapterData, dataLen1);
    adapter->SendSoftbusStream(sessionId, stream, ext, info);
    adapter->SendSoftbusBytes(sessionId, adapterData, dataLen1);
    adapter->CloseSoftbusSession(sessionId);
}

void SoftbusOnBytesReceivedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    int32_t sessionId = dataProvider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = dataProvider.ConsumeIntegral<uint32_t>();
    void *adapterData = nullptr;
    std::shared_ptr<SoftbusAdapter> adapter = std::make_shared<SoftbusAdapter>();
    adapter->OnBytesReceived(sessionId, adapterData, dataLen);
}

void SoftbusOnMessageReceivedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    int32_t sessionId = dataProvider.ConsumeIntegral<int32_t>();
    unsigned int dataLen = dataProvider.ConsumeIntegral<unsigned int>();
    void *adapterData = nullptr;
    std::shared_ptr<SoftbusAdapter> adapter = std::make_shared<SoftbusAdapter>();
    adapter->OnMessageReceived(sessionId, adapterData, dataLen);
}

void SoftbusOnSessionClosedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    int32_t sessionId = dataProvider.ConsumeIntegral<int32_t>();
    std::shared_ptr<SoftbusAdapter> adapter = std::make_shared<SoftbusAdapter>();
    ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
    adapter->OnSoftbusSessionClosed(sessionId, reason);
}

void SoftbusOnSessionOpenedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    int32_t sessionId = dataProvider.ConsumeIntegral<int32_t>();
    PeerSocketInfo peerSocketInfo = {
        .name = const_cast<char *>(PEER_SESSION_NAME.c_str()),
        .networkId = const_cast<char *>(REMOTE_DEV_ID.c_str()),
        .pkgName = const_cast<char *>(DSCREEN_PKG_NAME_TEST.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    std::shared_ptr<SoftbusAdapter> adapter = std::make_shared<SoftbusAdapter>();
    adapter->OnSoftbusSessionOpened(sessionId, peerSocketInfo);
}

void SoftbusOnStreamReceivedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    int32_t sessionId = dataProvider.ConsumeIntegral<int32_t>();
    StreamData *stream = nullptr;
    StreamData *ext = nullptr;
    StreamFrameInfo *info = nullptr;
    std::shared_ptr<SoftbusAdapter> adapter = std::make_shared<SoftbusAdapter>();
    adapter->OnStreamReceived(sessionId, stream, ext, info);
}

void SoftbusRegisterSoftbusListenerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string sessionName(dataProvider.ConsumeRandomLengthString());
    std::string peerDevId(dataProvider.ConsumeRandomLengthString());

    std::shared_ptr<SoftbusAdapter> softbusAdapter = std::make_shared<SoftbusAdapter>();
    std::shared_ptr<ISoftbusListener> listener = std::make_shared<MockSoftbusListener>();
    (void)softbusAdapter->RegisterSoftbusListener(listener, sessionName, peerDevId);
    (void)softbusAdapter->UnRegisterSoftbusListener(sessionName, peerDevId);
}

void SoftbusUnRegisterSoftbusListenerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string sessionName(dataProvider.ConsumeRandomLengthString());
    std::string peerDevId(dataProvider.ConsumeRandomLengthString());

    std::shared_ptr<SoftbusAdapter> softbusAdapter = std::make_shared<SoftbusAdapter>();
    (void)softbusAdapter->UnRegisterSoftbusListener(sessionName, peerDevId);
}

void SoftbusCreateSoftbusSessionServerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string sessionName(dataProvider.ConsumeRandomLengthString());
    std::string peerDevId(dataProvider.ConsumeRandomLengthString());
    std::string pkgName(dataProvider.ConsumeRandomLengthString());

    std::shared_ptr<SoftbusAdapter> softbusAdapter = std::make_shared<SoftbusAdapter>();
    (void)softbusAdapter->CreateSoftbusSessionServer(pkgName, sessionName, peerDevId);
    (void)softbusAdapter->RemoveSoftbusSessionServer(pkgName, sessionName, peerDevId);
}

void SoftbusRemoveSoftbusSessionServerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string sessionName(dataProvider.ConsumeRandomLengthString());
    std::string peerDevId(dataProvider.ConsumeRandomLengthString());
    std::string pkgName(dataProvider.ConsumeRandomLengthString());

    std::shared_ptr<SoftbusAdapter> softbusAdapter = std::make_shared<SoftbusAdapter>();
    (void)softbusAdapter->RemoveSoftbusSessionServer(pkgName, sessionName, peerDevId);
}

void SoftbusOpenSoftbusSessionFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string mySessionName(dataProvider.ConsumeRandomLengthString());
    std::string peerSessionName(dataProvider.ConsumeRandomLengthString());
    std::string peerDevId(dataProvider.ConsumeRandomLengthString(size));

    std::shared_ptr<SoftbusAdapter> softbusAdapter = std::make_shared<SoftbusAdapter>();
    int32_t socketId = softbusAdapter->OpenSoftbusSession(mySessionName, peerSessionName, peerDevId);
    (void)softbusAdapter->CloseSoftbusSession(socketId);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SoftbusAdapterFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusOnBytesReceivedFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusOnMessageReceivedFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusOnSessionClosedFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusOnSessionOpenedFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusOnStreamReceivedFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusRegisterSoftbusListenerFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusUnRegisterSoftbusListenerFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusCreateSoftbusSessionServerFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusRemoveSoftbusSessionServerFuzzTest(data, size);
    OHOS::DistributedHardware::SoftbusOpenSoftbusSessionFuzzTest(data, size);
    return 0;
}

extern "C" __attribute__((constructor)) int Socket(SocketInfo info)
{
    return 0;
}

extern "C" __attribute__((constructor)) int Listen(int32_t socket, const QosTV qos[], uint32_t qosCount,
    const ISocketListener *listener)
{
    return 0;
}

extern "C" __attribute__((constructor)) int Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
    const ISocketListener *listener)
{
    return 0;
}

extern "C" __attribute__((constructor)) void Shutdown(int32_t socket) {}

extern "C" __attribute__((constructor)) int SendBytes(int32_t socket, const void *data, uint32_t len)
{
    return 0;
}

extern "C" __attribute__((constructor)) int SendStream(int32_t socket, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    return 0;
}
