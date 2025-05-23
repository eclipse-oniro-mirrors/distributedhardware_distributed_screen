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

#include "dscreensourcecallbackstub_fuzzer.h"
#include "dscreen_errcode.h"
#include "dscreen_source_callback_stub.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
class DScreenSourceCallbackStubFuzzTest : public DScreenSourceCallbackStub {
public:
    DScreenSourceCallbackStubFuzzTest() = default;
    ~DScreenSourceCallbackStubFuzzTest() = default;
    int32_t OnNotifyRegResult(const std::string &devId, const std::string &dhId, const std::string &reqId,
        int32_t status, const std::string &data) override
    {
        return 0;
    };
    int32_t OnNotifyUnregResult(const std::string &devId, const std::string &dhId, const std::string &reqId,
        int32_t status, const std::string &data) override
    {
        return 0;
    };
};

void DscreenSourceCallbackStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider dataProvider(data, size);
    unsigned int code = dataProvider.ConsumeIntegral<uint32_t>();
    uint32_t status = dataProvider.ConsumeIntegral<int32_t>();
    std::string dhId(dataProvider.ConsumeRandomLengthString());
    std::string devId(dataProvider.ConsumeRandomLengthString());
    std::string reqId(dataProvider.ConsumeRandomLengthString());
    std::string dataStr(dataProvider.ConsumeRandomLengthString());

    MessageParcel pdata;
    MessageParcel reply;
    MessageOption option;
    pdata.WriteInt32(status);
    pdata.WriteString(devId);
    pdata.WriteString(dhId);
    pdata.WriteString(reqId);
    pdata.WriteString(dataStr);

    std::shared_ptr<DScreenSourceCallbackStub> dScreenSourceCallbackStub =
        std::make_shared<DScreenSourceCallbackStubFuzzTest>();
    dScreenSourceCallbackStub->OnRemoteRequest(code, pdata, reply, option);
    dScreenSourceCallbackStub->OnNotifyRegResultInner(pdata, reply, option);
    dScreenSourceCallbackStub->OnNotifyUnregResultInner(pdata, reply, option);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DscreenSourceCallbackStubFuzzTest(data, size);
    return 0;
}
