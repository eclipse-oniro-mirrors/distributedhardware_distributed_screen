/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <new>

#include "callbackonnotifyregresult_fuzzer.h"
#include "mock_component_enable.h"
#include "dscreen_constants.h"
#include "dscreen_source_callback.h"
#include "dscreen_source_proxy.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
void OnNotifyRegResultFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider dataProvider(data, size);
    std::string devId(dataProvider.ConsumeRandomLengthString());
    std::string dhId(dataProvider.ConsumeRandomLengthString());
    std::string reqId(dataProvider.ConsumeRandomLengthString());
    int32_t status = dataProvider.ConsumeIntegral<int32_t>();
    std::string dataStr(dataProvider.ConsumeRandomLengthString());
    std::shared_ptr<RegisterCallback> callback = std::make_shared<MockComponentEnable>();

    sptr<DScreenSourceCallback> dScreenSourceCallback(new (std::nothrow) DScreenSourceCallback());
    if (dScreenSourceCallback == nullptr) {
        return;
    }
    dScreenSourceCallback->PushRegRegisterCallback(reqId, callback);
    dScreenSourceCallback->OnNotifyRegResult(devId, dhId, reqId, status, dataStr);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::OnNotifyRegResultFuzzTest(data, size);
    return 0;
}