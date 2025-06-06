/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "initsink_fuzzer.h"
#include "dscreen_sink_handler.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
void InitSinkFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider dataProvider(data, size);
    std::string params(dataProvider.ConsumeRandomLengthString());
    std::string networkId(dataProvider.ConsumeRandomLengthString());

    DScreenSinkHandler::GetInstance().InitSink(params);
    DScreenSinkHandler::GetInstance().PauseDistributedHardware(networkId);
    DScreenSinkHandler::GetInstance().ResumeDistributedHardware(networkId);
    DScreenSinkHandler::GetInstance().StopDistributedHardware(networkId);
    DScreenSinkHandler::GetInstance().ReleaseSink();
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::InitSinkFuzzTest(data, size);
    return 0;
}
