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

#include "dscreenutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "dscreen_util.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
#define MAX_STRING_LENGTH (128)
#define SHORT_VERSION_LENGTH (8)
#define MIN_VERSION_VALUE (-2)
#define MAX_VERSION_VALUE (8)
#define FUZZ_SUCCESS (0)

std::string CreateVersionString(FuzzedDataProvider &provider)
{
    if (provider.ConsumeBool()) {
        return provider.ConsumeRandomLengthString(SHORT_VERSION_LENGTH);
    }
    return std::to_string(provider.ConsumeIntegralInRange<int32_t>(MIN_VERSION_VALUE, MAX_VERSION_VALUE));
}
} // namespace

void RunDscreenutilFuzzer(FuzzedDataProvider &provider)
{
    std::string value = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string version = CreateVersionString(provider);

    (void)GetAnonyString(value);
    (void)GetInterruptString(value);
    (void)GetAnonyString("");
    (void)GetInterruptString("");
    if (provider.ConsumeBool()) {
        (void)IsSupportAVTransEngine(version);
    }
    value.clear();
    version.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunDscreenutilFuzzer(provider);
    return FUZZ_SUCCESS;
}
