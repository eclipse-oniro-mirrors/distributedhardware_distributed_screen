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

#include "dscreenhidumper_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dscreen_hidumper.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr size_t MAX_ARG_LENGTH = 32;
constexpr uint8_t MAX_ARG_COUNT = 3;

std::string ConsumeKnownOrRandomArg(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 4)) {
        case 0:
            return "-h";
        case 1:
            return "--stopdump";
        case 2:
            return "--unknown";
        case 3:
            return "";
        default:
            return provider.ConsumeRandomLengthString(MAX_ARG_LENGTH);
    }
}

void ResetHidumperFlags(DscreenHidumper &hidumper)
{
    hidumper.SetFlagFalse();
    hidumper.SetFileFlagFalse();
    hidumper.SetReDumpFlagFalse();
    hidumper.SetTransReDumpFlagFalse();
}
} // namespace

void RunDscreenhidumperFuzzer(FuzzedDataProvider &provider)
{
    auto &hidumper = DscreenHidumper::GetInstance();
    if (provider.ConsumeBool()) {
        hidumper.SetFileFlagTrue();
    } else {
        hidumper.SetFileFlagFalse();
    }
    if (provider.ConsumeBool()) {
        hidumper.SetReDumpFlagTrue();
    } else {
        hidumper.SetReDumpFlagFalse();
    }
    if (provider.ConsumeBool()) {
        hidumper.SetTransReDumpFlagTrue();
    } else {
        hidumper.SetTransReDumpFlagFalse();
    }

    std::vector<std::string> args;
    uint8_t argCount = provider.ConsumeIntegralInRange<uint8_t>(0, MAX_ARG_COUNT);
    for (uint8_t index = 0; index < argCount; ++index) {
        args.emplace_back(ConsumeKnownOrRandomArg(provider));
    }
    std::string result;
    (void)hidumper.Dump(args, result);
    (void)hidumper.GetFlagStatus();
    (void)hidumper.GetFileFlag();
    (void)hidumper.GetReDumpFlag();
    (void)hidumper.GetTransReDumpFlag();
    ResetHidumperFlags(hidumper);
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunDscreenhidumperFuzzer(provider);
    return 0;
}
