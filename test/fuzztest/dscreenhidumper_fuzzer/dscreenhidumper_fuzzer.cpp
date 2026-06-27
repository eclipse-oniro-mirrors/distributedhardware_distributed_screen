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
#define DHIDUMP_FUZZ_MAX_ARG_LENGTH (32)
#define DHIDUMP_FUZZ_MAX_ARG_COUNT (3)
#define DHIDUMP_FUZZ_MIN_ARG_SELECTOR (0)
#define DHIDUMP_FUZZ_ARG_HELP_SELECTOR (0)
#define DHIDUMP_FUZZ_ARG_STOP_DUMP_SELECTOR (1)
#define DHIDUMP_FUZZ_ARG_UNKNOWN_SELECTOR (2)
#define DHIDUMP_FUZZ_ARG_EMPTY_SELECTOR (3)
#define DHIDUMP_FUZZ_MAX_ARG_SELECTOR (4)
#define DHIDUMP_FUZZ_FUZZ_SUCCESS (0)
std::string ConsumeKnownOrRandomArg(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(DHIDUMP_FUZZ_MIN_ARG_SELECTOR, DHIDUMP_FUZZ_MAX_ARG_SELECTOR)) {
        case DHIDUMP_FUZZ_ARG_HELP_SELECTOR:
            return "-h";
        case DHIDUMP_FUZZ_ARG_STOP_DUMP_SELECTOR:
            return "--stopdump";
        case DHIDUMP_FUZZ_ARG_UNKNOWN_SELECTOR:
            return "--unknown";
        case DHIDUMP_FUZZ_ARG_EMPTY_SELECTOR:
            return "";
        default:
            return provider.ConsumeRandomLengthString(DHIDUMP_FUZZ_MAX_ARG_LENGTH);
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
    uint8_t argCount = provider.ConsumeIntegralInRange<uint8_t>(DHIDUMP_FUZZ_MIN_ARG_SELECTOR,
        DHIDUMP_FUZZ_MAX_ARG_COUNT);
    for (uint8_t index = DHIDUMP_FUZZ_MIN_ARG_SELECTOR; index < argCount; ++index) {
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
    return DHIDUMP_FUZZ_FUZZ_SUCCESS;
}
