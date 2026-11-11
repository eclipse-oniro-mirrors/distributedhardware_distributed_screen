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

#include "softbuspermission_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "softbus_permission_check.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
#define SBPERM_FUZZ_MAX_JSON_LENGTH (128)
#define SBPERM_FUZZ_MAX_NETWORK_ID_LENGTH (64)
#define SBPERM_FUZZ_ACCOUNT_ID_VALUE_LENGTH (24)
#define SBPERM_FUZZ_MIN_ACCESS_INFO_SELECTOR (0)
#define SBPERM_FUZZ_STRING_ACCOUNT_SELECTOR (0)
#define SBPERM_FUZZ_NUMERIC_ACCOUNT_SELECTOR (1)
#define SBPERM_FUZZ_BAD_JSON_SELECTOR (2)
#define SBPERM_FUZZ_EMPTY_JSON_SELECTOR (3)
#define SBPERM_FUZZ_MAX_ACCESS_INFO_SELECTOR (4)
#define SBPERM_FUZZ_EMPTY_TOKEN_ID (0)
#define SBPERM_FUZZ_FUZZ_SUCCESS (0)
const std::string JSON_ACCOUNT_PREFIX = "{\"accountId\":\"";
const std::string JSON_ACCOUNT_SUFFIX = "\"}";
const std::string JSON_NUMERIC_ACCOUNT_PREFIX = "{\"accountId\":";
const std::string JSON_NUMERIC_ACCOUNT_VALUE = std::to_string(SBPERM_FUZZ_NUMERIC_ACCOUNT_SELECTOR);
const std::string JSON_NUMERIC_ACCOUNT_SUFFIX = "}";
const std::string BAD_JSON_PAYLOAD = "{bad json";
const std::string EMPTY_JSON_PAYLOAD = "{}";
#define SBPERM_FUZZ_STRING_TERMINATOR ('\0')
std::string ConsumeAccessInfo(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(SBPERM_FUZZ_MIN_ACCESS_INFO_SELECTOR,
        SBPERM_FUZZ_MAX_ACCESS_INFO_SELECTOR)) {
        case SBPERM_FUZZ_STRING_ACCOUNT_SELECTOR:
            return JSON_ACCOUNT_PREFIX + provider.ConsumeRandomLengthString(SBPERM_FUZZ_ACCOUNT_ID_VALUE_LENGTH) +
                JSON_ACCOUNT_SUFFIX;
        case SBPERM_FUZZ_NUMERIC_ACCOUNT_SELECTOR:
            return JSON_NUMERIC_ACCOUNT_PREFIX + JSON_NUMERIC_ACCOUNT_VALUE + JSON_NUMERIC_ACCOUNT_SUFFIX;
        case SBPERM_FUZZ_BAD_JSON_SELECTOR:
            return BAD_JSON_PAYLOAD;
        case SBPERM_FUZZ_EMPTY_JSON_SELECTOR:
            return EMPTY_JSON_PAYLOAD;
        default:
            return provider.ConsumeRandomLengthString(SBPERM_FUZZ_MAX_JSON_LENGTH);
    }
}

void SetSocketAccessInfoFields(SocketAccessInfo &accessInfo, FuzzedDataProvider &provider, char *extraAccessInfo)
{
    accessInfo.userId = provider.ConsumeIntegral<int32_t>();
    accessInfo.localTokenId = provider.ConsumeIntegral<uint64_t>();
    accessInfo.extraAccessInfo = extraAccessInfo;
}

void ResetSocketAccessInfo(SocketAccessInfo &accessInfo)
{
    accessInfo.userId = INVALID_USER_ID;
    accessInfo.localTokenId = SBPERM_FUZZ_EMPTY_TOKEN_ID;
    accessInfo.extraAccessInfo = nullptr;
}
} // namespace

void RunSoftbuspermissionFuzzer(FuzzedDataProvider &provider)
{
    AccountInfo callerAccountInfo;
    std::string networkId = provider.ConsumeRandomLengthString(SBPERM_FUZZ_MAX_NETWORK_ID_LENGTH);
    (void)SoftBusPermissionCheck::TransCallerInfo(nullptr, callerAccountInfo, networkId);

    SocketAccessInfo accessInfo {};
    if (provider.ConsumeBool()) {
        accessInfo.extraAccessInfo = nullptr;
        (void)SoftBusPermissionCheck::TransCallerInfo(&accessInfo, callerAccountInfo, networkId);
    }

    std::string payload = ConsumeAccessInfo(provider);
    std::vector<char> payloadBuffer(payload.begin(), payload.end());
    payloadBuffer.emplace_back(SBPERM_FUZZ_STRING_TERMINATOR);
    SetSocketAccessInfoFields(accessInfo, provider, payloadBuffer.data());
    (void)SoftBusPermissionCheck::TransCallerInfo(&accessInfo, callerAccountInfo, networkId);
    ResetSocketAccessInfo(accessInfo);
    payloadBuffer.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunSoftbuspermissionFuzzer(provider);
    return SBPERM_FUZZ_FUZZ_SUCCESS;
}
