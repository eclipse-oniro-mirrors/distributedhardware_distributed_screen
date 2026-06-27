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
constexpr size_t MAX_JSON_LENGTH = 128;
constexpr size_t MAX_NETWORK_ID_LENGTH = 64;

std::string ConsumeAccessInfo(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 4)) {
        case 0:
            return "{\"accountId\":\"" + provider.ConsumeRandomLengthString(24) + "\"}";
        case 1:
            return "{\"accountId\":1}";
        case 2:
            return "{bad json";
        case 3:
            return "{}";
        default:
            return provider.ConsumeRandomLengthString(MAX_JSON_LENGTH);
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
    accessInfo.localTokenId = 0;
    accessInfo.extraAccessInfo = nullptr;
}
} // namespace

void RunSoftbuspermissionFuzzer(FuzzedDataProvider &provider)
{
    AccountInfo callerAccountInfo;
    std::string networkId = provider.ConsumeRandomLengthString(MAX_NETWORK_ID_LENGTH);
    (void)SoftBusPermissionCheck::TransCallerInfo(nullptr, callerAccountInfo, networkId);

    SocketAccessInfo accessInfo {};
    if (provider.ConsumeBool()) {
        accessInfo.extraAccessInfo = nullptr;
        (void)SoftBusPermissionCheck::TransCallerInfo(&accessInfo, callerAccountInfo, networkId);
    }

    std::string payload = ConsumeAccessInfo(provider);
    std::vector<char> payloadBuffer(payload.begin(), payload.end());
    payloadBuffer.emplace_back('\0');
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
    return 0;
}
