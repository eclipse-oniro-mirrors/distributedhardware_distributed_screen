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

#include "dscreenjsonutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dscreen_constants.h"
#include "dscreen_json_util.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr size_t MAX_KEY_LENGTH = 32;
constexpr size_t MAX_STRING_LENGTH = 128;
constexpr uint8_t JSON_TYPE_COUNT = 9;

nlohmann::json ConsumeJsonValue(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, JSON_TYPE_COUNT - 1)) {
        case 0:
            return provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
        case 1:
            return provider.ConsumeIntegral<uint8_t>();
        case 2:
            return provider.ConsumeIntegral<int32_t>();
        case 3:
            return provider.ConsumeIntegral<uint32_t>();
        case 4:
            return provider.ConsumeIntegral<int64_t>();
        case 5:
            return provider.ConsumeIntegral<uint64_t>();
        case 6:
            return provider.ConsumeFloatingPoint<double>();
        case 7:
            return provider.ConsumeBool();
        default:
            return nlohmann::json::array({provider.ConsumeIntegral<int32_t>(),
                provider.ConsumeRandomLengthString(MAX_KEY_LENGTH)});
    }
}

std::string ConsumeKnownOrRandomKey(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> keys = {
        KEY_SCREEN_WIDTH,
        KEY_SCREEN_HEIGHT,
        KEY_VIDEO_WIDTH,
        KEY_VIDEO_HEIGHT,
        KEY_FPS,
        KEY_CODECTYPE,
        KEY_COLOR_FORMAT,
        KEY_PARTIALREFRESH,
        KEY_DISPLAY_ID,
        KEY_SCREEN_ID,
        KEY_DISPLAY_RECT,
        KEY_SCREEN_RECT,
    };
    if (provider.ConsumeBool()) {
        return keys[provider.ConsumeIntegralInRange<size_t>(0, keys.size() - 1)];
    }
    std::string key = provider.ConsumeRandomLengthString(MAX_KEY_LENGTH);
    return key.empty() ? KEY_SCREEN_WIDTH : key;
}
nlohmann::json CreateJsonObject(FuzzedDataProvider &provider, std::string &targetKey)
{
    nlohmann::json jsonObj = nlohmann::json::object();
    targetKey = ConsumeKnownOrRandomKey(provider);
    if (provider.ConsumeBool()) {
        jsonObj[targetKey] = ConsumeJsonValue(provider);
    }
    uint8_t extraCount = provider.ConsumeIntegralInRange<uint8_t>(0, 8);
    for (uint8_t index = 0; index < extraCount; ++index) {
        jsonObj[ConsumeKnownOrRandomKey(provider)] = ConsumeJsonValue(provider);
    }
    return jsonObj;
}
} // namespace

void RunDscreenjsonutilFuzzer(FuzzedDataProvider &provider)
{
    std::string targetKey;
    nlohmann::json jsonObj = CreateJsonObject(provider, targetKey);

    (void)IsString(jsonObj, targetKey);
    (void)IsUInt8(jsonObj, targetKey);
    (void)IsInt32(jsonObj, targetKey);
    (void)IsUInt32(jsonObj, targetKey);
    (void)IsFloat(jsonObj, targetKey);
    (void)IsInt64(jsonObj, targetKey);
    (void)IsUInt64(jsonObj, targetKey);
    (void)IsArray(jsonObj, targetKey);
    (void)IsBool(jsonObj, targetKey);
    (void)IsString(jsonObj, provider.ConsumeRandomLengthString(MAX_KEY_LENGTH));
    jsonObj.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunDscreenjsonutilFuzzer(provider);
    return 0;
}
