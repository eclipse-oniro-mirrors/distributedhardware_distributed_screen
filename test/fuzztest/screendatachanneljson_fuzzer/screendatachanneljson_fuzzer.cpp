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

#include "screendatachanneljson_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "data_buffer.h"
#include "dscreen_constants.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "nlohmann/json.hpp"
#include "screen_data_channel_impl.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
#define SDCHJSON_FUZZ_MAX_PEER_ID_LENGTH (64)
#define SDCHJSON_FUZZ_MAX_BUFFER_CAPACITY (512)
#define SDCHJSON_FUZZ_MAX_DIRTY_COUNT (8)
#define SDCHJSON_FUZZ_MAX_DIRTY_FIELD (4096)
#define SDCHJSON_FUZZ_MIN_BUFFER_CAPACITY (1)
#define SDCHJSON_FUZZ_MIN_DIRTY_COUNT (0)
#define SDCHJSON_FUZZ_MIN_DIRTY_JSON_COUNT (0)
#define SDCHJSON_FUZZ_MIN_DIRTY_FIELD (0)
#define SDCHJSON_FUZZ_INVALID_JSON_VALUE_LENGTH (8)
#define SDCHJSON_FUZZ_FUZZ_SUCCESS (0)
std::shared_ptr<DataBuffer> MakeScreenData(FuzzedDataProvider &provider)
{
    auto dataBuffer =
        std::make_shared<DataBuffer>(provider.ConsumeIntegralInRange<size_t>(SDCHJSON_FUZZ_MIN_BUFFER_CAPACITY,
            SDCHJSON_FUZZ_MAX_BUFFER_CAPACITY));
    dataBuffer->SetDataType(provider.ConsumeBool() ? VIDEO_PART_SCREEN_DATA : VIDEO_FULL_SCREEN_DATA);
    uint8_t rectCount = provider.ConsumeIntegralInRange<uint8_t>(SDCHJSON_FUZZ_MIN_DIRTY_COUNT,
        SDCHJSON_FUZZ_MAX_DIRTY_COUNT);
    for (uint8_t index = SDCHJSON_FUZZ_MIN_DIRTY_COUNT; index < rectCount; ++index) {
        DirtyRect rect {
            provider.ConsumeIntegralInRange<uint32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD, SDCHJSON_FUZZ_MAX_DIRTY_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD, SDCHJSON_FUZZ_MAX_DIRTY_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD, SDCHJSON_FUZZ_MAX_DIRTY_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD, SDCHJSON_FUZZ_MAX_DIRTY_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD, DSCREEN_MAX_LEN),
        };
        dataBuffer->AddDirtyRect(rect);
    }
    return dataBuffer;
}

nlohmann::json MakeDirtyJson(FuzzedDataProvider &provider)
{
    nlohmann::json rectJson = nlohmann::json::object();
    int32_t dirtySize = provider.ConsumeIntegralInRange<int32_t>(SDCHJSON_FUZZ_MIN_DIRTY_JSON_COUNT,
        SDCHJSON_FUZZ_MAX_DIRTY_COUNT);
    if (provider.ConsumeBool()) {
        rectJson["dirtySize"] = dirtySize;
    } else {
        rectJson["dirtySize"] = provider.ConsumeRandomLengthString(SDCHJSON_FUZZ_INVALID_JSON_VALUE_LENGTH);
    }
    if (provider.ConsumeBool()) {
        rectJson["dataType"] = static_cast<int32_t>(VIDEO_PART_SCREEN_DATA);
    } else {
        rectJson["dataType"] = provider.ConsumeRandomLengthString(SDCHJSON_FUZZ_INVALID_JSON_VALUE_LENGTH);
    }
    for (int32_t index = SDCHJSON_FUZZ_MIN_DIRTY_JSON_COUNT; index < dirtySize; ++index) {
        std::string key = std::to_string(index);
        if (provider.ConsumeBool()) {
            rectJson[key] = nlohmann::json {
                {KEY_POINT_DIRTY_X, provider.ConsumeIntegralInRange<int32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD,
                    static_cast<int32_t>(SDCHJSON_FUZZ_MAX_DIRTY_FIELD))},
                {KEY_POINT_DIRTY_Y, provider.ConsumeIntegralInRange<int32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD,
                    static_cast<int32_t>(SDCHJSON_FUZZ_MAX_DIRTY_FIELD))},
                {KEY_POINT_DIRTY_W, provider.ConsumeIntegralInRange<int32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD,
                    static_cast<int32_t>(SDCHJSON_FUZZ_MAX_DIRTY_FIELD))},
                {KEY_POINT_DIRTY_H, provider.ConsumeIntegralInRange<int32_t>(SDCHJSON_FUZZ_MIN_DIRTY_FIELD,
                    static_cast<int32_t>(SDCHJSON_FUZZ_MAX_DIRTY_FIELD))},
                {KEY_POINT_DIRTY_SIZE, provider.ConsumeIntegralInRange<int32_t>(
                    SDCHJSON_FUZZ_MIN_DIRTY_FIELD, DSCREEN_MAX_LEN)},
            };
        }
    }
    return rectJson;
}
} // namespace

void RunScreendatachanneljsonFuzzer(FuzzedDataProvider &provider)
{
    std::string peerDevId = provider.ConsumeRandomLengthString(SDCHJSON_FUZZ_MAX_PEER_ID_LENGTH);
    auto channel = std::make_shared<ScreenDataChannelImpl>(peerDevId);
    channel->SetJpegSessionFlag(provider.ConsumeBool());

    nlohmann::json rectJson;
    auto dataBuffer = MakeScreenData(provider);
    channel->DirtyVecToJson(rectJson, dataBuffer);

    auto parsedBuffer =
        std::make_shared<DataBuffer>(provider.ConsumeIntegralInRange<size_t>(SDCHJSON_FUZZ_MIN_BUFFER_CAPACITY,
            SDCHJSON_FUZZ_MAX_BUFFER_CAPACITY));
    nlohmann::json fuzzJson = provider.ConsumeBool() ? rectJson : MakeDirtyJson(provider);
    channel->JsonToDirtyJson(fuzzJson, parsedBuffer);
    (void)parsedBuffer->GetDirtyRectVec();
    rectJson.clear();
    fuzzJson.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunScreendatachanneljsonFuzzer(provider);
    return SDCHJSON_FUZZ_FUZZ_SUCCESS;
}
