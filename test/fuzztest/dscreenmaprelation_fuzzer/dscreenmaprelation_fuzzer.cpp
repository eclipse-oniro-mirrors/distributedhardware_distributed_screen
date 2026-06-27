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

#include "dscreenmaprelation_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dscreen_constants.h"
#include "dscreen_maprelation.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedHardware {
void to_json(json &j, const DScreenMapRelation &dScreenMapRelation);

namespace {
#define DMAP_FUZZ_MIN_COORDINATE -4096
#define DMAP_FUZZ_MAX_COORDINATE 4096
#define DMAP_FUZZ_INVALID_RECT_DIMENSION -1
#define DMAP_FUZZ_MIN_RECT_FIELD 0
#define DMAP_FUZZ_DIMENSION_OVERFLOW_DELTA 128
#define DMAP_FUZZ_INVALID_SCREEN_WIDTH_DELTA 1
#define DMAP_FUZZ_INVALID_FIELD_LENGTH 8
#define DMAP_FUZZ_FUZZ_SUCCESS 0
DisplayRect ConsumeDisplayRect(FuzzedDataProvider &provider)
{
    return {
        provider.ConsumeIntegralInRange<int32_t>(DMAP_FUZZ_MIN_COORDINATE, DMAP_FUZZ_MAX_COORDINATE),
        provider.ConsumeIntegralInRange<int32_t>(DMAP_FUZZ_MIN_COORDINATE, DMAP_FUZZ_MAX_COORDINATE),
        provider.ConsumeIntegralInRange<int32_t>(DMAP_FUZZ_INVALID_RECT_DIMENSION,
            static_cast<int32_t>(DSCREEN_MAX_VIDEO_DATA_WIDTH + DMAP_FUZZ_DIMENSION_OVERFLOW_DELTA)),
        provider.ConsumeIntegralInRange<int32_t>(DMAP_FUZZ_INVALID_RECT_DIMENSION,
            static_cast<int32_t>(DSCREEN_MAX_VIDEO_DATA_HEIGHT + DMAP_FUZZ_DIMENSION_OVERFLOW_DELTA)),
    };
}

ScreenRect ConsumeScreenRect(FuzzedDataProvider &provider)
{
    return {
        provider.ConsumeIntegralInRange<int32_t>(DMAP_FUZZ_MIN_COORDINATE, DMAP_FUZZ_MAX_COORDINATE),
        provider.ConsumeIntegralInRange<int32_t>(DMAP_FUZZ_MIN_COORDINATE, DMAP_FUZZ_MAX_COORDINATE),
        provider.ConsumeIntegralInRange<uint32_t>(DMAP_FUZZ_MIN_RECT_FIELD,
            DSCREEN_MAX_SCREEN_DATA_WIDTH + DMAP_FUZZ_DIMENSION_OVERFLOW_DELTA),
        provider.ConsumeIntegralInRange<uint32_t>(DMAP_FUZZ_MIN_RECT_FIELD,
            DSCREEN_MAX_SCREEN_DATA_HEIGHT + DMAP_FUZZ_DIMENSION_OVERFLOW_DELTA),
    };
}

nlohmann::json CreateRelationJson(FuzzedDataProvider &provider)
{
    DScreenMapRelation relation;
    relation.SetDisplayId(provider.ConsumeIntegral<uint64_t>());
    relation.SetScreenId(provider.ConsumeIntegral<uint64_t>());
    auto displayRect = ConsumeDisplayRect(provider);
    auto screenRect = ConsumeScreenRect(provider);
    relation.SetDisplayRect(displayRect);
    relation.SetScreenRect(screenRect);
    nlohmann::json jsonObj;
    to_json(jsonObj, relation);

    if (provider.ConsumeBool()) {
        jsonObj.erase(KEY_DISPLAY_ID);
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_SCREEN_RECT][KEY_WIDTH] = DSCREEN_MAX_SCREEN_DATA_WIDTH + DMAP_FUZZ_INVALID_SCREEN_WIDTH_DELTA;
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_DISPLAY_RECT][KEY_HEIGHT] = provider.ConsumeRandomLengthString(DMAP_FUZZ_INVALID_FIELD_LENGTH);
    }
    return jsonObj;
}
} // namespace

void RunDscreenmaprelationFuzzer(FuzzedDataProvider &provider)
{
    DScreenMapRelation relation;
    relation.SetDisplayId(provider.ConsumeIntegral<uint64_t>());
    relation.SetScreenId(provider.ConsumeIntegral<uint64_t>());
    auto displayRect = ConsumeDisplayRect(provider);
    auto screenRect = ConsumeScreenRect(provider);
    relation.SetDisplayRect(displayRect);
    relation.SetScreenRect(screenRect);
    (void)relation.GetDisplayId();
    (void)relation.GetScreenId();
    (void)relation.GetDisplayRect();
    (void)relation.GetScreenRect();

    nlohmann::json relationJson;
    to_json(relationJson, relation);
    from_json(CreateRelationJson(provider), relation);
    from_json(relationJson, relation);

    nlohmann::json rectJson;
    to_json(rectJson, displayRect);
    from_json(rectJson, displayRect);
    to_json(rectJson, screenRect);
    from_json(rectJson, screenRect);
    relationJson.clear();
    rectJson.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunDscreenmaprelationFuzzer(provider);
    return DMAP_FUZZ_FUZZ_SUCCESS;
}
