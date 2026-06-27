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

#include "videoparam_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dscreen_constants.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "nlohmann/json.hpp"
#include "video_param.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
#define DIMENSION_OVERFLOW_DELTA (128)
#define MAX_DIMENSION (DSCREEN_MAX_SCREEN_DATA_WIDTH + DIMENSION_OVERFLOW_DELTA)
#define MIN_DIMENSION (0)
#define MIN_DIMENSION_OVERFLOW_DELTA (1)
#define INVALID_JSON_VALUE_LENGTH (8)
#define MIN_FPS (0.0)
#define MAX_FPS (240.0)
#define FUZZ_SUCCESS (0)

uint32_t ConsumeDimension(FuzzedDataProvider &provider, uint32_t maxValue)
{
    if (provider.ConsumeBool()) {
        return provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION, maxValue);
    }
    return maxValue + provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION_OVERFLOW_DELTA,
        DIMENSION_OVERFLOW_DELTA);
}

nlohmann::json CreateVideoParamJson(FuzzedDataProvider &provider)
{
    nlohmann::json jsonObj = nlohmann::json::object();
    if (provider.ConsumeBool()) {
        jsonObj[KEY_SCREEN_WIDTH] = ConsumeDimension(provider, DSCREEN_MAX_SCREEN_DATA_WIDTH);
    } else {
        jsonObj[KEY_SCREEN_WIDTH] = provider.ConsumeRandomLengthString(INVALID_JSON_VALUE_LENGTH);
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_SCREEN_HEIGHT] = ConsumeDimension(provider, DSCREEN_MAX_SCREEN_DATA_HEIGHT);
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_VIDEO_WIDTH] = ConsumeDimension(provider, DSCREEN_MAX_VIDEO_DATA_WIDTH);
        jsonObj[KEY_VIDEO_HEIGHT] = ConsumeDimension(provider, DSCREEN_MAX_VIDEO_DATA_HEIGHT);
    } else {
        jsonObj[KEY_VIDEO_WIDTH] = provider.ConsumeIntegral<int32_t>();
        jsonObj[KEY_VIDEO_HEIGHT] = provider.ConsumeRandomLengthString(INVALID_JSON_VALUE_LENGTH);
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_FPS] = provider.ConsumeFloatingPointInRange<double>(MIN_FPS, MAX_FPS);
    } else {
        jsonObj[KEY_FPS] = provider.ConsumeIntegral<int32_t>();
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_CODECTYPE] =
            provider.ConsumeIntegralInRange<uint8_t>(VIDEO_CODEC_TYPE_VIDEO_H264, VIDEO_CODEC_TYPE_VIDEO_MPEG4);
    } else {
        jsonObj[KEY_CODECTYPE] = provider.ConsumeIntegral<uint32_t>();
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_COLOR_FORMAT] =
            provider.ConsumeIntegralInRange<uint8_t>(VIDEO_DATA_FORMAT_YUVI420, VIDEO_DATA_FORMAT_RGBA8888);
    } else {
        jsonObj[KEY_COLOR_FORMAT] = provider.ConsumeRandomLengthString(INVALID_JSON_VALUE_LENGTH);
    }
    if (provider.ConsumeBool()) {
        jsonObj[KEY_PARTIALREFRESH] = provider.ConsumeBool();
    }
    return jsonObj;
}
} // namespace

void RunVideoparamFuzzer(FuzzedDataProvider &provider)
{
    VideoParam videoParam;
    videoParam.SetScreenWidth(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION, MAX_DIMENSION));
    videoParam.SetScreenHeight(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_SCREEN_DATA_HEIGHT + DIMENSION_OVERFLOW_DELTA));
    videoParam.SetVideoWidth(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_VIDEO_DATA_WIDTH + DIMENSION_OVERFLOW_DELTA));
    videoParam.SetVideoHeight(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_VIDEO_DATA_HEIGHT + DIMENSION_OVERFLOW_DELTA));
    videoParam.SetFps(provider.ConsumeFloatingPointInRange<double>(MIN_FPS, MAX_FPS));
    videoParam.SetCodecType(provider.ConsumeIntegral<uint8_t>());
    videoParam.SetVideoFormat(provider.ConsumeIntegral<uint8_t>());
    videoParam.SetPartialRefreshFlag(provider.ConsumeBool());

    nlohmann::json outJson;
    to_json(outJson, videoParam);
    VideoParam parsedParam;
    from_json(CreateVideoParamJson(provider), parsedParam);
    from_json(outJson, parsedParam);

    (void)parsedParam.GetScreenWidth();
    (void)parsedParam.GetScreenHeight();
    (void)parsedParam.GetVideoWidth();
    (void)parsedParam.GetVideoHeight();
    (void)parsedParam.GetFps();
    (void)parsedParam.GetCodecType();
    (void)parsedParam.GetVideoFormat();
    (void)parsedParam.GetPartialRefreshFlag();
    outJson.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunVideoparamFuzzer(provider);
    return FUZZ_SUCCESS;
}
