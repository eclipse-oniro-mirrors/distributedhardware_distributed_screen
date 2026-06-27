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

#include "screendecisioncenter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "dscreen_constants.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "screen_decision_center.h"
#include "surface_type.h"
#include "video_param.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
#define MAX_DAMAGE_COUNT (8)
#define MIN_RECT_FIELD (-64)
#define MAX_RECT_FIELD (4096)
#define MIN_DIMENSION (0)
#define DIMENSION_OVERFLOW_DELTA (128)
#define MIN_FPS (0.0)
#define MAX_FPS (240.0)
#define MIN_DAMAGE_COUNT (0)
#define FUZZ_SUCCESS (0)

VideoParam CreateVideoParam(FuzzedDataProvider &provider)
{
    VideoParam param;
    param.SetScreenWidth(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_SCREEN_DATA_WIDTH + DIMENSION_OVERFLOW_DELTA));
    param.SetScreenHeight(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_SCREEN_DATA_HEIGHT + DIMENSION_OVERFLOW_DELTA));
    param.SetVideoWidth(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_VIDEO_DATA_WIDTH + DIMENSION_OVERFLOW_DELTA));
    param.SetVideoHeight(provider.ConsumeIntegralInRange<uint32_t>(MIN_DIMENSION,
        DSCREEN_MAX_VIDEO_DATA_HEIGHT + DIMENSION_OVERFLOW_DELTA));
    param.SetFps(provider.ConsumeFloatingPointInRange<double>(MIN_FPS, MAX_FPS));
    param.SetCodecType(provider.ConsumeIntegral<uint8_t>());
    param.SetVideoFormat(provider.ConsumeIntegral<uint8_t>());
    param.SetPartialRefreshFlag(provider.ConsumeBool());
    return param;
}

std::vector<OHOS::Rect> ConsumeDamages(FuzzedDataProvider &provider)
{
    std::vector<OHOS::Rect> damages;
    uint8_t count = provider.ConsumeIntegralInRange<uint8_t>(MIN_DAMAGE_COUNT, MAX_DAMAGE_COUNT);
    for (uint8_t index = MIN_DAMAGE_COUNT; index < count; ++index) {
        damages.emplace_back(OHOS::Rect {
            provider.ConsumeIntegralInRange<int32_t>(MIN_RECT_FIELD, MAX_RECT_FIELD),
            provider.ConsumeIntegralInRange<int32_t>(MIN_RECT_FIELD, MAX_RECT_FIELD),
            provider.ConsumeIntegralInRange<int32_t>(MIN_RECT_FIELD, MAX_RECT_FIELD),
            provider.ConsumeIntegralInRange<int32_t>(MIN_RECT_FIELD, MAX_RECT_FIELD),
        });
    }
    return damages;
}
} // namespace

void RunScreendecisioncenterFuzzer(FuzzedDataProvider &provider)
{
    VideoParam param = CreateVideoParam(provider);
    ScreenDecisionCenter decisionCenter(param);
    auto damages = ConsumeDamages(provider);

    (void)decisionCenter.IsDirtyRectValid(damages);
    (void)decisionCenter.JudgeDirtyThreshold(damages);

    std::shared_ptr<IImageSourceProcessorListener> listener = nullptr;
    std::shared_ptr<IImageSourceProcessor> imageProcessor = nullptr;
    (void)decisionCenter.ConfigureDecisionCenter(listener, imageProcessor);
    sptr<Surface> surface = nullptr;
    (void)decisionCenter.SetJpegSurface(surface);
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    (void)decisionCenter.InputBufferImage(surfaceBuffer, damages);
    damages.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunScreendecisioncenterFuzzer(provider);
    return FUZZ_SUCCESS;
}
