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
constexpr uint8_t MAX_DAMAGE_COUNT = 8;
constexpr int32_t MIN_RECT_FIELD = -64;
constexpr int32_t MAX_RECT_FIELD = 4096;

VideoParam CreateVideoParam(FuzzedDataProvider &provider)
{
    VideoParam param;
    param.SetScreenWidth(provider.ConsumeIntegralInRange<uint32_t>(0, DSCREEN_MAX_SCREEN_DATA_WIDTH + 128));
    param.SetScreenHeight(provider.ConsumeIntegralInRange<uint32_t>(0, DSCREEN_MAX_SCREEN_DATA_HEIGHT + 128));
    param.SetVideoWidth(provider.ConsumeIntegralInRange<uint32_t>(0, DSCREEN_MAX_VIDEO_DATA_WIDTH + 128));
    param.SetVideoHeight(provider.ConsumeIntegralInRange<uint32_t>(0, DSCREEN_MAX_VIDEO_DATA_HEIGHT + 128));
    param.SetFps(provider.ConsumeFloatingPointInRange<double>(0.0, 240.0));
    param.SetCodecType(provider.ConsumeIntegral<uint8_t>());
    param.SetVideoFormat(provider.ConsumeIntegral<uint8_t>());
    param.SetPartialRefreshFlag(provider.ConsumeBool());
    return param;
}

std::vector<OHOS::Rect> ConsumeDamages(FuzzedDataProvider &provider)
{
    std::vector<OHOS::Rect> damages;
    uint8_t count = provider.ConsumeIntegralInRange<uint8_t>(0, MAX_DAMAGE_COUNT);
    for (uint8_t index = 0; index < count; ++index) {
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
    return 0;
}
