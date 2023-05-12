/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "screen_decision_center.h"

#include "dscreen_constants.h"
#include "dscreen_errcode.h"
#include "dscreen_log.h"

namespace OHOS {
namespace DistributedHardware {
bool ScreenDecisionCenter::IsDirtyRectValid(const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: IsDirtyRectValid.", LOG_TAG);
    if (damages.empty()) {
        DHLOGE("%s: damages size is empty.", LOG_TAG);
        return false;
    }
    int32_t screenWidth = static_cast<int32_t>(configParam_.GetScreenWidth());
    int32_t screenHeight = static_cast<int32_t>(configParam_.GetScreenHeight());
    for (const auto &damage : damages) {
        if (damage.x < 0 || damage.x > screenWidth || damage.y < 0 ||
            damage.y > screenHeight || damage.x % TWO == 1 || damage.w % TWO == 1) {
            DHLOGE("%s: dirty x:%" PRId32 ", y:%" PRId32 ", w:%" PRId32 ", h:%" PRId32,
                LOG_TAG, damage.x, damage.y, damage.w, damage.h);
            return false;
        }
        int32_t width = screenWidth - damage.x;
        int32_t height = screenHeight - damage.y;
        if (damage.w < 0 || damage.w > width || damage.h < 0 || damage.h > height) {
            DHLOGE("%s: dirty x:%" PRId32 ", y:%" PRId32 ", w:%" PRId32 ", h:%" PRId32,
                LOG_TAG, damage.x, damage.y, damage.w, damage.h);
            return false;
        }
    }
    return true;
}

bool ScreenDecisionCenter::JudgeDirtyThreshold(const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: JudgeDirtyThreshold.", LOG_TAG);
    int32_t allDirtyArea = 0;
    for (const auto &damage : damages) {
        allDirtyArea += damage.w * damage.h;
        if (allDirtyArea > DIRTY_REGION_ARE_THRESHOLD) {
            DHLOGE("%s: dirtyArea is %." PRId32, LOG_TAG, allDirtyArea);
            return false;
        }
    }
    return true;
}

bool ScreenDecisionCenter::LimitTime(uint32_t timethreshold)
{
    return difftime(time(nullptr), sendFullTime_) >= timethreshold;
}

int32_t ScreenDecisionCenter::InputBufferImage(sptr<SurfaceBuffer> &surfaceBuffer,
    const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: InputBufferImage.", LOG_TAG);
    if (surfaceBuffer == nullptr) {
        DHLOGE("%s: surfaceBuffer is null.", LOG_TAG);
        return ERR_DH_SCREEN_SURFACE_BUFFER_INVALIED;
    }
    if (damages.empty() || frameCount_ < MIN_SURPPORT_FRAME_COUNT ||
        LimitTime(FORCE_FULL_IMAGE_TIME_INTERAL) ||
        !IsDirtyRectValid(damages) || !JudgeDirtyThreshold(damages)) {
        DHLOGI("%s: send full image data.", LOG_TAG);
        sendFullTime_ = time(nullptr);
        int32_t ret = imageProcessor_->ProcessFullImage(surfaceBuffer);
        if (ret != DH_SUCCESS) {
            DHLOGE("%s: send full data failed.", LOG_TAG);
            return ret;
        }
    } else {
        DHLOGI("%s: send dirty data.", LOG_TAG);
        int32_t ret = imageJpeg_->ProcessDamageSurface(surfaceBuffer, damages);
        if (ret != DH_SUCCESS) {
            DHLOGE("%s: send dirty data failed.", LOG_TAG);
            return ret;
        }
    }
    frameCount_++;
    return DH_SUCCESS;
}

int32_t ScreenDecisionCenter::ConfigureDecisionCenter(std::shared_ptr<IImageSourceProcessorListener> &listener,
    std::shared_ptr<IImageSourceProcessor> &imageProcessor)
{
    DHLOGI("%s: ConfigureDecisionCenter.", LOG_TAG);
    if (listener == nullptr || imageProcessor == nullptr) {
        DHLOGE("%s: Image source process is null.", LOG_TAG);
        return ERR_DH_SCREEN_TRANS_NULL_VALUE;
    }
    imageJpeg_ = std::make_shared<JpegImageProcessor>(configParam_);
    imageJpeg_->SetImageProcessListener(listener);
    imageProcessor_ = imageProcessor;
    return DH_SUCCESS;
}

int32_t ScreenDecisionCenter::SetJpegSurface(sptr<Surface> &surface)
{
    DHLOGI("%s: SetJpegSurface.", LOG_TAG);
    if (surface ==nullptr) {
        DHLOGE("%s: Jpeg source is null.", LOG_TAG);
        return ERR_DH_SCREEN_TRANS_NULL_VALUE;
    }
    return imageJpeg_->SetOutputSurface(surface);
}
} // namespace DistributedHardware
} // namespace OHOS