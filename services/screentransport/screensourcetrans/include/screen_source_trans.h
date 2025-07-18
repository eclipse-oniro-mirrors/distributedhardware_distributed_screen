/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_SCREEN_SOURCE_TRANS_H
#define OHOS_SCREEN_SOURCE_TRANS_H

#include <condition_variable>
#include <mutex>
#include <memory>
#include <queue>
#include <string>
#include <thread>

#include "screen_decision_center.h"
#include "iimage_source_processor.h"
#include "iscreen_source_trans.h"
#include "iscreen_source_trans_callback.h"
#include "iscreen_channel.h"

namespace OHOS {
namespace DistributedHardware {
class ScreenSourceTrans : public IScreenSourceTrans,
    public IScreenChannelListener,
    public IImageSourceProcessorListener,
    public std::enable_shared_from_this<ScreenSourceTrans> {
public:
    ScreenSourceTrans() = default;
    ~ScreenSourceTrans() override = default;

    int32_t SetUp(const VideoParam &localParam, const VideoParam &remoteParam, const std::string &peerDevId) override;
    int32_t Release() override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t RegisterStateCallback(const std::shared_ptr<IScreenSourceTransCallback> &callback) override;
    sptr<Surface> GetImageSurface() override;

    void OnSessionOpened() override;
    void OnSessionClosed() override;
    void OnDataReceived(const std::shared_ptr<DataBuffer> &data) override;
    void OnImageProcessDone(const std::shared_ptr<DataBuffer> &data) override;
    void OnProcessorStateNotify(int32_t state) override;
    void OnDamageProcessDone(sptr<SurfaceBuffer> &surfaceBuffer, const std::vector<OHOS::Rect> &damages) override;
    int32_t SetConsumerSurface() override;
    void SetScreenVersion(const std::string &version) override;

private:
    int32_t CheckVideoParam(const VideoParam &param);
    int32_t CheckTransParam(const VideoParam &localParam, const VideoParam &remoteParam, const std::string &peerDevId);
    int32_t InitScreenTrans(const VideoParam &localParam, const VideoParam &remoteParam, const std::string &peerDevId);
    int32_t RegisterChannelListener();
    int32_t RegisterProcessorListener(const VideoParam &localParam, const VideoParam &remoteParam);
    void FeedChannelData();

private:
    static const constexpr char *DSCREEN_LOG_TAG = "ScreenSourceTrans";

    std::mutex sessionMtx_;
    std::mutex channelMtx_;
    std::mutex dataMtx_;
    std::condition_variable sessionCond_;
    std::condition_variable dataCond_;
    std::mutex dataQueueMtx_;

    bool isChannelReady_ = false;
    sptr<Surface> consumerSurface_;
    std::queue<std::shared_ptr<DataBuffer>> dataQueue_;

    std::shared_ptr<IImageSourceProcessor> imageProcessor_;
    std::shared_ptr<IScreenChannel> screenChannel_;
    std::weak_ptr<IScreenSourceTransCallback> transCallback_;
    std::shared_ptr<ScreenDecisionCenter> screenDecisionCenter_;
    std::string version_ = "1.0";
};
} // namespace DistributedHardware
} // namespace OHOS
#endif