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

#ifndef OHOS_ENGINE_TEST_UTILS_H
#define OHOS_ENGINE_TEST_UTILS_H

#include "i_av_receiver_engine.h"
#include "i_av_sender_engine.h"
#include "2.0/include/av_receiver_engine_adapter.h"
#include "2.0/include/av_sender_engine_adapter.h"

namespace OHOS {
namespace DistributedHardware {
class MockAVReceiverAdapterCallback : public AVReceiverAdapterCallback {
public:
    explicit MockAVReceiverAdapterCallback() {}
    ~MockAVReceiverAdapterCallback() {}
    void OnEngineEvent(DScreenEventType event, const std::string &content) override {}
    void OnEngineMessage(const std::shared_ptr<AVTransMessage> &message) override {}
    void OnEngineDataDone(const std::shared_ptr<AVTransBuffer> &buffer) override {}
};
class MockAVSenderAdapterCallback : public AVSenderAdapterCallback {
public:
    explicit MockAVSenderAdapterCallback() {}
    ~MockAVSenderAdapterCallback() {}
    void OnEngineEvent(DScreenEventType event, const std::string &content) override {}
    void OnEngineMessage(const std::shared_ptr<AVTransMessage> &message) override {}
};

class MockIAVReceiverEngine : public IAVReceiverEngine {
public:
    explicit MockIAVReceiverEngine() {}
    ~MockIAVReceiverEngine() {}

    int32_t Initialize() override
    {
        return 0;
    }

    int32_t Start() override
    {
        return 0;
    }

    int32_t Stop() override
    {
        return 0;
    }

    int32_t Release() override
    {
        return 0;
    }

    int32_t SetParameter(AVTransTag tag, const std::string &value) override
    {
        (void) tag;
        (void) value;
        return 0;
    }

    int32_t SendMessage(const std::shared_ptr<AVTransMessage> &message) override
    {
        return 0;
    }

    int32_t CreateControlChannel(const std::vector<std::string> &dstDevIds,
        const ChannelAttribute &attribution) override
    {
        (void) dstDevIds;
        (void) attribution;
        return 0;
    }

    int32_t RegisterReceiverCallback(const std::shared_ptr<IAVReceiverEngineCallback> &callback) override
    {
        (void) callback;
        return 0;
    }

    bool StartDumpMediaData() override
    {
        return false;
    }

    bool StopDumpMediaData() override
    {
        return false;
    }

    bool ReStartDumpMediaData() override
    {
        return false;
    }
};

class MockIAVSenderEngine : public IAVSenderEngine {
public:
    explicit MockIAVSenderEngine() {}
    ~MockIAVSenderEngine() {}

    int32_t Initialize() override
    {
        return 0;
    }

    int32_t Start() override
    {
        return 0;
    }

    int32_t Stop() override
    {
        return 0;
    }

    int32_t Release() override
    {
        return 0;
    }

    int32_t PushData(const std::shared_ptr<AVTransBuffer> &buffer) override
    {
        return 0;
    }

    int32_t SetParameter(AVTransTag tag, const std::string &value) override
    {
        (void) tag;
        (void) value;
        return 0;
    }

    int32_t SendMessage(const std::shared_ptr<AVTransMessage> &message) override
    {
        return 0;
    }

    int32_t CreateControlChannel(const std::vector<std::string> &dstDevIds,
        const ChannelAttribute &attribution) override
    {
        (void) dstDevIds;
        (void) attribution;
        return 0;
    }

    int32_t RegisterSenderCallback(const std::shared_ptr<IAVSenderEngineCallback> &callback)
    {
        (void) callback;
        return 0;
    }

    bool StartDumpMediaData() override
    {
        return false;
    }

    bool StopDumpMediaData() override
    {
        return false;
    }

    bool ReStartDumpMediaData() override
    {
        return false;
    }
};
} // DistributedHardware
} // OHOS
#endif // OHOS_ENGINE_TEST_UTILS_H