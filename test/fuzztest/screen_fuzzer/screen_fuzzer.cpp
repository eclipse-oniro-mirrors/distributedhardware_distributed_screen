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

#include "screen_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "dscreen_constants.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "screen_client.h"
#include "screen_client_window_adapter.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr uint8_t MAX_OPERATION_COUNT = 16;
constexpr int32_t MIN_COORDINATE = -4096;
constexpr int32_t MAX_COORDINATE = 4096;
constexpr uint32_t MAX_WINDOW_DIMENSION = 4096;

std::shared_ptr<WindowProperty> ConsumeWindowProperty(FuzzedDataProvider &provider)
{
    auto property = std::make_shared<WindowProperty>();
    property->type = provider.ConsumeIntegral<int32_t>();
    property->displayId = provider.ConsumeIntegral<uint64_t>();
    property->startX = provider.ConsumeIntegralInRange<int32_t>(MIN_COORDINATE, MAX_COORDINATE);
    property->startY = provider.ConsumeIntegralInRange<int32_t>(MIN_COORDINATE, MAX_COORDINATE);
    property->width = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_WINDOW_DIMENSION);
    property->height = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_WINDOW_DIMENSION);
    return property;
}

int32_t ConsumeWindowId(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
        case 0:
            return INVALID_WINDOW_ID;
        case 1:
            return 0;
        case 2:
            return provider.ConsumeIntegralInRange<int32_t>(-8, 8);
        default:
            return provider.ConsumeIntegral<int32_t>();
    }
}

void FuzzInputEventListener()
{
    ScreenClientInputEventListener listener;
    std::shared_ptr<MMI::PointerEvent> pointerEvent = nullptr;
    std::shared_ptr<MMI::KeyEvent> keyEvent = nullptr;
    std::shared_ptr<MMI::AxisEvent> axisEvent = nullptr;
    (void)listener.OnInputEvent(pointerEvent);
    (void)listener.OnInputEvent(keyEvent);
    (void)listener.OnInputEvent(axisEvent);
}

void FuzzScreenClientOperation(FuzzedDataProvider &provider, int32_t windowId)
{
    auto &client = ScreenClient::GetInstance();
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 7)) {
        case 0: {
            std::shared_ptr<WindowProperty> nullProperty = nullptr;
            (void)client.AddWindow(nullProperty);
            break;
        }
        case 1:
            (void)client.GetSurface(windowId);
            break;
        case 2:
            (void)client.ShowWindow(windowId);
            break;
        case 3:
            (void)client.HideWindow(windowId);
            break;
        case 4:
            (void)client.MoveWindow(windowId,
                provider.ConsumeIntegralInRange<int32_t>(MIN_COORDINATE, MAX_COORDINATE),
                provider.ConsumeIntegralInRange<int32_t>(MIN_COORDINATE, MAX_COORDINATE));
            break;
        case 5:
            (void)client.RemoveWindow(windowId);
            break;
        case 6:
            (void)client.DestroyAllWindow();
            break;
        default:
            FuzzInputEventListener();
            break;
    }
}

void FuzzWindowAdapterOperation(FuzzedDataProvider &provider, int32_t windowId)
{
    auto &adapter = ScreenClientWindowAdapter::GetInstance();
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 6)) {
        case 0: {
            std::shared_ptr<WindowProperty> nullProperty = nullptr;
            (void)adapter.CreateWindow(nullProperty, windowId);
            break;
        }
        case 1:
            (void)adapter.ShowWindow(windowId);
            break;
        case 2:
            (void)adapter.HideWindow(windowId);
            break;
        case 3:
            (void)adapter.MoveWindow(windowId,
                provider.ConsumeIntegralInRange<int32_t>(MIN_COORDINATE, MAX_COORDINATE),
                provider.ConsumeIntegralInRange<int32_t>(MIN_COORDINATE, MAX_COORDINATE));
            break;
        case 4:
            (void)adapter.RemoveWindow(windowId);
            break;
        case 5:
            (void)adapter.DestroyAllWindow();
            break;
        default:
            (void)ConsumeWindowProperty(provider);
            break;
    }
}
} // namespace

void RunScreenFuzzer(FuzzedDataProvider &provider)
{
    std::vector<int32_t> windowIds = {
        INVALID_WINDOW_ID,
        0,
        ConsumeWindowId(provider),
    };

    uint8_t operationCount = provider.ConsumeIntegralInRange<uint8_t>(1, MAX_OPERATION_COUNT);
    for (uint8_t index = 0; index < operationCount; ++index) {
        int32_t windowId = windowIds[provider.ConsumeIntegralInRange<size_t>(0, windowIds.size() - 1)];
        if (provider.ConsumeBool()) {
            FuzzScreenClientOperation(provider, windowId);
        } else {
            FuzzWindowAdapterOperation(provider, windowId);
        }
    }

    FuzzInputEventListener();
    (void)ScreenClient::GetInstance().DestroyAllWindow();
    (void)ScreenClientWindowAdapter::GetInstance().DestroyAllWindow();
    windowIds.clear();
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunScreenFuzzer(provider);
    return 0;
}
