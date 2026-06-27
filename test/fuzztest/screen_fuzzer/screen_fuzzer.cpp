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
#define SCR_FUZZ_MAX_OPERATION_COUNT 16
#define SCR_FUZZ_MIN_COORDINATE -4096
#define SCR_FUZZ_MAX_COORDINATE 4096
#define SCR_FUZZ_MAX_WINDOW_DIMENSION 4096
#define SCR_FUZZ_MIN_WINDOW_DIMENSION 0
#define SCR_FUZZ_ZERO_WINDOW_ID 0
#define SCR_FUZZ_MIN_SMALL_WINDOW_ID -8
#define SCR_FUZZ_MAX_SMALL_WINDOW_ID 8
#define SCR_FUZZ_MIN_SELECTOR 0
#define SCR_FUZZ_WINDOW_ID_INVALID_SELECTOR 0
#define SCR_FUZZ_WINDOW_ID_ZERO_SELECTOR 1
#define SCR_FUZZ_WINDOW_ID_SMALL_SELECTOR 2
#define SCR_FUZZ_MAX_WINDOW_ID_SELECTOR 3
#define SCR_FUZZ_SCREEN_CLIENT_ADD_WINDOW_SELECTOR 0
#define SCR_FUZZ_SCREEN_CLIENT_GET_SURFACE_SELECTOR 1
#define SCR_FUZZ_SCREEN_CLIENT_SHOW_WINDOW_SELECTOR 2
#define SCR_FUZZ_SCREEN_CLIENT_HIDE_WINDOW_SELECTOR 3
#define SCR_FUZZ_SCREEN_CLIENT_MOVE_WINDOW_SELECTOR 4
#define SCR_FUZZ_SCREEN_CLIENT_REMOVE_WINDOW_SELECTOR 5
#define SCR_FUZZ_SCREEN_CLIENT_DESTROY_ALL_SELECTOR 6
#define SCR_FUZZ_MAX_SCREEN_CLIENT_SELECTOR 7
#define SCR_FUZZ_WINDOW_ADAPTER_CREATE_WINDOW_SELECTOR 0
#define SCR_FUZZ_WINDOW_ADAPTER_SHOW_WINDOW_SELECTOR 1
#define SCR_FUZZ_WINDOW_ADAPTER_HIDE_WINDOW_SELECTOR 2
#define SCR_FUZZ_WINDOW_ADAPTER_MOVE_WINDOW_SELECTOR 3
#define SCR_FUZZ_WINDOW_ADAPTER_REMOVE_WINDOW_SELECTOR 4
#define SCR_FUZZ_WINDOW_ADAPTER_DESTROY_ALL_SELECTOR 5
#define SCR_FUZZ_MAX_WINDOW_ADAPTER_SELECTOR 6
#define SCR_FUZZ_MIN_WINDOW_ID_INDEX 0
#define SCR_FUZZ_WINDOW_ID_INDEX_STEP 1
#define SCR_FUZZ_FUZZ_SUCCESS 0
std::shared_ptr<WindowProperty> ConsumeWindowProperty(FuzzedDataProvider &provider)
{
    auto property = std::make_shared<WindowProperty>();
    property->type = provider.ConsumeIntegral<int32_t>();
    property->displayId = provider.ConsumeIntegral<uint64_t>();
    property->startX = provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_COORDINATE, SCR_FUZZ_MAX_COORDINATE);
    property->startY = provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_COORDINATE, SCR_FUZZ_MAX_COORDINATE);
    property->width = provider.ConsumeIntegralInRange<uint32_t>(SCR_FUZZ_MIN_WINDOW_DIMENSION,
        SCR_FUZZ_MAX_WINDOW_DIMENSION);
    property->height = provider.ConsumeIntegralInRange<uint32_t>(SCR_FUZZ_MIN_WINDOW_DIMENSION,
        SCR_FUZZ_MAX_WINDOW_DIMENSION);
    return property;
}

int32_t ConsumeWindowId(FuzzedDataProvider &provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(SCR_FUZZ_MIN_SELECTOR, SCR_FUZZ_MAX_WINDOW_ID_SELECTOR)) {
        case SCR_FUZZ_WINDOW_ID_INVALID_SELECTOR:
            return INVALID_WINDOW_ID;
        case SCR_FUZZ_WINDOW_ID_ZERO_SELECTOR:
            return SCR_FUZZ_ZERO_WINDOW_ID;
        case SCR_FUZZ_WINDOW_ID_SMALL_SELECTOR:
            return provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_SMALL_WINDOW_ID, SCR_FUZZ_MAX_SMALL_WINDOW_ID);
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
    switch (provider.ConsumeIntegralInRange<uint8_t>(SCR_FUZZ_MIN_SELECTOR, SCR_FUZZ_MAX_SCREEN_CLIENT_SELECTOR)) {
        case SCR_FUZZ_SCREEN_CLIENT_ADD_WINDOW_SELECTOR: {
            std::shared_ptr<WindowProperty> nullProperty = nullptr;
            (void)client.AddWindow(nullProperty);
            break;
        }
        case SCR_FUZZ_SCREEN_CLIENT_GET_SURFACE_SELECTOR:
            (void)client.GetSurface(windowId);
            break;
        case SCR_FUZZ_SCREEN_CLIENT_SHOW_WINDOW_SELECTOR:
            (void)client.ShowWindow(windowId);
            break;
        case SCR_FUZZ_SCREEN_CLIENT_HIDE_WINDOW_SELECTOR:
            (void)client.HideWindow(windowId);
            break;
        case SCR_FUZZ_SCREEN_CLIENT_MOVE_WINDOW_SELECTOR:
            (void)client.MoveWindow(windowId,
                provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_COORDINATE, SCR_FUZZ_MAX_COORDINATE),
                provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_COORDINATE, SCR_FUZZ_MAX_COORDINATE));
            break;
        case SCR_FUZZ_SCREEN_CLIENT_REMOVE_WINDOW_SELECTOR:
            (void)client.RemoveWindow(windowId);
            break;
        case SCR_FUZZ_SCREEN_CLIENT_DESTROY_ALL_SELECTOR:
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
    switch (provider.ConsumeIntegralInRange<uint8_t>(SCR_FUZZ_MIN_SELECTOR, SCR_FUZZ_MAX_WINDOW_ADAPTER_SELECTOR)) {
        case SCR_FUZZ_WINDOW_ADAPTER_CREATE_WINDOW_SELECTOR: {
            std::shared_ptr<WindowProperty> nullProperty = nullptr;
            (void)adapter.CreateWindow(nullProperty, windowId);
            break;
        }
        case SCR_FUZZ_WINDOW_ADAPTER_SHOW_WINDOW_SELECTOR:
            (void)adapter.ShowWindow(windowId);
            break;
        case SCR_FUZZ_WINDOW_ADAPTER_HIDE_WINDOW_SELECTOR:
            (void)adapter.HideWindow(windowId);
            break;
        case SCR_FUZZ_WINDOW_ADAPTER_MOVE_WINDOW_SELECTOR:
            (void)adapter.MoveWindow(windowId,
                provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_COORDINATE, SCR_FUZZ_MAX_COORDINATE),
                provider.ConsumeIntegralInRange<int32_t>(SCR_FUZZ_MIN_COORDINATE, SCR_FUZZ_MAX_COORDINATE));
            break;
        case SCR_FUZZ_WINDOW_ADAPTER_REMOVE_WINDOW_SELECTOR:
            (void)adapter.RemoveWindow(windowId);
            break;
        case SCR_FUZZ_WINDOW_ADAPTER_DESTROY_ALL_SELECTOR:
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
        SCR_FUZZ_ZERO_WINDOW_ID,
        ConsumeWindowId(provider),
    };

    uint8_t operationCount = provider.ConsumeIntegralInRange<uint8_t>(SCR_FUZZ_WINDOW_ID_ZERO_SELECTOR,
        SCR_FUZZ_MAX_OPERATION_COUNT);
    for (uint8_t index = SCR_FUZZ_MIN_SELECTOR; index < operationCount; ++index) {
        int32_t windowId = windowIds[provider.ConsumeIntegralInRange<size_t>(SCR_FUZZ_MIN_WINDOW_ID_INDEX,
            windowIds.size() - SCR_FUZZ_WINDOW_ID_INDEX_STEP)];
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
    return SCR_FUZZ_FUZZ_SUCCESS;
}
