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

#ifndef OHOS_DSCREEN_IPC_INTERFACE_CODE_H
#define OHOS_DSCREEN_IPC_INTERFACE_CODE_H

#include <cstdint>

namespace OHOS {
namespace DistributedHardware {
/* SAID: 4807*/
enum class IDScreenSourceInterfaceCode : uint32_t {
    INIT_SOURCE = 0,
    RELEASE_SOURCE = 1,
    REGISTER_DISTRIBUTED_HARDWARE = 2,
    UNREGISTER_DISTRIBUTED_HARDWARE = 3,
    CONFIG_DISTRIBUTED_HARDWARE = 4,
    DSCREEN_NOTIFY = 5,
};

/* SAID: 4808*/
enum class IDScreenSinkInterfaceCode : uint32_t {
    INIT_SINK = 0,
    RELEASE_SINK = 1,
    SUBSCRIBE_DISTRIBUTED_HARDWARE = 2,
    UNSUBSCRIBE_DISTRIBUTED_HARDWARE = 3,
    DSCREEN_NOTIFY = 4,
};
} // namespace DistributedHardware
} // namespace OHOS
#endif