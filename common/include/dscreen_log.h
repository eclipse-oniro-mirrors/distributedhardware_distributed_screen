/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DSCREEN_LOG_H
#define OHOS_DSCREEN_LOG_H

#include <cinttypes>

#include "hilog/log.h"
#include <inttypes.h>

namespace OHOS {
namespace DistributedHardware {
#undef LOG_TAG
#define LOG_TAG "DSCREEN"

#define DHLOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, \
    "[%{public}s][%{public}s]:" fmt, DH_LOG_TAG, __FUNCTION__, ##__VA_ARGS__)

#define DHLOGI(fmt, ...) HILOG_INFO(LOG_CORE, \
    "[%{public}s][%{public}s]:" fmt, DH_LOG_TAG, __FUNCTION__, ##__VA_ARGS__)

#define DHLOGW(fmt, ...) HILOG_WARN(LOG_CORE, \
    "[%{public}s][%{public}s]:" fmt, DH_LOG_TAG, __FUNCTION__, ##__VA_ARGS__)

#define DHLOGE(fmt, ...) HILOG_ERROR(LOG_CORE, \
    "[%{public}s][%{public}s]:" fmt, DH_LOG_TAG, __FUNCTION__, ##__VA_ARGS__)
} // namespace DistributedHardware
} // namespace OHOS
#endif