// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#ifndef HAP_OPAQUE_TYPES_64_H
#define HAP_OPAQUE_TYPES_64_H

#ifdef __cplusplus
extern "C" {
#endif

#include "HAPBase.h"

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

/**
 * String builder.
 */
typedef HAP_OPAQUE(32) HAPStringBuilderRef;

/**
 * TLV Reader.
 */
typedef HAP_OPAQUE(32) HAPTLVReaderRef;

/**
 * TLV Writer.
 */
typedef HAP_OPAQUE(32) HAPTLVWriterRef;
HAP_NONNULL_SUPPORT(HAPTLVWriterRef)

/**
 * HomeKit Accessory server.
 */
typedef HAP_OPAQUE(1896) HAPAccessoryServerRef;
HAP_NONNULL_SUPPORT(HAPAccessoryServerRef)

/**
 * HomeKit Session.
 */
typedef HAP_OPAQUE(424) HAPSessionRef;
HAP_NONNULL_SUPPORT(HAPSessionRef)

/**
 * IP request context.
 */
typedef HAP_OPAQUE(64) HAPIPCharacteristicContextRef;

/**
 * IP session descriptor.
 */
typedef HAP_OPAQUE(832) HAPIPSessionDescriptorRef;

/**
 * IP event notification.
 */
typedef HAP_OPAQUE(24) HAPIPEventNotificationRef;

/**
 * Element of the BLE GATT table.
 *
 * - For accessories that support Bluetooth LE, at least one of these elements must be allocated per HomeKit
 *   characteristic and service, and provided as part of a HAPBLEAccessoryServerStorage structure.
 */
typedef HAP_OPAQUE(56) HAPBLEGATTTableElementRef;

/**
 * Element of the BLE Pair Resume session cache.
 *
 * - For accessories that support Bluetooth LE, at least kHAPBLESessionCache_MinElements
 *   of these elements must be allocated and provided as part of a HAPBLEAccessoryServerStorage structure.
 */
typedef HAP_OPAQUE(48) HAPBLESessionCacheElementRef;

/**
 * HAP-BLE procedure.
 *
 * - For accessories that support Bluetooth LE, at least one of these procedures must be allocated
 *   and provided as part of a HAPBLEAccessoryServerStorage structure.
 */
typedef HAP_OPAQUE(160) HAPBLEProcedureRef;

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
