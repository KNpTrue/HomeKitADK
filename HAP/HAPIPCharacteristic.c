// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include "HAP+Internal.h"
#include "util_base64.h"

HAP_RESULT_USE_CHECK
bool HAPIPCharacteristicIsSupported(const HAPCharacteristic* characteristic_) {
    HAPPrecondition(characteristic_);
    const HAPBaseCharacteristic* characteristic = characteristic_;

    return !HAPUUIDAreEqual(characteristic->characteristicType, &kHAPCharacteristicType_ServiceSignature);
}

HAP_RESULT_USE_CHECK
size_t HAPCharacteristicGetNumEnabledProperties(const HAPCharacteristic* characteristic_) {
    HAPPrecondition(characteristic_);
    const HAPBaseCharacteristic* characteristic = characteristic_;

    // See HomeKit Accessory Protocol Specification R14
    // Section 6.3.3 Characteristic Objects
    return (characteristic->properties.readable ? 1 : 0) + (characteristic->properties.writable ? 1 : 0) +
           (characteristic->properties.supportsEventNotification ? 1 : 0) +
           (characteristic->properties.supportsAuthorizationData ? 1 : 0) +
           (characteristic->properties.requiresTimedWrite ? 1 : 0) +
           (characteristic->properties.ip.supportsWriteResponse ? 1 : 0) + (characteristic->properties.hidden ? 1 : 0);
}

HAP_RESULT_USE_CHECK
HAPCharacteristicUnits HAPCharacteristicGetUnit(const HAPCharacteristic* characteristic_) {
    HAPPrecondition(characteristic_);
    const HAPBaseCharacteristic* characteristic = characteristic_;

    // See HomeKit Accessory Protocol Specification R14
    // Section 6.3.3 Characteristic Objects
    switch (characteristic->format) {
        case kHAPCharacteristicFormat_UInt8: {
            return ((const HAPUInt8Characteristic*) characteristic)->units;
        }
        case kHAPCharacteristicFormat_UInt16: {
            return ((const HAPUInt16Characteristic*) characteristic)->units;
        }
        case kHAPCharacteristicFormat_UInt32: {
            return ((const HAPUInt32Characteristic*) characteristic)->units;
        }
        case kHAPCharacteristicFormat_UInt64: {
            return ((const HAPUInt64Characteristic*) characteristic)->units;
        }
        case kHAPCharacteristicFormat_Int: {
            return ((const HAPIntCharacteristic*) characteristic)->units;
        }
        case kHAPCharacteristicFormat_Float: {
            return ((const HAPFloatCharacteristic*) characteristic)->units;
        }
        case kHAPCharacteristicFormat_Bool:
        case kHAPCharacteristicFormat_String:
        case kHAPCharacteristicFormat_TLV8:
        case kHAPCharacteristicFormat_Data: {
            return kHAPCharacteristicUnits_None;
        }
    }
    HAPFatalError();
}

void HAPIPCharacteristicContextSetDataValue(
        HAPIPCharacteristicContextRef* _context,
        HAPIPByteBuffer* dataBuffer,
        const void* valueBytes,
        size_t numValueBytes) {
    HAPPrecondition(_context);
    HAPPrecondition(dataBuffer);
    HAPPrecondition(valueBytes);

    HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) _context;

    if (numValueBytes <= dataBuffer->limit - dataBuffer->position) {
        util_base64_encode(
                valueBytes,
                numValueBytes,
                &dataBuffer->data[dataBuffer->position],
                dataBuffer->limit - dataBuffer->position,
                &numValueBytes);
        if (numValueBytes < dataBuffer->limit - dataBuffer->position) {
            dataBuffer->data[dataBuffer->position + numValueBytes] = 0;
            context->value.stringValue.bytes = &dataBuffer->data[dataBuffer->position];
            context->value.stringValue.numBytes = numValueBytes;
            dataBuffer->position += numValueBytes + 1;
            HAPAssert(dataBuffer->position <= dataBuffer->limit);
            HAPAssert(dataBuffer->limit <= dataBuffer->capacity);
        } else {
            context->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
        }
    } else {
        context->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
    }
}

void HAPIPCharacteristicContextSetUIntValue(
        HAPIPCharacteristicContextRef* context,
        uint64_t value) {
    HAPPrecondition(context);

    ((HAPIPCharacteristicContext*) context)->value.unsignedIntValue = value;
}

void HAPIPCharacteristicContextSetIntValue(
        HAPIPCharacteristicContextRef* context,
        int32_t value) {
    HAPPrecondition(context);

    ((HAPIPCharacteristicContext*) context)->value.intValue = value;
}

void HAPIPCharacteristicContextSetFloatValue(
        HAPIPCharacteristicContextRef* context,
        float value) {
    HAPPrecondition(context);

    ((HAPIPCharacteristicContext*) context)->value.floatValue = value;
}

void HAPIPCharacteristicContextSetStringValue(
        HAPIPCharacteristicContextRef* _context,
        HAPIPByteBuffer* dataBuffer,
        const char* value) {
    HAPPrecondition(_context);
    HAPPrecondition(dataBuffer);
    HAPPrecondition(value);

    HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) _context;

    size_t len = HAPStringGetNumBytes(value);
    if (len < dataBuffer->limit - dataBuffer->position) {
        dataBuffer->data[dataBuffer->position + len] = 0;
        context->value.stringValue.bytes = &dataBuffer->data[dataBuffer->position];
        context->value.stringValue.numBytes = len;
        dataBuffer->position += len + 1;
        HAPAssert(dataBuffer->position <= dataBuffer->limit);
        HAPAssert(dataBuffer->limit <= dataBuffer->capacity);
    } else {
        context->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
    }
}

void HAPIPCharacteristicContextSetTLV8Value(
        HAPIPCharacteristicContextRef* _context,
        HAPIPByteBuffer* dataBuffer,
        HAPTLVWriterRef* writer) {
    HAPPrecondition(_context);
    HAPPrecondition(dataBuffer);
    HAPPrecondition(writer);

    HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) _context;

    if (((HAPTLVWriter*) writer)->numBytes <= dataBuffer->limit - dataBuffer->position) {
        size_t len;
        util_base64_encode(
                ((HAPTLVWriter*) writer)->bytes,
                ((HAPTLVWriter*) writer)->numBytes,
                &dataBuffer->data[dataBuffer->position],
                dataBuffer->limit - dataBuffer->position,
                &len);
        if (len < dataBuffer->limit - dataBuffer->position) {
            dataBuffer->data[dataBuffer->position + len] = 0;
            context->value.stringValue.bytes = &dataBuffer->data[dataBuffer->position];
            context->value.stringValue.numBytes = len;
            dataBuffer->position += len + 1;
            HAPAssert(dataBuffer->position <= dataBuffer->limit);
            HAPAssert(dataBuffer->limit <= dataBuffer->capacity);
        } else {
            context->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
        }
    } else {
        context->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
    }
}

int32_t HAPIPCharacteristicConvertReadErrorToStatusCode(HAPError error) {
    switch (error) {
        case kHAPError_None: {
            return kHAPIPAccessoryServerStatusCode_Success;
        }
        case kHAPError_Unknown: {
            return kHAPIPAccessoryServerStatusCode_UnableToPerformOperation;
        }
        case kHAPError_InvalidState: {
            return kHAPIPAccessoryServerStatusCode_UnableToPerformOperation;
        }
        case kHAPError_InvalidData: {
            HAPFatalError();
        }
        case kHAPError_OutOfResources: {
            return kHAPIPAccessoryServerStatusCode_OutOfResources;
        }
        case kHAPError_NotAuthorized: {
            return kHAPIPAccessoryServerStatusCode_InsufficientAuthorization;
        }
        case kHAPError_Busy: {
            return kHAPIPAccessoryServerStatusCode_ResourceIsBusy;
        }
        case kHAPError_InProgress: {
            return kHAPIPAccessoryServerStatusCode_InPorgress;
        }
    }
    HAPFatalError();
}

int32_t HAPIPCharacteristicConvertWriteErrorToStatusCode(HAPError error) {
    switch (error) {
        case kHAPError_None: {
            return kHAPIPAccessoryServerStatusCode_Success;
        }
        case kHAPError_Unknown: {
            return kHAPIPAccessoryServerStatusCode_UnableToPerformOperation;
        }
        case kHAPError_InvalidState: {
            return kHAPIPAccessoryServerStatusCode_UnableToPerformOperation;
        }
        case kHAPError_InvalidData: {
            return kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
        }
        case kHAPError_OutOfResources: {
            return kHAPIPAccessoryServerStatusCode_OutOfResources;
        }
        case kHAPError_NotAuthorized: {
            return kHAPIPAccessoryServerStatusCode_InsufficientAuthorization;
        }
        case kHAPError_Busy: {
            return kHAPIPAccessoryServerStatusCode_ResourceIsBusy;
        }
        case kHAPError_InProgress: {
            return kHAPIPAccessoryServerStatusCode_InPorgress;
        }
    }
    HAPFatalError();
}

void HAPIPCharacteristicHandleReadRequest(
        HAPIPSessionDescriptorRef* _session,
        const HAPCharacteristic* _chr,
        const HAPService* svc,
        const HAPAccessory* acc,
        HAPIPCharacteristicContextRef* _ctx,
        HAPIPByteBuffer* dataBuffer) {
    HAPPrecondition(_session);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) _session;
    HAPPrecondition(session->server);
    HAPPrecondition(_chr);
    HAPPrecondition(svc);
    HAPPrecondition(acc);
    HAPPrecondition(_ctx);
    HAPPrecondition(dataBuffer);

    HAPError err;

    size_t sval_length;
    bool bool_val;
    int32_t int_val;
    uint8_t uint8_val;
    uint16_t uint16_val;
    uint32_t uint32_val;
    uint64_t uint64_val;
    float float_val;
    HAPTLVWriterRef tlv8_writer;
    const HAPBaseCharacteristic* chr = _chr;
    HAPIPCharacteristicContext* ctx = (HAPIPCharacteristicContext*) _ctx;
    HAPAssert(dataBuffer->data);
    HAPAssert(dataBuffer->position <= dataBuffer->limit);
    HAPAssert(dataBuffer->limit <= dataBuffer->capacity);
    ctx->status = kHAPIPAccessoryServerStatusCode_Success;
    switch (chr->format) {
        case kHAPCharacteristicFormat_Data: {
            err = HAPDataCharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPDataCharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                .session = &session->securitySession.session,
                                                                .characteristic = (const HAPDataCharacteristic*) chr,
                                                                .service = svc,
                                                                .accessory = acc },
                    &dataBuffer->data[dataBuffer->position],
                    dataBuffer->limit - dataBuffer->position,
                    &sval_length,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetDataValue(
                        _ctx,
                        dataBuffer,
                        &dataBuffer->data[dataBuffer->position],
                        sval_length);
            }
        } break;
        case kHAPCharacteristicFormat_Bool: {
            err = HAPBoolCharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPBoolCharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                .session = &session->securitySession.session,
                                                                .characteristic = (const HAPBoolCharacteristic*) chr,
                                                                .service = svc,
                                                                .accessory = acc },
                    &bool_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetUIntValue(_ctx, bool_val ? 1 : 0);
            }
        } break;
        case kHAPCharacteristicFormat_UInt8: {
            err = HAPUInt8CharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPUInt8CharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                 .session = &session->securitySession.session,
                                                                 .characteristic = (const HAPUInt8Characteristic*) chr,
                                                                 .service = svc,
                                                                 .accessory = acc },
                    &uint8_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetUIntValue(_ctx, uint8_val);
            }
        } break;
        case kHAPCharacteristicFormat_UInt16: {
            err = HAPUInt16CharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPUInt16CharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                  .session = &session->securitySession.session,
                                                                  .characteristic =
                                                                          (const HAPUInt16Characteristic*) chr,
                                                                  .service = svc,
                                                                  .accessory = acc },
                    &uint16_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetUIntValue(_ctx, uint16_val);
            }
        } break;
        case kHAPCharacteristicFormat_UInt32: {
            err = HAPUInt32CharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPUInt32CharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                  .session = &session->securitySession.session,
                                                                  .characteristic =
                                                                          (const HAPUInt32Characteristic*) chr,
                                                                  .service = svc,
                                                                  .accessory = acc },
                    &uint32_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetUIntValue(_ctx, uint32_val);
            }
        } break;
        case kHAPCharacteristicFormat_UInt64: {
            err = HAPUInt64CharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPUInt64CharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                  .session = &session->securitySession.session,
                                                                  .characteristic =
                                                                          (const HAPUInt64Characteristic*) chr,
                                                                  .service = svc,
                                                                  .accessory = acc },
                    &uint64_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetUIntValue(_ctx, uint64_val);
            }
        } break;
        case kHAPCharacteristicFormat_Int: {
            err = HAPIntCharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPIntCharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                               .session = &session->securitySession.session,
                                                               .characteristic = (const HAPIntCharacteristic*) chr,
                                                               .service = svc,
                                                               .accessory = acc },
                    &int_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetIntValue(_ctx, int_val);
            }
        } break;
        case kHAPCharacteristicFormat_Float: {
            err = HAPFloatCharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPFloatCharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                 .session = &session->securitySession.session,
                                                                 .characteristic = (const HAPFloatCharacteristic*) chr,
                                                                 .service = svc,
                                                                 .accessory = acc },
                    &float_val,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetFloatValue(_ctx, float_val);
            }
        } break;
        case kHAPCharacteristicFormat_String: {
            err = HAPStringCharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPStringCharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                  .session = &session->securitySession.session,
                                                                  .characteristic =
                                                                          (const HAPStringCharacteristic*) chr,
                                                                  .service = svc,
                                                                  .accessory = acc },
                    &dataBuffer->data[dataBuffer->position],
                    dataBuffer->limit - dataBuffer->position,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetStringValue(_ctx, dataBuffer, &dataBuffer->data[dataBuffer->position]);
            }
        } break;
        case kHAPCharacteristicFormat_TLV8: {
            HAPTLVWriterCreate(
                    &tlv8_writer, &dataBuffer->data[dataBuffer->position], dataBuffer->limit - dataBuffer->position);
            err = HAPTLV8CharacteristicHandleRead(
                    HAPNonnull(session->server),
                    &(const HAPTLV8CharacteristicReadRequest) { .transportType = kHAPTransportType_IP,
                                                                .session = &session->securitySession.session,
                                                                .characteristic = (const HAPTLV8Characteristic*) chr,
                                                                .service = svc,
                                                                .accessory = acc },
                    &tlv8_writer,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            ctx->status = HAPIPCharacteristicConvertReadErrorToStatusCode(err);
            if (ctx->status == kHAPIPAccessoryServerStatusCode_Success) {
                HAPIPCharacteristicContextSetTLV8Value(_ctx, dataBuffer, &tlv8_writer);
            }
        } break;
    }
}

void HAPIPCharacteristicFinshWriteRequest(
        HAPIPSessionDescriptorRef* _session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer) {
    HAPPrecondition(_session);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) _session;
    HAPPrecondition(session->server);
    HAPPrecondition(service);
    HAPPrecondition(accessory);
    HAPPrecondition(context);
    HAPPrecondition(dataBuffer);

    const HAPBaseCharacteristic* baseCharacteristic = characteristic;
    HAPIPCharacteristicContext* writeContext = (HAPIPCharacteristicContext*) context;

    if (writeContext->status == kHAPIPAccessoryServerStatusCode_Success) {
        if (baseCharacteristic->properties.ip.supportsWriteResponse) {
            HAPIPByteBuffer dataBufferSnapshot;
            HAPRawBufferCopyBytes(&dataBufferSnapshot, dataBuffer, sizeof dataBufferSnapshot);
            HAPIPCharacteristicHandleReadRequest(
                    _session,
                    characteristic,
                    service,
                    accessory,
                    (HAPIPCharacteristicContextRef*) writeContext,
                    dataBuffer);
            if (writeContext->status == kHAPIPAccessoryServerStatusCode_Success) {
                if (!writeContext->write.response) {
                    // Ignore value of read operation and revert possible changes to data buffer.
                    HAPRawBufferCopyBytes(dataBuffer, &dataBufferSnapshot, sizeof *dataBuffer);
                }
            }
        } else if (writeContext->write.response) {
            writeContext->status = kHAPIPAccessoryServerStatusCode_ReadFromWriteOnlyCharacteristic;
        }
    }
}

void HAPIPCharacteristicHandleWriteRequest(
        HAPIPSessionDescriptorRef* _session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer) {
    HAPPrecondition(_session);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) _session;
    HAPPrecondition(session->server);
    HAPPrecondition(characteristic);
    HAPPrecondition(service);
    HAPPrecondition(accessory);
    HAPPrecondition(context);
    HAPPrecondition(dataBuffer);

    HAPError err;

    const HAPBaseCharacteristic* baseCharacteristic = characteristic;

    HAPIPCharacteristicContext* writeContext = (HAPIPCharacteristicContext*) context;
    HAPAssert(baseCharacteristic->iid == writeContext->iid);

    if ((writeContext->write.type == kHAPIPWriteValueType_None) &&
        (writeContext->write.ev == kHAPIPEventNotificationState_Undefined)) {
        writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
        return;
    }

    if (writeContext->write.ev != kHAPIPEventNotificationState_Undefined) {
        if (HAPCharacteristicReadRequiresAdminPermissions(baseCharacteristic) &&
            !HAPSessionControllerIsAdmin(&session->securitySession.session)) {
            writeContext->status = kHAPIPAccessoryServerStatusCode_InsufficientPrivileges;
        } else if (!baseCharacteristic->properties.supportsEventNotification) {
            writeContext->status = kHAPIPAccessoryServerStatusCode_NotificationNotSupported;
        } else {
            writeContext->status = kHAPIPAccessoryServerStatusCode_Success;
            HAPAssert(session->numEventNotifications <= session->maxEventNotifications);
            size_t i = 0;
            while ((i < session->numEventNotifications) &&
                   ((((HAPIPEventNotification*) &session->eventNotifications[i])->aid != writeContext->aid) ||
                    (((HAPIPEventNotification*) &session->eventNotifications[i])->iid != writeContext->iid))) {
                i++;
            }
            HAPAssert(
                    (i == session->numEventNotifications) ||
                    ((i < session->numEventNotifications) &&
                     (((HAPIPEventNotification*) &session->eventNotifications[i])->aid == writeContext->aid) &&
                     (((HAPIPEventNotification*) &session->eventNotifications[i])->iid == writeContext->iid)));
            if (i == session->numEventNotifications) {
                if (writeContext->write.ev == kHAPIPEventNotificationState_Enabled) {
                    if (i == session->maxEventNotifications) {
                        writeContext->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
                    } else {
                        ((HAPIPEventNotification*) &session->eventNotifications[i])->aid = writeContext->aid;
                        ((HAPIPEventNotification*) &session->eventNotifications[i])->iid = writeContext->iid;
                        ((HAPIPEventNotification*) &session->eventNotifications[i])->flag = false;
                        session->numEventNotifications++;
                        HAPIPCharacteristicHandleSubscribeRequest(_session, characteristic, service, accessory);
                    }
                }
            } else if (writeContext->write.ev == kHAPIPEventNotificationState_Disabled) {
                session->numEventNotifications--;
                if (((HAPIPEventNotification*) &session->eventNotifications[i])->flag) {
                    HAPAssert(session->numEventNotificationFlags > 0);
                    session->numEventNotificationFlags--;
                }
                while (i < session->numEventNotifications) {
                    HAPRawBufferCopyBytes(
                            &session->eventNotifications[i],
                            &session->eventNotifications[i + 1],
                            sizeof session->eventNotifications[i]);
                    i++;
                }
                HAPAssert(i == session->numEventNotifications);
                HAPIPCharacteristicHandleUnsubscribeRequest(_session, characteristic, service, accessory);
            }
        }
    }

    if (writeContext->write.type != kHAPIPWriteValueType_None) {
        if (HAPCharacteristicWriteRequiresAdminPermissions(baseCharacteristic) &&
            !HAPSessionControllerIsAdmin(&session->securitySession.session)) {
            writeContext->status = kHAPIPAccessoryServerStatusCode_InsufficientPrivileges;
            return;
        }
        if ((baseCharacteristic->properties.ip.supportsWriteResponse || writeContext->write.response) &&
            HAPCharacteristicReadRequiresAdminPermissions(baseCharacteristic) &&
            !HAPSessionControllerIsAdmin(&session->securitySession.session)) {
            writeContext->status = kHAPIPAccessoryServerStatusCode_InsufficientPrivileges;
            return;
        }
        if (baseCharacteristic->properties.writable) {
            writeContext->status = kHAPIPAccessoryServerStatusCode_Success;
            const void* authorizationDataBytes = NULL;
            size_t numAuthorizationDataBytes = 0;
            if (writeContext->write.authorizationData.bytes) {
                int r = util_base64_decode(
                        writeContext->write.authorizationData.bytes,
                        writeContext->write.authorizationData.numBytes,
                        writeContext->write.authorizationData.bytes,
                        writeContext->write.authorizationData.numBytes,
                        &writeContext->write.authorizationData.numBytes);
                if (r == 0) {
                    authorizationDataBytes = writeContext->write.authorizationData.bytes;
                    numAuthorizationDataBytes = writeContext->write.authorizationData.numBytes;
                } else {
                    writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                }
            }
            if (writeContext->status == kHAPIPAccessoryServerStatusCode_Success) {
                switch (baseCharacteristic->format) {
                    case kHAPCharacteristicFormat_Data: {
                        if (writeContext->write.type == kHAPIPWriteValueType_String) {
                            HAPAssert(writeContext->value.stringValue.bytes);
                            int r = util_base64_decode(
                                    writeContext->value.stringValue.bytes,
                                    writeContext->value.stringValue.numBytes,
                                    writeContext->value.stringValue.bytes,
                                    writeContext->value.stringValue.numBytes,
                                    &writeContext->value.stringValue.numBytes);
                            if (r == 0) {
                                HAPAssert(writeContext->value.stringValue.bytes);
                                err = HAPDataCharacteristicHandleWrite(
                                        HAPNonnull(session->server),
                                        &(const HAPDataCharacteristicWriteRequest) {
                                                .transportType = kHAPTransportType_IP,
                                                .session = &session->securitySession.session,
                                                .characteristic = (const HAPDataCharacteristic*) baseCharacteristic,
                                                .service = service,
                                                .accessory = accessory,
                                                .remote = writeContext->write.remote,
                                                .authorizationData = { .bytes = authorizationDataBytes,
                                                                       .numBytes = numAuthorizationDataBytes } },
                                        HAPNonnull(writeContext->value.stringValue.bytes),
                                        writeContext->value.stringValue.numBytes,
                                        HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                                writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                            } else {
                                writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                            }
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_Bool: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_UInt) &&
                            (writeContext->value.unsignedIntValue <= 1)) {
                            err = HAPBoolCharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPBoolCharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPBoolCharacteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    (bool) writeContext->value.unsignedIntValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_UInt8: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_UInt) &&
                            (writeContext->value.unsignedIntValue <= UINT8_MAX)) {
                            err = HAPUInt8CharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPUInt8CharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPUInt8Characteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    (uint8_t) writeContext->value.unsignedIntValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_UInt16: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_UInt) &&
                            (writeContext->value.unsignedIntValue <= UINT16_MAX)) {
                            err = HAPUInt16CharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPUInt16CharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPUInt16Characteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    (uint16_t) writeContext->value.unsignedIntValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_UInt32: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_UInt) &&
                            (writeContext->value.unsignedIntValue <= UINT32_MAX)) {
                            err = HAPUInt32CharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPUInt32CharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPUInt32Characteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    (uint32_t) writeContext->value.unsignedIntValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_UInt64: {
                        if (writeContext->write.type == kHAPIPWriteValueType_UInt) {
                            err = HAPUInt64CharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPUInt64CharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPUInt64Characteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    writeContext->value.unsignedIntValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_Int: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_UInt) &&
                            (writeContext->value.unsignedIntValue <= INT32_MAX)) {
                            writeContext->value.intValue = (int32_t) writeContext->value.unsignedIntValue;
                            writeContext->write.type = kHAPIPWriteValueType_Int;
                        }
                        if (writeContext->write.type == kHAPIPWriteValueType_Int) {
                            err = HAPIntCharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPIntCharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPIntCharacteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    writeContext->value.intValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_Float: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_Int) &&
                            (writeContext->value.intValue >= -FLT_MAX) && (writeContext->value.intValue <= FLT_MAX)) {
                            writeContext->value.floatValue = (float) writeContext->value.intValue;
                            writeContext->write.type = kHAPIPWriteValueType_Float;
                        }
                        if ((writeContext->write.type == kHAPIPWriteValueType_UInt) &&
                            (writeContext->value.unsignedIntValue <= FLT_MAX)) {
                            writeContext->value.floatValue = (float) writeContext->value.unsignedIntValue;
                            writeContext->write.type = kHAPIPWriteValueType_Float;
                        }
                        if (writeContext->write.type == kHAPIPWriteValueType_Float) {
                            err = HAPFloatCharacteristicHandleWrite(
                                    HAPNonnull(session->server),
                                    &(const HAPFloatCharacteristicWriteRequest) {
                                            .transportType = kHAPTransportType_IP,
                                            .session = &session->securitySession.session,
                                            .characteristic = (const HAPFloatCharacteristic*) baseCharacteristic,
                                            .service = service,
                                            .accessory = accessory,
                                            .remote = writeContext->write.remote,
                                            .authorizationData = { .bytes = authorizationDataBytes,
                                                                   .numBytes = numAuthorizationDataBytes } },
                                    writeContext->value.floatValue,
                                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                            writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_String: {
                        if ((writeContext->write.type == kHAPIPWriteValueType_String) &&
                            (writeContext->value.stringValue.numBytes <= 256)) {
                            HAPAssert(writeContext->value.stringValue.bytes);
                            HAPAssert(dataBuffer->data);
                            HAPAssert(dataBuffer->position <= dataBuffer->limit);
                            HAPAssert(dataBuffer->limit <= dataBuffer->capacity);
                            if (writeContext->value.stringValue.numBytes >= dataBuffer->limit - dataBuffer->position) {
                                writeContext->status = kHAPIPAccessoryServerStatusCode_OutOfResources;
                            } else {
                                HAPRawBufferCopyBytes(
                                        &dataBuffer->data[dataBuffer->position],
                                        HAPNonnull(writeContext->value.stringValue.bytes),
                                        writeContext->value.stringValue.numBytes);
                                dataBuffer->data[dataBuffer->position + writeContext->value.stringValue.numBytes] =
                                        '\0';
                                err = HAPStringCharacteristicHandleWrite(
                                        HAPNonnull(session->server),
                                        &(const HAPStringCharacteristicWriteRequest) {
                                                .transportType = kHAPTransportType_IP,
                                                .session = &session->securitySession.session,
                                                .characteristic = (const HAPStringCharacteristic*) baseCharacteristic,
                                                .service = service,
                                                .accessory = accessory,
                                                .remote = writeContext->write.remote,
                                                .authorizationData = { .bytes = authorizationDataBytes,
                                                                       .numBytes = numAuthorizationDataBytes } },
                                        &dataBuffer->data[dataBuffer->position],
                                        HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                                writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                            }
                        } else {
                            writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                        }
                    } break;
                    case kHAPCharacteristicFormat_TLV8: {
                        if (writeContext->write.type == kHAPIPWriteValueType_String) {
                            HAPAssert(writeContext->value.stringValue.bytes);
                            int r = util_base64_decode(
                                    writeContext->value.stringValue.bytes,
                                    writeContext->value.stringValue.numBytes,
                                    writeContext->value.stringValue.bytes,
                                    writeContext->value.stringValue.numBytes,
                                    &writeContext->value.stringValue.numBytes);
                            if (r == 0) {
                                HAPTLVReaderRef tlvReader;
                                HAPTLVReaderCreate(
                                        &tlvReader,
                                        writeContext->value.stringValue.bytes,
                                        writeContext->value.stringValue.numBytes);
                                err = HAPTLV8CharacteristicHandleWrite(
                                        HAPNonnull(session->server),
                                        &(const HAPTLV8CharacteristicWriteRequest) {
                                                .transportType = kHAPTransportType_IP,
                                                .session = &session->securitySession.session,
                                                .characteristic = (const HAPTLV8Characteristic*) baseCharacteristic,
                                                .service = service,
                                                .accessory = accessory,
                                                .remote = writeContext->write.remote,
                                                .authorizationData = { .bytes = authorizationDataBytes,
                                                                       .numBytes = numAuthorizationDataBytes } },
                                        &tlvReader,
                                        HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
                                writeContext->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(err);
                            } else {
                                writeContext->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                            }
                        }
                    } break;
                }
                HAPIPCharacteristicFinshWriteRequest(_session, characteristic, service, accessory, context, dataBuffer);
            }
        } else {
            writeContext->status = kHAPIPAccessoryServerStatusCode_WriteToReadOnlyCharacteristic;
        }
    }
}

void HAPIPCharacteristicHandleSubscribeRequest(
        HAPIPSessionDescriptorRef* _session,
        const HAPCharacteristic* chr,
        const HAPService* svc,
        const HAPAccessory* acc) {
    HAPPrecondition(_session);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) _session;
    HAPPrecondition(session->server);
    HAPPrecondition(chr);
    HAPPrecondition(svc);
    HAPPrecondition(acc);

    HAPAccessoryServerHandleSubscribe(HAPNonnull(session->server), &session->securitySession.session, chr, svc, acc);
}

void HAPIPCharacteristicHandleUnsubscribeRequest(
        HAPIPSessionDescriptorRef* _session,
        const HAPCharacteristic* chr,
        const HAPService* svc,
        const HAPAccessory* acc) {
    HAPPrecondition(_session);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) _session;
    HAPPrecondition(session->server);
    HAPPrecondition(chr);
    HAPPrecondition(svc);
    HAPPrecondition(acc);

    HAPAccessoryServerHandleUnsubscribe(HAPNonnull(session->server), &session->securitySession.session, chr, svc, acc);
}
