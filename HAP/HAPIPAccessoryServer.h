// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#ifndef HAP_IP_ACCESSORY_SERVER_H
#define HAP_IP_ACCESSORY_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "HAP+Internal.h"

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

/**
 * HAP Status Codes.
 *
 * @see HomeKit Accessory Protocol Specification R14
 *      Table 6-11 HAP Status Codes
 */
/**@{*/
/** This specifies a success for the request. */
#define kHAPIPAccessoryServerStatusCode_Success ((int32_t) 0)

/** Request denied due to insufficient privileges. */
#define kHAPIPAccessoryServerStatusCode_InsufficientPrivileges ((int32_t) -70401)

/** Unable to perform operation with requested service or characteristic. */
#define kHAPIPAccessoryServerStatusCode_UnableToPerformOperation ((int32_t) -70402)

/** Resource is busy, try again. */
#define kHAPIPAccessoryServerStatusCode_ResourceIsBusy ((int32_t) -70403)

/** Cannot write to read only characteristic. */
#define kHAPIPAccessoryServerStatusCode_WriteToReadOnlyCharacteristic ((int32_t) -70404)

/** Cannot read from a write only characteristic. */
#define kHAPIPAccessoryServerStatusCode_ReadFromWriteOnlyCharacteristic ((int32_t) -70405)

/** Notification is not supported for characteristic. */
#define kHAPIPAccessoryServerStatusCode_NotificationNotSupported ((int32_t) -70406)

/** Out of resources to process request. */
#define kHAPIPAccessoryServerStatusCode_OutOfResources ((int32_t) -70407)

/** Resource does not exist. */
#define kHAPIPAccessoryServerStatusCode_ResourceDoesNotExist ((int32_t) -70409)

/** Accessory received an invalid value in a write request. */
#define kHAPIPAccessoryServerStatusCode_InvalidValueInWrite ((int32_t) -70410)

/** Insufficient Authorization. */
#define kHAPIPAccessoryServerStatusCode_InsufficientAuthorization ((int32_t) -70411)

/** In progress. */
#define kHAPIPAccessoryServerStatusCode_InPorgress ((int32_t) -70412)

/**@}*/

struct HAPIPAccessoryServerTransport {
    void (*create)(HAPAccessoryServerRef* server, const HAPAccessoryServerOptions* options);

    void (*prepareStart)(HAPAccessoryServerRef* server);

    void (*prepareStop)(HAPAccessoryServerRef* server);

    struct {
        void (*invalidateDependentIPState)(HAPAccessoryServerRef* server_, HAPSessionRef* session);
    } session;

    struct {
        void (*init)(HAPAccessoryServerRef* server);

        HAP_RESULT_USE_CHECK
        HAPError (*deinit)(HAPAccessoryServerRef* server);

        HAP_RESULT_USE_CHECK
        HAPAccessoryServerState (*getState)(HAPAccessoryServerRef* server);

        void (*start)(HAPAccessoryServerRef* server);

        HAP_RESULT_USE_CHECK
        HAPError (*stop)(HAPAccessoryServerRef* server);

        HAP_RESULT_USE_CHECK
        HAPError (*raiseEvent)(
                HAPAccessoryServerRef* server,
                const HAPCharacteristic* characteristic,
                const HAPService* service,
                const HAPAccessory* accessory);

        HAP_RESULT_USE_CHECK
        HAPError (*raiseEventOnSession)(
                HAPAccessoryServerRef* server,
                const HAPCharacteristic* characteristic,
                const HAPService* service,
                const HAPAccessory* accessory,
                const HAPSessionRef* session);

        HAP_RESULT_USE_CHECK
        HAPError (*raiseEventByIID)(
                HAPAccessoryServerRef* server,
                uint64_t iid,
                uint64_t aid,
                const HAPSessionRef* session);

        HAP_RESULT_USE_CHECK
        HAPError (*responseWriteRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPCharacteristic* characteristic,
                HAPError result);

        HAP_RESULT_USE_CHECK
        HAPError (*responseDataReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPDataCharacteristic* characteristic,
                HAPError result,
                const void* valueBytes,
                size_t numValueBytes);

        HAP_RESULT_USE_CHECK
        HAPError (*responseBoolReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPBoolCharacteristic* characteristic,
                HAPError result,
                bool value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseUInt8ReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPUInt8Characteristic* characteristic,
                HAPError result,
                uint8_t value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseUInt16ReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPUInt16Characteristic* characteristic,
                HAPError result,
                uint16_t value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseUInt32ReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPUInt32Characteristic* characteristic,
                HAPError result,
                uint32_t value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseUInt64ReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPUInt64Characteristic* characteristic,
                HAPError result,
                uint64_t value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseIntReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPIntCharacteristic* characteristic,
                HAPError result,
                int32_t value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseFloatReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPFloatCharacteristic* characteristic,
                HAPError result,
                float value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseStringReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPStringCharacteristic* characteristic,
                HAPError result,
                const char* value);

        HAP_RESULT_USE_CHECK
        HAPError (*responseTLV8ReadRequest)(
                HAPAccessoryServerRef* server,
                HAPSessionRef* session,
                const HAPAccessory* accessory,
                const HAPService* service,
                const HAPTLV8Characteristic* characteristic,
                HAPError result,
                HAPTLVWriterRef* writer);
    } serverEngine;
};

/**
 * Session.
 */
typedef struct {
    /** Whether or not the session is open. */
    bool isOpen : 1;

    /** Whether or not a security session has been established. */
    bool isSecured : 1;

    /**
     * Whether or not the /config message has been received.
     *
     * - This sends FIN after the next response, and restarts the IP server after receiving FIN from controller.
     */
    bool receivedConfig : 1;

    /** HAP Session. */
    HAPSessionRef session;
} HAPIPSecuritySession;

//----------------------------------------------------------------------------------------------------------------------

/**
 * Accessory server session state.
 */
HAP_ENUM_BEGIN(uint8_t, HAPIPSessionState) { /** Accessory server session is idle. */
                                             kHAPIPSessionState_Idle,

                                             /** Accessory server session is reading. */
                                             kHAPIPSessionState_Reading,

                                             /** Accessory server session is writing. */
                                             kHAPIPSessionState_Writing
} HAP_ENUM_END(uint8_t, HAPIPSessionState);

/**
 * Session in progress state.
 */
HAP_ENUM_BEGIN(uint8_t, HAPIPSessionInProgressState) { /** None. */
                                                       kHAPIPSessionInProgressState_None,

                                                       /** Get Accessories. */
                                                       kHAPIPSessionInProgressState_GetAccessories,

                                                       /** Put characteristics. */
                                                       kHAPIPSessionInProgressState_PutCharacteristics,

                                                       /** Get characteristics. */
                                                       kHAPIPSessionInProgressState_GetCharacteristics,
        
                                                       /** Event notifications. */
                                                       kHAPIPSessionInProgressState_EventNotifications,
} HAP_ENUM_END(uint8_t, HAPIPSessionInProgressState);

/**
 * HTTP/1.1 Content Type.
 */
HAP_ENUM_BEGIN(uint8_t, HAPIPAccessoryServerContentType) { /** Unknown HTTP/1.1 content type. */
                                                           kHAPIPAccessoryServerContentType_Unknown,

                                                           /** application/hap+json. */
                                                           kHAPIPAccessoryServerContentType_Application_HAPJSON,

                                                           /** application/octet-stream. */
                                                           kHAPIPAccessoryServerContentType_Application_OctetStream,

                                                           /** application/pairing+tlv8. */
                                                           kHAPIPAccessoryServerContentType_Application_PairingTLV8,
} HAP_ENUM_END(uint8_t, HAPIPAccessoryServerContentType);

/**
 * IP specific event notification state.
 */
typedef struct {
    /** Accessory instance ID. */
    uint64_t aid;

    /** Characteristic instance ID. */
    uint64_t iid;

    /** Flag indicating whether an event has been raised for the given characteristic in the given accessory. */
    bool flag;
} HAPIPEventNotification;
HAP_STATIC_ASSERT(sizeof(HAPIPEventNotificationRef) >= sizeof(HAPIPEventNotification), event_notification);

/**
 * IP specific accessory server session descriptor.
 */
typedef struct {
    /** Accessory server serving this session. */
    HAPAccessoryServerRef* _Nullable server;

    /** TCP stream. */
    HAPPlatformTCPStreamRef tcpStream;

    /** Flag indicating whether the TCP stream is open. */
    bool tcpStreamIsOpen;

    /** IP session state. */
    HAPIPSessionState state;

    /** Time stamp of last activity on this session. */
    HAPTime stamp;

    /** Security session. */
    HAPIPSecuritySession securitySession;

    /** Inbound buffer. */
    HAPIPByteBuffer inboundBuffer;

    /** Outbound buffer. */
    HAPIPByteBuffer outboundBuffer;

    /** Scratch buffer. */
    HAPIPByteBuffer scratchBuffer;

    /** Marked inbound buffer position indicating the position until which the buffer has been decrypted. */
    size_t inboundBufferMark;

    /**
     * Marked outbound buffer position indicating the position until which the buffer has not yet been encrypted
     * (starting from outboundBuffer->limit).
     */
    size_t outboundBufferMark;

    /** HTTP reader. */
    struct util_http_reader httpReader;

    /** Current position of the HTTP reader in the inbound buffer. */
    size_t httpReaderPosition;

    /** Flag indication whether an error has been encountered while parsing a HTTP message. */
    bool httpParserError;

    /**
     * HTTP/1.1 Method.
     */
    struct {
        /**
         * Pointer to the HTTP/1.1 method in the inbound buffer.
         */
        char* _Nullable bytes;

        /**
         * Length of the HTTP/1.1 method in the inbound buffer.
         */
        size_t numBytes;
    } httpMethod;

    /**
     * HTTP/1.1 URI.
     */
    struct {
        /**
         * Pointer to the HTTP/1.1 URI in the inbound buffer.
         */
        char* _Nullable bytes;

        /**
         * Length of the HTTP/1.1 URI in the inbound buffer.
         */
        size_t numBytes;
    } httpURI;

    /**
     * HTTP/1.1 Header Field Name.
     */
    struct {
        /**
         * Pointer to the current HTTP/1.1 header field name in the inbound buffer.
         */
        char* _Nullable bytes;

        /**
         * Length of the current HTTP/1.1 header field name in the inbound buffer.
         */
        size_t numBytes;
    } httpHeaderFieldName;

    /**
     * HTTP/1.1 Header Field Value.
     */
    struct {
        /**
         * Pointer to the current HTTP/1.1 header value in the inbound buffer.
         */
        char* _Nullable bytes;

        /**
         * Length of the current HTTP/1.1 header value in the inbound buffer.
         */
        size_t numBytes;
    } httpHeaderFieldValue;

    /**
     * HTTP/1.1 Content Length.
     */
    struct {
        /**
         * Flag indicating whether a HTTP/1.1 content length is defined.
         */
        bool isDefined;

        /**
         * HTTP/1.1 content length.
         */
        size_t value;
    } httpContentLength;

    /**
     * HTTP/1.1 Content Type.
     */
    HAPIPAccessoryServerContentType httpContentType;

    /**
     * Array of read/write contexts on this session.
     */
    HAPIPCharacteristicContextRef* _Nullable contexts;

    /**
     * The maximum number of contexts this session can handle.
     */
    size_t maxContexts;

    /**
     * The number of contexts on this session.
     */
    size_t numContexts;

    /**
     * Array of event notification contexts on this session.
     */
    HAPIPEventNotificationRef* _Nullable eventNotifications;

    /**
     * The maximum number of events this session can handle.
     */
    size_t maxEventNotifications;

    /**
     * The number of subscribed events on this session.
     */
    size_t numEventNotifications;

    /**
     * The number of raised events on this session.
     */
    size_t numEventNotificationFlags;

    /**
     * Time stamp of last event notification on this session.
     */
    HAPTime eventNotificationStamp;

    /**
     * Time when the request expires. 0 if no timed write in progress.
     */
    HAPTime timedWriteExpirationTime;

    /**
     * PID of timed write. Must match "pid" of next PUT /characteristics.
     */
    uint64_t timedWritePID;

    /**
     * Serialization context for incremental accessory attribute database serialization.
     */
    HAPIPAccessorySerializationContext accessorySerializationContext;

    struct {
        bool mutliStatus;
        HAPIPReadRequestParameters parameters;
        HAPIPSessionInProgressState state;
        size_t numContexts;
        HAPPlatformTimerRef timer;
    } inProgress;
} HAPIPSessionDescriptor;
HAP_STATIC_ASSERT(sizeof(HAPIPSessionDescriptorRef) >= sizeof(HAPIPSessionDescriptor), HAPIPSessionDescriptor);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
