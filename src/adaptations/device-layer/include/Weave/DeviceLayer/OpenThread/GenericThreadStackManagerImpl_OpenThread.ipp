/*
 *
 *    Copyright (c) 2019 Nest Labs, Inc.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *          Contains non-inline method definitions for the
 *          GenericThreadStackManagerImpl_OpenThread<> template.
 */

#ifndef GENERIC_THREAD_STACK_MANAGER_IMPL_OPENTHREAD_IPP
#define GENERIC_THREAD_STACK_MANAGER_IMPL_OPENTHREAD_IPP

#include <Weave/DeviceLayer/internal/WeaveDeviceLayerInternal.h>
#include <Weave/DeviceLayer/ThreadStackManager.h>
#include <Weave/DeviceLayer/OpenThread/GenericThreadStackManagerImpl_OpenThread.h>
#include <Weave/DeviceLayer/OpenThread/OpenThreadUtils.h>
#include <Weave/Profiles/network-provisioning/NetworkProvisioning.h>
#include <Weave/DeviceLayer/internal/DeviceNetworkInfo.h>
#include <Weave/Support/crypto/WeaveRNG.h>
#include <Weave/Support/TraitEventUtils.h>
#include <nest/trait/network/TelemetryNetworkWpanTrait.h>

#include <openthread/thread.h>
#include <openthread/tasklet.h>
#include <openthread/link.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>

using namespace ::nl::Weave::Profiles::NetworkProvisioning;
using namespace Schema::Nest::Trait::Network;

extern "C" void otSysProcessDrivers(otInstance *aInstance);

namespace nl {
namespace Weave {
namespace DeviceLayer {
namespace Internal {

// Assert some presumptions in this code
static_assert(DeviceNetworkInfo::kMaxThreadNetworkNameLength == OT_NETWORK_NAME_MAX_SIZE);
static_assert(DeviceNetworkInfo::kThreadExtendedPANIdLength == OT_EXT_PAN_ID_SIZE);
static_assert(DeviceNetworkInfo::kThreadMeshPrefixLength == OT_MESH_LOCAL_PREFIX_SIZE);
static_assert(DeviceNetworkInfo::kThreadNetworkKeyLength == OT_MASTER_KEY_SIZE);
static_assert(DeviceNetworkInfo::kThreadPSKcLength == OT_PSKC_MAX_SIZE);

static WEAVE_ERROR LogThreadTopologyEntries(nl::Weave::Profiles::DataManagement_Current::event_id_t parentEventId,
                                            otNeighborInfo *neighborInfoTable, uint32_t neighborInfoTableSize);

// Fully instantiate the generic implementation class in whatever compilation unit includes this file.
template class GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>;

/**
 * Called by OpenThread to alert the ThreadStackManager of a change in the state of the Thread stack.
 *
 * By default, applications never need to call this method directly.  However, applications that
 * wish to receive OpenThread state change call-backs directly from OpenThread (e.g. by calling
 * otSetStateChangedCallback() with their own callback function) can call this method to pass
 * state change events to the ThreadStackManager.
 */
template<class ImplClass>
void GenericThreadStackManagerImpl_OpenThread<ImplClass>::OnOpenThreadStateChange(uint32_t flags, void * context)
{
    WeaveDeviceEvent event;
    event.Type = DeviceEventType::kThreadStateChange;
    event.ThreadStateChange.RoleChanged = (flags & OT_CHANGED_THREAD_ROLE) != 0;
    event.ThreadStateChange.AddressChanged = (flags & (OT_CHANGED_IP6_ADDRESS_ADDED|OT_CHANGED_IP6_ADDRESS_REMOVED)) != 0;
    event.ThreadStateChange.NetDataChanged = (flags & OT_CHANGED_THREAD_NETDATA) != 0;
    event.ThreadStateChange.ChildNodesChanged = (flags & (OT_CHANGED_THREAD_CHILD_ADDED|OT_CHANGED_THREAD_CHILD_REMOVED)) != 0;
    event.ThreadStateChange.OpenThread.Flags = flags;
    PlatformMgr().PostEvent(&event);
}

template<class ImplClass>
void GenericThreadStackManagerImpl_OpenThread<ImplClass>::_ProcessThreadActivity(void)
{
    otTaskletsProcess(mOTInst);
    otSysProcessDrivers(mOTInst);
}

template<class ImplClass>
bool GenericThreadStackManagerImpl_OpenThread<ImplClass>::_HaveRouteToAddress(const IPAddress & destAddr)
{
    bool res = false;

    // Lock OpenThread
    Impl()->LockThreadStack();

    // No routing of IPv4 over Thread.
    VerifyOrExit(!destAddr.IsIPv4(), res = false);

    // If the device is attached to a Thread network...
    if (IsThreadAttachedNoLock())
    {
        // Link-local addresses are always presumed to be routable, provided the device is attached.
        if (destAddr.IsIPv6LinkLocal())
        {
            ExitNow(res = true);
        }

        // Iterate over the routes known to the OpenThread stack looking for a route that covers the
        // destination address.  If found, consider the address routable.
        // Ignore any routes advertised by this device.
        // If the destination address is a ULA, ignore default routes. Border routers advertising
        // default routes are not expected to be capable of routing Weave fabric ULAs unless they
        // advertise those routes specifically.
        {
            otError otErr;
            otNetworkDataIterator routeIter = OT_NETWORK_DATA_ITERATOR_INIT;
            otExternalRouteConfig routeConfig;
            const bool destIsULA = destAddr.IsIPv6ULA();

            while ((otErr = otNetDataGetNextRoute(Impl()->OTInstance(), &routeIter, &routeConfig)) == OT_ERROR_NONE)
            {
                const IPPrefix prefix = ToIPPrefix(routeConfig.mPrefix);
                char addrStr[64];
                prefix.IPAddr.ToString(addrStr, sizeof(addrStr));
                if (!routeConfig.mNextHopIsThisDevice &&
                    (!destIsULA || routeConfig.mPrefix.mLength > 0) &&
                    ToIPPrefix(routeConfig.mPrefix).MatchAddress(destAddr))
                {
                    ExitNow(res = true);
                }
            }
        }
    }

exit:

    // Unlock OpenThread
    Impl()->UnlockThreadStack();

    return res;
}

template<class ImplClass>
void GenericThreadStackManagerImpl_OpenThread<ImplClass>::_OnPlatformEvent(const WeaveDeviceEvent * event)
{
    if (event->Type == DeviceEventType::kThreadStateChange)
    {
#if WEAVE_DETAIL_LOGGING

        Impl()->LockThreadStack();

        LogOpenThreadStateChange(mOTInst, event->ThreadStateChange.OpenThread.Flags);

        Impl()->UnlockThreadStack();

#endif // WEAVE_DETAIL_LOGGING
    }
}

template<class ImplClass>
bool GenericThreadStackManagerImpl_OpenThread<ImplClass>::_IsThreadEnabled(void)
{
    otDeviceRole curRole;

    Impl()->LockThreadStack();
    curRole = otThreadGetDeviceRole(mOTInst);
    Impl()->UnlockThreadStack();

    return (curRole != OT_DEVICE_ROLE_DISABLED);
}

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::_SetThreadEnabled(bool val)
{
    otError otErr = OT_ERROR_NONE;

    Impl()->LockThreadStack();

    bool isEnabled = (otThreadGetDeviceRole(mOTInst) != OT_DEVICE_ROLE_DISABLED);
    if (val != isEnabled)
    {
        otErr = otThreadSetEnabled(mOTInst, val);
    }

    Impl()->UnlockThreadStack();

    return MapOpenThreadError(otErr);
}

template<class ImplClass>
bool GenericThreadStackManagerImpl_OpenThread<ImplClass>::_IsThreadProvisioned(void)
{
    bool provisioned;

    Impl()->LockThreadStack();
    provisioned = otDatasetIsCommissioned(mOTInst);
    Impl()->UnlockThreadStack();

    return provisioned;
}

template<class ImplClass>
bool GenericThreadStackManagerImpl_OpenThread<ImplClass>::_IsThreadAttached(void)
{
    otDeviceRole curRole;

    Impl()->LockThreadStack();
    curRole = otThreadGetDeviceRole(mOTInst);
    Impl()->UnlockThreadStack();

    return (curRole != OT_DEVICE_ROLE_DISABLED && curRole != OT_DEVICE_ROLE_DETACHED);
}

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::_GetThreadProvision(DeviceNetworkInfo & netInfo, bool includeCredentials)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    otOperationalDataset activeDataset;

    netInfo.Reset();

    Impl()->LockThreadStack();

    if (otDatasetIsCommissioned(mOTInst))
    {
        otError otErr = otDatasetGetActive(mOTInst, &activeDataset);
        err = MapOpenThreadError(otErr);
    }
    else
    {
        err = WEAVE_ERROR_INCORRECT_STATE;
    }

    Impl()->UnlockThreadStack();

    SuccessOrExit(err);

    netInfo.NetworkType = kNetworkType_Thread;
    netInfo.NetworkId = kThreadNetworkId;
    netInfo.FieldPresent.NetworkId = true;
    if (activeDataset.mComponents.mIsNetworkNamePresent)
    {
        strncpy(netInfo.ThreadNetworkName, (const char *)activeDataset.mNetworkName.m8, sizeof(netInfo.ThreadNetworkName));
    }
    if (activeDataset.mComponents.mIsExtendedPanIdPresent)
    {
        memcpy(netInfo.ThreadExtendedPANId, activeDataset.mExtendedPanId.m8, sizeof(netInfo.ThreadExtendedPANId));
        netInfo.FieldPresent.ThreadExtendedPANId = true;
    }
    if (activeDataset.mComponents.mIsMeshLocalPrefixPresent)
    {
        memcpy(netInfo.ThreadMeshPrefix, activeDataset.mMeshLocalPrefix.m8, sizeof(netInfo.ThreadMeshPrefix));
        netInfo.FieldPresent.ThreadMeshPrefix = true;
    }
    if (includeCredentials)
    {
        if (activeDataset.mComponents.mIsMasterKeyPresent)
        {
            memcpy(netInfo.ThreadNetworkKey, activeDataset.mMasterKey.m8, sizeof(netInfo.ThreadNetworkKey));
            netInfo.FieldPresent.ThreadNetworkKey = true;
        }
        if (activeDataset.mComponents.mIsPSKcPresent)
        {
            memcpy(netInfo.ThreadPSKc, activeDataset.mPSKc.m8, sizeof(netInfo.ThreadPSKc));
            netInfo.FieldPresent.ThreadPSKc = true;
        }
    }
    if (activeDataset.mComponents.mIsPanIdPresent)
    {
        netInfo.ThreadPANId = activeDataset.mPanId;
    }
    if (activeDataset.mComponents.mIsChannelPresent)
    {
        netInfo.ThreadChannel = activeDataset.mChannel;
    }

exit:
    return err;
}

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::_SetThreadProvision(const DeviceNetworkInfo & netInfo)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    otError otErr;
    otOperationalDataset newDataset;

    // Form a Thread operational dataset from the given network parameters.
    memset(&newDataset, 0, sizeof(newDataset));
    newDataset.mComponents.mIsActiveTimestampPresent = true;
    newDataset.mComponents.mIsPendingTimestampPresent = true;
    if (netInfo.ThreadNetworkName[0] != 0)
    {
        strncpy((char *)newDataset.mNetworkName.m8, netInfo.ThreadNetworkName, sizeof(newDataset.mNetworkName.m8));
        newDataset.mComponents.mIsNetworkNamePresent = true;
    }
    if (netInfo.FieldPresent.ThreadExtendedPANId)
    {
        memcpy(newDataset.mExtendedPanId.m8, netInfo.ThreadExtendedPANId, sizeof(newDataset.mExtendedPanId.m8));
        newDataset.mComponents.mIsExtendedPanIdPresent = true;
    }
    if (netInfo.FieldPresent.ThreadMeshPrefix)
    {
        memcpy(newDataset.mMeshLocalPrefix.m8, netInfo.ThreadMeshPrefix, sizeof(newDataset.mMeshLocalPrefix.m8));
        newDataset.mComponents.mIsMeshLocalPrefixPresent = true;
    }
    if (netInfo.FieldPresent.ThreadNetworkKey)
    {
        memcpy(newDataset.mMasterKey.m8, netInfo.ThreadNetworkKey, sizeof(newDataset.mMasterKey.m8));
        newDataset.mComponents.mIsMasterKeyPresent = true;
    }
    if (netInfo.FieldPresent.ThreadPSKc)
    {
        memcpy(newDataset.mPSKc.m8, netInfo.ThreadPSKc, sizeof(newDataset.mPSKc.m8));
        newDataset.mComponents.mIsPSKcPresent = true;
    }
    if (netInfo.ThreadPANId != kThreadPANId_NotSpecified)
    {
        newDataset.mPanId = netInfo.ThreadPANId;
        newDataset.mComponents.mIsPanIdPresent = true;
    }
    if (netInfo.ThreadChannel != kThreadChannel_NotSpecified)
    {
        newDataset.mChannel = netInfo.ThreadChannel;
        newDataset.mComponents.mIsChannelPresent = true;
    }

    // Set the dataset as the active dataset for the node.
    Impl()->LockThreadStack();
    otErr = otDatasetSetActive(mOTInst, &newDataset);
    Impl()->UnlockThreadStack();

    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

exit:
    return err;
}

template<class ImplClass>
void GenericThreadStackManagerImpl_OpenThread<ImplClass>::_ClearThreadProvision(void)
{
    Impl()->LockThreadStack();
    otThreadSetEnabled(mOTInst, false);
    otInstanceErasePersistentInfo(mOTInst);
    Impl()->UnlockThreadStack();
}

template<class ImplClass>
bool GenericThreadStackManagerImpl_OpenThread<ImplClass>::_HaveMeshConnectivity(void)
{
    bool res;
    otDeviceRole curRole;

    Impl()->LockThreadStack();

    // Get the current Thread role.
    curRole = otThreadGetDeviceRole(mOTInst);

    // If Thread is disabled, or the node is detached, then the node has no mesh connectivity.
    if (curRole == OT_DEVICE_ROLE_DISABLED || curRole == OT_DEVICE_ROLE_DETACHED)
    {
        res = false;
    }

    // If the node is a child, that implies the existence of a parent node which provides connectivity
    // to the mesh.
    else if (curRole == OT_DEVICE_ROLE_CHILD)
    {
        res = true;
    }

    // Otherwise, if the node is acting as a router, scan the Thread neighbor table looking for at least
    // one other node that is also acting as router.
    else
    {
        otNeighborInfoIterator neighborIter = OT_NEIGHBOR_INFO_ITERATOR_INIT;
        otNeighborInfo neighborInfo;

        res = false;

        while (otThreadGetNextNeighborInfo(mOTInst, &neighborIter, &neighborInfo) == OT_ERROR_NONE)
        {
            if (!neighborInfo.mIsChild)
            {
                res = true;
                break;
            }
        }
    }

    Impl()->UnlockThreadStack();

    return res;
}

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::_GetAndLogThreadStatsCounters(void)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    nl::Weave::Profiles::DataManagement_Current::event_id_t eventId;
    Schema::Nest::Trait::Network::TelemetryNetworkWpanTrait::NetworkWpanStatsEvent counterEvent = { 0 };
    const otMacCounters *macCounters;
    const otIpCounters *ipCounters;
    otDeviceRole role;

    Impl()->LockThreadStack();

    // Get Mac Counters
    macCounters = otLinkGetCounters(mOTInst);

    // Rx Counters
    counterEvent.phyRx                = macCounters->mRxTotal;
    counterEvent.macUnicastRx         = macCounters->mRxUnicast;
    counterEvent.macBroadcastRx       = macCounters->mRxBroadcast;
    counterEvent.macRxData            = macCounters->mRxData;
    counterEvent.macRxDataPoll        = macCounters->mRxDataPoll;
    counterEvent.macRxBeacon          = macCounters->mRxBeacon;
    counterEvent.macRxBeaconReq       = macCounters->mRxBeaconRequest;
    counterEvent.macRxOtherPkt        = macCounters->mRxOther;
    counterEvent.macRxFilterWhitelist = macCounters->mRxAddressFiltered;
    counterEvent.macRxFilterDestAddr  = macCounters->mRxDestAddrFiltered;

    // Tx Counters
    counterEvent.phyTx          = macCounters->mTxTotal;
    counterEvent.macUnicastTx   = macCounters->mTxUnicast;
    counterEvent.macBroadcastTx = macCounters->mTxBroadcast;
    counterEvent.macTxAckReq    = macCounters->mTxAckRequested;
    counterEvent.macTxNoAckReq  = macCounters->mTxNoAckRequested;
    counterEvent.macTxAcked     = macCounters->mTxAcked;
    counterEvent.macTxData      = macCounters->mTxData;
    counterEvent.macTxDataPoll  = macCounters->mTxDataPoll;
    counterEvent.macTxBeacon    = macCounters->mTxBeacon;
    counterEvent.macTxBeaconReq = macCounters->mTxBeaconRequest;
    counterEvent.macTxOtherPkt  = macCounters->mTxOther;
    counterEvent.macTxRetry     = macCounters->mTxRetry;

    // Tx Error Counters
    counterEvent.macTxFailCca = macCounters->mTxErrCca;

    // Rx Error Counters
    counterEvent.macRxFailDecrypt         = macCounters->mRxErrSec;
    counterEvent.macRxFailNoFrame         = macCounters->mRxErrNoFrame;
    counterEvent.macRxFailUnknownNeighbor = macCounters->mRxErrUnknownNeighbor;
    counterEvent.macRxFailInvalidSrcAddr  = macCounters->mRxErrInvalidSrcAddr;
    counterEvent.macRxFailFcs             = macCounters->mRxErrFcs;
    counterEvent.macRxFailOther           = macCounters->mRxErrOther;

    // Get Ip Counters
    ipCounters = otThreadGetIp6Counters(mOTInst);

    // Ip Counters
    counterEvent.ipTxSuccess = ipCounters->mTxSuccess;
    counterEvent.ipRxSuccess = ipCounters->mRxSuccess;
    counterEvent.ipTxFailure = ipCounters->mTxFailure;
    counterEvent.ipRxFailure = ipCounters->mRxFailure;

    // TODO
    // counterEvent.channel = static_cast<uint8_t>(NMUtilities::GetChannel6LoWPAN());

    role = otThreadGetDeviceRole(mOTInst);

    switch (role)
    {
    case OT_DEVICE_ROLE_LEADER:
        counterEvent.nodeType |= TelemetryNetworkWpanTrait::NODE_TYPE_LEADER;
        // Intentional fall-through: if it's a leader, then it's also a router
    case OT_DEVICE_ROLE_ROUTER:
        counterEvent.nodeType |= TelemetryNetworkWpanTrait::NODE_TYPE_ROUTER;
        break;
    case OT_DEVICE_ROLE_CHILD:
    case OT_DEVICE_ROLE_DISABLED:
    case OT_DEVICE_ROLE_DETACHED:
    default:
        counterEvent.nodeType = 0;
        break;
    }

    counterEvent.threadType = TelemetryNetworkWpanTrait::THREAD_TYPE_OPENTHREAD;

    WeaveLogProgress(DeviceLayer,
                     "Rx Counters:\n"
                     "PHY Rx Total:                 %d\n"
                     "MAC Rx Unicast:               %d\n"
                     "MAC Rx Broadcast:             %d\n"
                     "MAC Rx Data:                  %d\n"
                     "MAC Rx Data Polls:            %d\n"
                     "MAC Rx Beacons:               %d\n"
                     "MAC Rx Beacon Reqs:           %d\n"
                     "MAC Rx Other:                 %d\n"
                     "MAC Rx Filtered Whitelist:    %d\n"
                     "MAC Rx Filtered DestAddr:     %d\n",
                     counterEvent.phyRx, counterEvent.macUnicastRx, counterEvent.macBroadcastRx, counterEvent.macRxData,
                     counterEvent.macRxDataPoll, counterEvent.macRxBeacon, counterEvent.macRxBeaconReq, counterEvent.macRxOtherPkt,
                     counterEvent.macRxFilterWhitelist, counterEvent.macRxFilterDestAddr);

    WeaveLogProgress(DeviceLayer,
                     "Tx Counters:\n"
                     "PHY Tx Total:                 %d\n"
                     "MAC Tx Unicast:               %d\n"
                     "MAC Tx Broadcast:             %d\n"
                     "MAC Tx Data:                  %d\n"
                     "MAC Tx Data Polls:            %d\n"
                     "MAC Tx Beacons:               %d\n"
                     "MAC Tx Beacon Reqs:           %d\n"
                     "MAC Tx Other:                 %d\n"
                     "MAC Tx Retry:                 %d\n"
                     "MAC Tx CCA Fail:              %d\n",
                     counterEvent.phyTx, counterEvent.macUnicastTx, counterEvent.macBroadcastTx, counterEvent.macTxData,
                     counterEvent.macTxDataPoll, counterEvent.macTxBeacon, counterEvent.macTxBeaconReq, counterEvent.macTxOtherPkt,
                     counterEvent.macTxRetry, counterEvent.macTxFailCca);

    WeaveLogProgress(DeviceLayer,
                     "Failure Counters:\n"
                     "MAC Rx Decrypt Fail:          %d\n"
                     "MAC Rx No Frame Fail:         %d\n"
                     "MAC Rx Unknown Neighbor Fail: %d\n"
                     "MAC Rx Invalid Src Addr Fail: %d\n"
                     "MAC Rx FCS Fail:              %d\n"
                     "MAC Rx Other Fail:            %d\n",
                     counterEvent.macRxFailDecrypt, counterEvent.macRxFailNoFrame, counterEvent.macRxFailUnknownNeighbor,
                     counterEvent.macRxFailInvalidSrcAddr, counterEvent.macRxFailFcs, counterEvent.macRxFailOther);

    eventId = nl::LogEvent(&counterEvent);
    WeaveLogProgress(DeviceLayer, "OpenThread Tolopoly Stats event: %u\n", eventId);

    Impl()->UnlockThreadStack();

    return err;
}

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::_GetAndLogThreadTopologyMinimal(void)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    otError otErr;
    nl::Weave::Profiles::DataManagement_Current::event_id_t eventId;
    Schema::Nest::Trait::Network::TelemetryNetworkWpanTrait::NetworkWpanTopoMinimalEvent topologyEvent = { 0 };
    const otExtAddress *extAddress;

    Impl()->LockThreadStack();

    topologyEvent.rloc16 = otThreadGetRloc16(mOTInst);

    // Router ID is the top 6 bits of the RLOC
    topologyEvent.routerId = (topologyEvent.rloc16 >> 10) & 0x3f;

    topologyEvent.leaderRouterId = otThreadGetLeaderRouterId(mOTInst);

    otErr = otThreadGetParentAverageRssi(mOTInst, &topologyEvent.parentAverageRssi);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    otErr = otThreadGetParentLastRssi(mOTInst, &topologyEvent.parentLastRssi);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    topologyEvent.partitionId = otThreadGetPartitionId(mOTInst);

    extAddress = otLinkGetExtendedAddress(mOTInst);

    topologyEvent.extAddress.mBuf = (uint8_t *)extAddress;
    topologyEvent.extAddress.mLen = sizeof(otExtAddress);

    topologyEvent.instantRssi = otPlatRadioGetRssi(mOTInst);

    WeaveLogProgress(DeviceLayer,
                     "Thread Topology:\n"
                     "RLOC16:           %04X\n"
                     "Router ID:        %u\n"
                     "Leader Router ID: %u\n"
                     "Parent Avg RSSI:  %d\n"
                     "Parent Last RSSI: %d\n"
                     "Partition ID:     %d\n"
                     "Extended Address: %02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
                     "Instant RSSI:     %d\n",
                     topologyEvent.rloc16, topologyEvent.routerId, topologyEvent.leaderRouterId, topologyEvent.parentAverageRssi,
                     topologyEvent.parentLastRssi, topologyEvent.partitionId, topologyEvent.extAddress.mBuf[0], topologyEvent.extAddress.mBuf[1],
                     topologyEvent.extAddress.mBuf[2], topologyEvent.extAddress.mBuf[3], topologyEvent.extAddress.mBuf[4],
                     topologyEvent.extAddress.mBuf[5], topologyEvent.extAddress.mBuf[6], topologyEvent.extAddress.mBuf[7], topologyEvent.instantRssi);

    eventId = nl::LogEvent(&topologyEvent);
    WeaveLogProgress(DeviceLayer, "Topology event: %u\n", eventId);

    Impl()->UnlockThreadStack();

exit:
    if (err != WEAVE_NO_ERROR)
    {
        WeaveLogError(DeviceLayer, "GetAndLogThreadTopologyMinimul failed: %s", nl::ErrorStr(err));
    }

    return err;
}

#define TELEM_NEIGHBOR_TABLE_SIZE (64)

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::_GetAndLogThreadTopologyFull(void)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    otError otErr;
    nl::Weave::Profiles::DataManagement_Current::event_id_t eventId;
    Schema::Nest::Trait::Network::TelemetryNetworkWpanTrait::NetworkWpanTopoFullEvent topologyEvent = { 0 };
    otIp6Address * leaderAddr;
    uint8_t * networkData;
    uint8_t * stableNetworkData;
    uint8_t networkDataLen = 0;
    uint8_t stableNetworkDataLen = 0;
    const otExtAddress * extAddress;
    otNeighborInfo neighborInfo[TELEM_NEIGHBOR_TABLE_SIZE];
    otNeighborInfoIterator iter;
    otNeighborInfoIterator iterCopy;

    Impl()->LockThreadStack();

    topologyEvent.rloc16 = otThreadGetRloc16(mOTInst);

    // Router ID is the top 6 bits of the RLOC
    topologyEvent.routerId = (topologyEvent.rloc16 >> 10) & 0x3f;

    topologyEvent.leaderRouterId = otThreadGetLeaderRouterId(mOTInst);

    memset(leaderAddr->mFields.m8, 0, OT_IP6_ADDRESS_SIZE);

    otErr = otThreadGetLeaderRloc(mOTInst, leaderAddr);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    topologyEvent.leaderAddress.mBuf = leaderAddr->mFields.m8;
    topologyEvent.leaderAddress.mLen = OT_IP6_ADDRESS_SIZE;

    WeaveLogProgress(DeviceLayer, "Leader Address:        %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
                     leaderAddr->mFields.m8[0], leaderAddr->mFields.m8[1], leaderAddr->mFields.m8[2], leaderAddr->mFields.m8[3],
                     leaderAddr->mFields.m8[4], leaderAddr->mFields.m8[5], leaderAddr->mFields.m8[6], leaderAddr->mFields.m8[7],
                     leaderAddr->mFields.m8[8], leaderAddr->mFields.m8[9], leaderAddr->mFields.m8[10], leaderAddr->mFields.m8[11],
                     leaderAddr->mFields.m8[12], leaderAddr->mFields.m8[13], leaderAddr->mFields.m8[14], leaderAddr->mFields.m8[15]);

    topologyEvent.leaderWeight = otThreadGetLeaderWeight(mOTInst);

// TODO: enable
//    topologyEvent.leaderLocalWeight = otThreadGetLocalLeaderWeight(mOTInst);

    otErr = otNetDataGet(mOTInst, false, networkData, &networkDataLen);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    topologyEvent.networkData.mBuf = networkData;
    topologyEvent.networkData.mLen = networkDataLen;

    topologyEvent.networkDataVersion = otNetDataGetVersion(mOTInst);

    otErr = otNetDataGet(mOTInst, true, stableNetworkData, &stableNetworkDataLen);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    topologyEvent.stableNetworkData.mBuf = stableNetworkData;
    topologyEvent.stableNetworkData.mLen = stableNetworkDataLen;

    topologyEvent.stableNetworkDataVersion = otNetDataGetStableVersion(mOTInst);

    // Deprecated property
    topologyEvent.preferredRouterId = -1;

    extAddress = otLinkGetExtendedAddress(mOTInst);

    topologyEvent.extAddress.mBuf = (uint8_t *)extAddress;
    topologyEvent.extAddress.mLen = sizeof(otExtAddress);

    topologyEvent.partitionId = otThreadGetPartitionId(mOTInst);

    topologyEvent.instantRssi = otPlatRadioGetRssi(mOTInst);

    iter = OT_NEIGHBOR_INFO_ITERATOR_INIT;
    iterCopy = OT_NEIGHBOR_INFO_ITERATOR_INIT;
    topologyEvent.neighborTableSize = 0;
    topologyEvent.childTableSize = 0;

    while (otThreadGetNextNeighborInfo(mOTInst, &iter, &neighborInfo[iter]) == OT_ERROR_NONE)
    {
        topologyEvent.neighborTableSize++;
        if (neighborInfo[iterCopy].mIsChild)
        {
            topologyEvent.childTableSize++;
        }
	iterCopy = iter;
    }

    eventId = nl::LogEvent(&topologyEvent);
    WeaveLogProgress(DeviceLayer, "OpenThread Full Topology event: %u\n", eventId);

    // TODO:
    // TopoFullLogEntries(eventId, entryTable, topologyEvent.neighborTableSize);
    LogThreadTopologyEntries(eventId, neighborInfo, topologyEvent.neighborTableSize);

    Impl()->UnlockThreadStack();

exit:
    if (err != WEAVE_NO_ERROR)
    {
        WeaveLogError(DeviceLayer, "GetAndLogThreadTopologyFull failed: %s", nl::ErrorStr(err));
    }
    return err;
}

#if 1

#define TELEM_PRINT_BUFFER_SIZE (64)

static WEAVE_ERROR LogThreadTopologyEntries(nl::Weave::Profiles::DataManagement_Current::event_id_t parentEventId,
                                            otNeighborInfo *neighborInfoTable, uint32_t neighborInfoTableSize)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    nl::Weave::Profiles::DataManagement_Current::EventOptions opts(true);
    nl::Weave::Profiles::DataManagement_Current::event_id_t eventId;
    TelemetryNetworkWpanTrait::TopoEntryEvent topologyEntryEvent = { 0 };
    char printBuf[TELEM_PRINT_BUFFER_SIZE];

    VerifyOrExit(neighborInfoTable != NULL, err = WEAVE_ERROR_INVALID_ARGUMENT);

    // Populate the event options so that the topo entries are linked to the
    // actual topo full event.
    opts.relatedEventID = parentEventId;
    opts.relatedImportance = TelemetryNetworkWpanTrait::NetworkWpanTopoFullEvent::Schema.mImportance;

    // Handle each event seperatly, this way we only need one TopoEntryEvent object, rather then
    // creating n of them on the stack.
    for (uint32_t i = 0; i < neighborInfoTableSize; i++)
    {
//        thci_neighbor_child_info_t * entry   = &aEntryTable[i];
        otNeighborInfo * neighbor            = &neighborInfoTable[i];

        topologyEntryEvent.extAddress.mBuf   = neighbor->mExtAddress.m8;
        topologyEntryEvent.extAddress.mLen   = sizeof(uint64_t);

        topologyEntryEvent.rloc16            = neighbor->mRloc16;
        topologyEntryEvent.linkQualityIn     = neighbor->mLinkQualityIn;
        topologyEntryEvent.averageRssi       = neighbor->mAverageRssi;
        topologyEntryEvent.age               = neighbor->mAge;
        topologyEntryEvent.rxOnWhenIdle      = neighbor->mRxOnWhenIdle;
//        topologyEntryEvent.fullFunction      = neighbor->mFullThreadDevice;
        topologyEntryEvent.fullFunction      = true;
        topologyEntryEvent.secureDataRequest = neighbor->mSecureDataRequest;
        topologyEntryEvent.fullNetworkData   = neighbor->mFullNetworkData;
        topologyEntryEvent.lastRssi          = neighbor->mLastRssi;
        topologyEntryEvent.linkFrameCounter  = neighbor->mLinkFrameCounter;
        topologyEntryEvent.mleFrameCounter   = neighbor->mMleFrameCounter;
        topologyEntryEvent.isChild           = neighbor->mIsChild;

        if (topologyEntryEvent.isChild)
        {
//            topologyEntryEvent.timeout            = entry->mTimeout;
//            topologyEntryEvent.networkDataVersion = entry->mNetworkDataVersion;

            topologyEntryEvent.SetTimeoutPresent();
            topologyEntryEvent.SetNetworkDataVersionPresent();
        }
        else
        {
            topologyEntryEvent.SetTimeoutNull();
            topologyEntryEvent.SetNetworkDataVersionNull();
        }

        eventId = nl::LogEvent(&topologyEntryEvent, opts);
        WeaveLogProgress(DeviceLayer, "TopoEntry[%u] Event ID: %ld\n", i, eventId);

        if (topologyEntryEvent.isChild)
        {
//            snprintf(printBuf, TELEM_PRINT_BUFFER_SIZE, ", Timeout: %10lu NetworkDataVersion: %3d", entry->mTimeout,
//                     entry->mNetworkDataVersion);
        }
        else
        {
            printBuf[0] = 0;
        }

        // These logs are used in log parsing to obtain children and neighbors where commandline
        // is not available. If you change these log lines, update the regex in pyrite in the file below
        // https://stash.nestlabs.com/projects/PLATFORM/repos/pyrite/browse/pyrite/antigua/messaging/ncp_neighbor_parser.py
        // These logs should match the logs from the nlnetworktools:
        // https://stash.nestlabs.com/projects/PLATFORM/repos/nlnetworktools/browse/src/nlnetworktelemetry-wpan-topology.cpp
        WeaveLogProgress(DeviceLayer,
                         "TopoEntry [%u] %02X%02X:%02X%02X:%02X%02X:%02X%02X RLOC: %04X, Age: %3d, "
                         "LQI: %1d, AvgRSSI: %3d, LastRSSI: %3d, LinkFrameCounter: %10d, MleFrameCounter: %10d, "
                         "RxOnWhenIdle: %c, SecureDataRequest: %c, FullFunction: %c, FullNetworkData: %c, "
                         "IsChild: %c%s\n",
                         i, neighbor->mExtAddress.m8[0], neighbor->mExtAddress.m8[1], neighbor->mExtAddress.m8[2],
                         neighbor->mExtAddress.m8[3], neighbor->mExtAddress.m8[4], neighbor->mExtAddress.m8[5],
                         neighbor->mExtAddress.m8[6], neighbor->mExtAddress.m8[7], neighbor->mRloc16, neighbor->mAge,
                         neighbor->mLinkQualityIn, neighbor->mAverageRssi, neighbor->mLastRssi, neighbor->mLinkFrameCounter,
                         neighbor->mMleFrameCounter, neighbor->mRxOnWhenIdle ? 'Y' : 'n', neighbor->mSecureDataRequest ? 'Y' : 'n',
//                         neighbor->mFullThreadDevice ? 'Y' : 'n', neighbor->mFullNetworkData ? 'Y' : 'n',
                         'Y', neighbor->mFullNetworkData ? 'Y' : 'n',
                         neighbor->mIsChild ? 'Y' : 'n',
                         printBuf);
    }

exit:
    return err;
}
#endif

template<class ImplClass>
WEAVE_ERROR GenericThreadStackManagerImpl_OpenThread<ImplClass>::DoInit(otInstance * otInst)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    otError otErr;

    // Arrange for OpenThread errors to be translated to text.
    RegisterOpenThreadErrorFormatter();

    mOTInst = NULL;

    // If an OpenThread instance hasn't been supplied, call otInstanceInitSingle() to
    // create or acquire a singleton instance of OpenThread.
    if (otInst == NULL)
    {
        otInst = otInstanceInitSingle();
        VerifyOrExit(otInst != NULL, err = MapOpenThreadError(OT_ERROR_FAILED));
    }

    mOTInst = otInst;

    // Arrange for OpenThread to call the OnOpenThreadStateChange method whenever a
    // state change occurs.  Note that we reference the OnOpenThreadStateChange method
    // on the concrete implementation class so that that class can override the default
    // method implementation if it chooses to.
    otErr = otSetStateChangedCallback(otInst, ImplClass::OnOpenThreadStateChange, NULL);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    // TODO: generalize this
    {
        otLinkModeConfig linkMode;

        memset(&linkMode, 0, sizeof(linkMode));
        linkMode.mRxOnWhenIdle       = true;
        linkMode.mSecureDataRequests = true;
        linkMode.mDeviceType         = true;
        linkMode.mNetworkData        = true;

        otErr = otThreadSetLinkMode(otInst, linkMode);
        VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));
    }

    // TODO: not supported in old version of OpenThread used by Nordic SDK.
    // otIp6SetSlaacEnabled(otInst, false);

    otErr = otIp6SetEnabled(otInst, true);
    VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));

    if (otThreadGetDeviceRole(mOTInst) == OT_DEVICE_ROLE_DISABLED && otDatasetIsCommissioned(otInst))
    {
        otErr = otThreadSetEnabled(otInst, true);
        VerifyOrExit(otErr == OT_ERROR_NONE, err = MapOpenThreadError(otErr));
    }

exit:
    return err;
}

template<class ImplClass>
bool GenericThreadStackManagerImpl_OpenThread<ImplClass>::IsThreadAttachedNoLock(void)
{
    otDeviceRole curRole = otThreadGetDeviceRole(mOTInst);
    return (curRole != OT_DEVICE_ROLE_DISABLED && curRole != OT_DEVICE_ROLE_DETACHED);
}


} // namespace Internal
} // namespace DeviceLayer
} // namespace Weave
} // namespace nl


#endif // GENERIC_THREAD_STACK_MANAGER_IMPL_OPENTHREAD_IPP
