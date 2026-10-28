"""Prepare private telemetry queues; never emit the caller's private config."""

from copy import deepcopy


def prepare_telemetry_profile(stock, *, lab_clone=False):
    if type(lab_clone) is not bool:
        raise ValueError("invalid telemetry profile mode")
    result = deepcopy(stock)
    try:
        if result["patterns"]["TMP"] != "/tmp" or result["patterns"]["DATA"] != "/data/quasar":
            raise ValueError("unreviewed telemetry filesystem layout")
        telemetry = result["teleme3d"]
        if telemetry["dbPath"] != "${TMP}/teleme3d":
            raise ValueError("stock telemetry queue changed")
        if telemetry["metricaSessionIdPersistentPart"] != "${DATA}/data/metrica/session_id_part.txt":
            raise ValueError("stock persistent session identity changed")
        if telemetry["metricaSessionIdTemporaryPart"] != "${TMP}/metrica/session_id_part.txt":
            raise ValueError("stock temporary session identity changed")
        size, reserve = telemetry["dbSizeLimitMB"], telemetry["reservedSizeMB"]
        if type(size) is not int or type(reserve) is not int or not 0 <= reserve < size <= 12:
            raise ValueError("unreviewed telemetry storage limits")
        batch = telemetry["persistentBatcher"]
        if batch["storagePath"] != "${DATA}/appmetrica/persistedBatch" or batch["enabled"] is not True:
            raise ValueError("stock batch storage changed")
        if type(batch["maxStorageSizeMb"]) is not int or not 1 <= batch["maxStorageSizeMb"] <= 4:
            raise ValueError("unreviewed batch storage limit")
        for key in ("syncPeriodSec", "maxBatchCollectingWhenNoInternetTimeSec"):
            if type(batch[key]) is not int or not 1 <= batch[key] <= 86400:
                raise ValueError("invalid telemetry batching interval")
        if type(batch["lookForNetworkConnection"]) is not bool or type(telemetry["noSyncClock"]) is not bool:
            raise ValueError("invalid telemetry clock/network policy")
        persistent = telemetry["persistentAppmetrica"]
        if not isinstance(telemetry["eventBlacklist"], list) or any(
            type(name) is not str for name in telemetry["eventBlacklist"]
        ):
            raise ValueError("invalid global telemetry filter")
        if persistent["mode"] not in {"white", "black"} or not isinstance(persistent["events"], dict):
            raise ValueError("unreviewed persistent event policy")
        if any(
            type(name) is not str or type(value) is not bool for name, value in persistent["events"].items()
        ):
            raise ValueError("invalid persistent event filter")
        service = result["telemetry"]
        if (
            service["Logging"]["file"]["fileName"] != "${LOGS}/telemetry.log"
            or service["Logging"]["file"]["enabled"] is not True
        ):
            raise ValueError("stock telemetry logging changed")
        if type(service["Minidump"]["enabled"]) is not bool:
            raise ValueError("invalid telemetry dump setting")
        for name in ("metricad", "metrica2d"):
            port = result[name]["port"]
            if type(port) is not int or not 1024 <= port <= 65535:
                raise ValueError("invalid telemetry IPC port")
            if lab_clone and port != {"metricad": 9887, "metrica2d": 9904}[name]:
                raise ValueError("unreviewed stock telemetry IPC port")
        telemetry["dbPath"] = "/tmp/lisa-telemetry/lmdb"
        telemetry["metricaSessionIdPersistentPart"] = "/tmp/lisa-telemetry/session-persistent"
        telemetry["metricaSessionIdTemporaryPart"] = "/tmp/lisa-telemetry/session-temporary"
        batch["storagePath"] = "/tmp/lisa-telemetry/persistedBatch"
        service["Logging"]["file"]["fileName"] = "/tmp/lisa-telemetry/telemetry.log"
        service["Minidump"]["enabled"] = False
        if lab_clone:
            result["metricad"]["port"], result["metrica2d"]["port"] = 57345, 57346
            batch["syncPeriodSec"] = batch["maxBatchCollectingWhenNoInternetTimeSec"] = 1
            batch["maxBatchCollectingTimeSec"] = 1
            batch["lookForNetworkConnection"] = False
            telemetry["noSyncClock"] = True
            # Accept the isolated SDK's startup diagnostics into its persistent
            # sink for the offline-storage trial. Production keeps stock filters.
            persistent["mode"], persistent["events"] = "black", {}
            # The SDK's one-shot processStart can expire before its private IPC
            # receiver starts. Admit its periodic self-metrics in this bounded
            # clone instead; stock filters remain unchanged outside the lab.
            telemetry["eventBlacklist"] = [
                name for name in telemetry["eventBlacklist"] if name != "systemMetrics"
            ]
    except (KeyError, TypeError) as error:
        raise ValueError("unsupported stock telemetry configuration") from error
    return result
