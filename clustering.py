import datetime
import sys
import pyshark
import logging
import json
import pandas as pd
from scipy import spatial
from sklearn.cluster import DBSCAN

LAYERS = 4
FIELDS_NAME = ["wlan.extcap", "wlan.ht", "wlan.vht"]
POWER_THRESHOLD = -70
DEFAULT = 1

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    start_time = datetime.datetime.now().timestamp()
    file = sys.argv[1]

    # Read the device-model database
    with open("devices.json", "r") as fr:
        hash_dict = json.load(fr)

    rates_dict = {hash_dict[k]["id"]: (hash_dict[k]["cap_id"], hash_dict[k]["mean_rate"]) for k in hash_dict.keys()}

    logger.info("Reading pcap file")
    capture = pyshark.FileCapture(file)

    flat_time = datetime.datetime.timestamp(capture[0].sniff_time)

    TIME_WINDOW = 0
    MAX_RATIO = 0
    pkt_counter = 0
    global_set = set()
    global_counter = 0
    # time_list = list()
    values_list = list()
    df = pd.DataFrame([])
    cluster_counter = 0

    logger.info("Parsing packets")
    for pkt in capture:
        # Check if the signal power is sufficient
        if int(pkt.layers[1]._all_fields.get("wlan_radio.signal_dbm")) <= POWER_THRESHOLD:
            continue
        pkt_counter += 1
        vht_cap = 0
        ext_cap = 0
        ht_cap = 0
        time = datetime.datetime.timestamp(pkt.sniff_time) - flat_time
        TIME_WINDOW = time
        src_mac = pkt.layers[2]._all_fields.get("wlan.ta")
        first_octet = int(float.fromhex(src_mac.split(":")[0][1]))
        # Check the nature of MAC address
        if (first_octet & 2) == 0:
            # Globally unique
            global_set.add(src_mac)
            global_counter += 1
            continue
        for i in range(LAYERS):
            layer = pkt.layers[i]
            keys = list(filter(lambda t: any([f for f in FIELDS_NAME if f in t]), layer._all_fields.keys()))
            # Collect the values for VHT, Extended and HT capabilities
            for k in keys:
                value = str(layer._all_fields.get(k))
                if not any([i for i in ["Rx", "VHT"] if i in value]):
                    value = int(float.fromhex(value))
                    if "wlan.vht" in k:
                        vht_cap += value
                    elif "wlan.extcap" in k:
                        ext_cap += value
                    elif "wlan.ht" in k:
                        ht_cap += value
        values = [vht_cap, ext_cap, ht_cap]
        new_df = pd.DataFrame({"vht_cap": [values[0]], "ext_cap": [values[1]], "ht_cap": [values[2]]})
        df = pd.concat(
            [df, new_df],
            ignore_index=True
        )
        values_list.append(values)

    MAX_RATIO = round(pkt_counter / TIME_WINDOW)

    # Count the global MAC addresses
    total_devices = len(global_set)

    # Check that at least the 2% of packets have a locally administered MAC address
    if (pkt_counter - global_counter) > 0.02*pkt_counter:
        logger.info("Model clustering")
        # Perform DBSCAN
        dbscan = DBSCAN(eps=4.0, min_samples=15, metric="euclidean")
        cluster_labels = list(dbscan.fit(df).labels_)

        cluster_tmp = list()
        # time_tmp = list()
        values_tmp = list()
        # Filter the noise group
        for i, x in enumerate(cluster_labels):
            if x != -1:
                cluster_tmp.append(x)
                # time_tmp.append(time_list[i])
                values_tmp.append(values_list[i])

        cluster_labels = cluster_tmp
        # time_list = time_tmp
        values_list = values_tmp
        # time_min_max = {cl: [-1, -1] for cl in set(cluster_labels)}
        cluster_values = {cl: [] for cl in set(cluster_labels)}

        # logger.info("Collecting times")
        # # Collect the time windows for each cluster
        # for i, time in enumerate(time_list):
        #     cluster = cluster_labels[i]
        #     if time_min_max[cluster][0] == -1:
        #         time_min_max[cluster][0] = time
        #     time_min_max[cluster][1] = time
        #     cluster_values[cluster].append(values_list[i])

        for i, val in enumerate(values_list):
            cluster = cluster_labels[i]
            cluster_values[cluster].append(val)

        # Perform the average of the VHT, Extended and HT capabilities inside clusters
        for key, value in cluster_values.items():
            cluster_values[key] = [sum(sub_list) / len(sub_list) for sub_list in zip(*value)]

        logger.info("Counting devices")
        device_numbers = dict()
        for key in cluster_values.keys():
            # Choose the closest device with similar characteristics
            closest_group = min(rates_dict.keys(), key=lambda k: spatial.distance.euclidean(rates_dict[k][0], cluster_values[key]))
            closest_rate = rates_dict[closest_group][1]
            # Number of packets inside the cluster
            N = len(list(filter(lambda k: k == key, cluster_labels)))
            # Capture time window
            T = TIME_WINDOW
            L = closest_rate
            # Check if the ratio is acceptable to do the standard count, otherwise use a default value
            if N / T < MAX_RATIO:
                K = N / (L * T)
                K = round(K)
                device_numbers[key] = K if K > 0 else 1
            else:
                device_numbers[key] = DEFAULT

        total_devices += sum(device_numbers.values())

    logger.info(f"Device detected: {total_devices}")
    end_time = datetime.datetime.now().timestamp()

    logger.info(f"End counting, total time: {round(end_time - start_time, 2)} seconds")
