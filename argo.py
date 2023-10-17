import datetime
import sys
import argparse
import pyshark
import logging
import json
import pandas as pd
from scipy import spatial
from sklearn.cluster import DBSCAN

LAYERS = 4
FIELDS_NAME = ["wlan.extcap", "wlan.ht", "wlan.vht"]

if __name__ == "__main__":

    start_time = datetime.datetime.now().timestamp()

    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", type=str, default="./input.pcap", help="Path for the .pcap trace.")
    parser.add_argument("--max_ratio", type=int, default=100, help="Maximum Ratio for clustering algorithm.")
    parser.add_argument("--power_threshold", type=int, default=-70, help="Threshold for the capturing power.")
    parser.add_argument("--default_counter", type=int, default=1, help="Default number assigned to a cluster if the condition on the Maximum Ratio is not respected.")
    parser.add_argument("--min_percentage", type=float, default=0.02, help="Minimum percentage of probe request that must have locally administered MAC address for doing clustering.")
    parser.add_argument("--epsilon", type=int, default=4, help="Epsilon parameter for DBSCAN clustering.")
    parser.add_argument("--min_samples", type=int, default=15, help="Min samples parameter for DBSCAN clustering.")
    parser.add_argument("--dbscan_metric", type=str, default="euclidean", help="Metric parameter for DBSCAN clustering.")
    parser.add_argument("--rate_modality", type=str, default="mean_rate", choices=["locked_rate", "awake_rate", "active_rate", "mean_rate"], help="Choose the rate to get from the database. The possibilities are: locked_rate, awake_rate, active_rate or mean_rate.")
    opt = vars(parser.parse_args())

    file = opt["input_file"]
    max_ratio = opt["max_ratio"]
    power_threshold = opt["power_threshold"]
    default_counter = opt["default_counter"]
    min_percentage = opt["min_percentage"]
    epsilon = opt["epsilon"]
    min_samples = opt["min_samples"]
    dbscan_metric = opt["dbscan_metric"]
    rate_modality = opt["rate_modality"]

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    # Read the device-model database
    with open("devices.json", "r") as fr:
        hash_dict = json.load(fr)

    rates_dict = {hash_dict[k]["id"]: (hash_dict[k]["cap_id"], hash_dict[k][rate_modality]) for k in hash_dict.keys()}

    logger.info("Reading pcap file")
    capture = pyshark.FileCapture(file)

    flat_time = datetime.datetime.timestamp(capture[0].sniff_time)
    TIME_WINDOW = 0
    pkt_counter = 0
    global_set = set()
    global_counter = 0
    values_list = list()
    df = pd.DataFrame([])
    cluster_counter = 0

    logger.info("Parsing packets")
    for pkt in capture:
        # Check if the signal power is sufficient
        if int(pkt.layers[1]._all_fields.get("wlan_radio.signal_dbm")) <= power_threshold:
            continue
        pkt_counter += 1
        vht_cap = 0
        ext_cap = 0
        ht_cap = 0
        TIME_WINDOW = datetime.datetime.timestamp(pkt.sniff_time) - flat_time
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

    # Count the global MAC addresses
    set_devices = len(global_set)
    cluster_devices = 0

    # Check that at least the 2% of packets have a locally administered MAC address
    if (pkt_counter - global_counter) > min_percentage*pkt_counter:
        logger.info("Model clustering")
        # Perform DBSCAN
        dbscan = DBSCAN(eps=epsilon, min_samples=min_samples, metric=dbscan_metric)
        cluster_labels = list(dbscan.fit(df).labels_)
        cluster_tmp = list()
        values_tmp = list()
        # Filter the noise group
        for i, x in enumerate(cluster_labels):
            if x != -1:
                cluster_tmp.append(x)
                values_tmp.append(values_list[i])

        cluster_labels = cluster_tmp
        values_list = values_tmp
        cluster_values = {cl: [] for cl in set(cluster_labels)}

        for i, val in enumerate(values_list):
            cluster = cluster_labels[i]
            cluster_values[cluster].append(val)

        # Perform the average of the VHT, Extended and HT capabilities inside clusters
        for key, value in cluster_values.items():
            cluster_values[key] = [sum(sub_list) / len(sub_list) for sub_list in zip(*value)]

        logger.info("Counting devices")
        device_numbers = dict()
        cluster_devices = 0
        for key in cluster_values.keys():
            # Choose the closest device with similar characteristics
            min_dist = rates_dict[
                min(rates_dict.keys(), key=lambda k: spatial.distance.euclidean(rates_dict[k][0], cluster_values[key]))
                ][0]
            closest_rates = [rates_dict[k][1] for k in rates_dict.keys() if min_dist == rates_dict[k][0]]
            L = sum(closest_rates)/len(closest_rates)
            # Number of packets inside the cluster
            N = len(list(filter(lambda k: k == key, cluster_labels)))
            # Capture time window
            T = TIME_WINDOW
            if N / T < max_ratio:
                K = N / (L * T)
                K = round(K)
                device_numbers[key] = K if K > 0 else 1
            else:
                device_numbers[key] = default_counter

        cluster_devices +=  sum(device_numbers.values())

    logging.info(f"Devices that use globally unique MAC addresses: {set_devices}")
    logging.info(f"Devices that use locally administered MAC addresses: {cluster_devices}")
    total_devices = set_devices + cluster_devices
    logger.info(f"Total device detected: {total_devices}")
    end_time = datetime.datetime.now().timestamp()

    logger.info(f"End counting, total time: {round(end_time - start_time, 2)} seconds")
