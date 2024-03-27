import datetime
import argparse
import re
from scapy.all import rdpcap
import logging
import json
import pandas as pd
from collections import defaultdict
from scipy import spatial
from sklearn.cluster import OPTICS
from statistics import mean
from bloomfilter_operations import *


def bloom_filter_insertion(main_bf, cluster_mac):
    # Insert the MAC address averages inside the Bloom Filter
    list_macs_mean = [mean([int(elem.replace(":", ""), 16) for elem in cluster_mac[k]]) for k in cluster_mac.keys()]

    # Fill the Bloom Filter
    for elem in list_macs_mean:
        # Insert the mean value but cast as string because mmh3 hash functions wants a bytes object
        main_bf.add(str(elem))


def process_input_string(input_string):
    # Replacement of "\\" followed by one of more chars with a space
    input_string = input_string.strip("'")
    result = input_string.replace(r'\n', r'\\x0a')
    result = result.replace("\\", ' ')
    # Replacement of "\n" with "\\x0a"
    output_string = result
    output_blocks = output_string.split()
    for n, block in enumerate(output_blocks):
        if block[0] != 'x':
            ascii_char = ord(block[0])
            hex_val = hex(ascii_char)
            hex_val = hex_val.replace('0x', '')
            block = hex_val + block[1:]  # Replace only the first char
        else:
            block = block[1:]
        if block[2:]:
            start = block[0:2]
            for char in block[2:]:
                ascii_char = ord(char)
                hex_val = hex(ascii_char)
                hex_val = hex_val.replace('0x', ' ')
                block = start + hex_val
        output_blocks[n] = block

    unique_string = ' '.join(output_blocks)
    unique_string.replace('x', ' ')
    hex_pairs = unique_string.split()
    decimal_sum = sum(int(number, 16) for number in hex_pairs)
    return decimal_sum


def process_ex_cap(input_string):
    # Replacement of "\\" followed by one of more chars with a space
    input_string = input_string.strip("'")
    result = input_string.replace(r'\n', r'\\x0a')
    result = result.replace("\\", ' ')
    # Replacement of "\n" with "\\x0a"
    output_string = result
    output_blocks = output_string.split()
    for n, block in enumerate(output_blocks):
        if block[0] != 'x':
            ascii_char = ord(block[0])
            hex_val = hex(ascii_char)
            hex_val = hex_val.replace('0x', '')
            block = hex_val + block[1:]  # Replace only the first char
        else:
            block = block[1:]
        if block[2:]:
            start = block[0:2]
            for char in block[2:]:
                ascii_char = ord(char)
                hex_val = hex(ascii_char)
                hex_val = hex_val.replace('0x', ' ')
                block = start + hex_val
        output_blocks[n] = block

    unique_string = ' '.join(output_blocks)
    unique_string.replace('x', ' ')
    hex_pairs = unique_string.split()
    binary_strings = []
    for hex_pair in hex_pairs:
        # Convert the hex couple in binary form and join it with the binary strings list
        binary_str = bin(int(hex_pair, 16))[2:].zfill(8)  # Replace the binary with a series of 0s at the beginning
        binary_strings.append(binary_str)

    total_ones = 0
    for binary_str in binary_strings:
        total_ones += binary_str.count('1')

    return total_ones


def calculate_combined_sum(dictionary):
    total_sum = 0
    for value in dictionary.values():
        if value.isdigit():
            total_sum += int(value)
    return total_sum


def process_oui(testo, info):
    # Find te part within the parenthesis with a regular expression
    match = re.search(r'\((.*?)\)', testo)
    if match:
        hex_string = match.group(1).replace(':', ' ')
        hex_pairs = hex_string.split()
        return sum(int(number, 16) for number in hex_pairs) + process_input_string(info)
    else:
        hex_string = testo.replace(':', ' ')
        hex_pairs = hex_string.split()
        return sum(int(number, 16) for number in hex_pairs) + process_input_string(info)


if __name__ == "__main__":

    start_time = datetime.datetime.now().timestamp()

    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", type=str, default="./input.pcap", help="Path for the .pcap trace.")
    parser.add_argument("--max_ratio", type=int, default=100, help="Maximum Ratio for clustering algorithm.")
    parser.add_argument("--power_threshold", type=int, default=-70, help="Threshold for the capturing power.")
    parser.add_argument("--default_counter", type=int, default=1,
                        help="Default number assigned to a cluster if the condition on the Maximum Ratio is not respected.")
    parser.add_argument("--min_percentage", type=float, default=0.02,
                        help="Minimum percentage of probe request that must have locally administered MAC address for doing clustering.")
    parser.add_argument("--epsilon", type=int, default=0.001, help="Epsilon parameter for DBSCAN clustering.")
    parser.add_argument("--min_samples", type=int, default=15, help="Min samples parameter for clustering.")
    parser.add_argument("--distance_metric", type=str, default="euclidean",
                        help="Metric parameter for clustering.")
    parser.add_argument("--rate_modality", type=str, default="mean_rate",
                        choices=["locked_rate", "awake_rate", "active_rate", "mean_rate"],
                        help="Choose the rate to get from the database. The possibilities are: locked_rate, awake_rate, active_rate or mean_rate.")
    parser.add_argument("--cluster_method", type=str, choices=["dbscan", "optics"], default="optics",
                        help="Clustering method, the possible choices are dbscan and optics.")
    parser.add_argument("--counting_method", type=str, choices=["simple", "advanced"], default="simple",
                        help="Counting method when a cluster is examined, the possible choices are simple and advanced.")
    opt = vars(parser.parse_args())

    file = opt["input_file"]
    max_ratio = opt["max_ratio"]
    power_threshold = opt["power_threshold"]
    default_counter = opt["default_counter"]
    min_percentage = opt["min_percentage"]
    epsilon = opt["epsilon"]
    min_samples = opt["min_samples"]
    distance_metric = opt["distance_metric"]
    rate_modality = opt["rate_modality"]
    cluster_method = opt["cluster_method"]
    counting_method = opt["counting_method"]

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    # Read the device-model database
    with open("./models.json", "r") as fr:
        hash_dict = json.load(fr)

    rates_dict = {hash_dict[k]["id"]: (hash_dict[k]["cap_id"], hash_dict[k][rate_modality]) for k in hash_dict.keys()}

    logger.info("Creating Bloom Filter structure")
    # BF Creation
    main_bf = BloomFilter(10000, 7)
    # Anonymization Noise
    main_bf.anonymization_noise(30)

    logger.info("Reading pcap file")
    capture = rdpcap(file)

    flat_time = float(capture[0].time)
    TIME_WINDOW = 0
    pkt_counter = 0
    values_list = list()
    local_mac_list = list()
    global_mac_list = list()
    global_values_dict = dict()
    df = pd.DataFrame([])
    global_counter = 0
    cluster_counter = 0

    logger.info("Parsing packets")
    quadruplets = {}
    count = {}
    for i, packet in enumerate(capture):

        src = packet.addr2
        quadruplets[i] = [-1, -1, -1, -1]
        if packet.dBm_AntSignal <= power_threshold:
            continue

        pkt_counter += 1
        TIME_WINDOW = float(packet.time) - flat_time
        probe_req = packet.getlayer("Dot11ProbeReq")
        if probe_req:
            first_octet = int(float.fromhex(src.split(":")[0][1]))
            # Check the nature of MAC address
            if (first_octet & 2) == 0:
                # Globally unique
                if not main_bf.check(src):
                    main_bf.add(src)
                if src not in global_mac_list:
                    global_counter += 1
                    global_mac_list.append(src)
                continue
            packet_dict = {}
            counter = {}
            layer = None
            for line in packet.show2(dump=True).split('\n'):
                if '###' in line:
                    layer = line.strip('#[] ')
                    if layer == 'RadioTap' or layer == '|###[ RadioTap Extended presence mask':
                        pass
                    else:
                        if layer not in packet_dict.keys():
                            counter[layer] = 0
                        else:
                            count = counter[layer] + 1
                            counter[layer] += 1
                            layer = layer + str(count)
                        packet_dict[layer] = {}
                elif '=' in line:
                    if layer == 'RadioTap' or layer == '|###[ RadioTap Extended presence mask':
                        pass
                    else:
                        key, val = line.split('=', 1)
                        packet_dict[layer][key.strip()] = val.strip()

            for entry in packet_dict.keys():
                if 'ID' in packet_dict[entry]:
                    src = packet.addr2
                    if packet_dict[entry]['ID'] == 'VHT Capabilities':
                        try:
                            quadruplets[i][0] = process_input_string(packet_dict[entry]['info'])
                        except Exception as e:
                            pass
                    elif packet_dict[entry]['ID'] == 'Extendend Capabilities':
                        try:
                            quadruplets[i][1] = process_input_string(packet_dict[entry]['info'])
                        except Exception as e:
                            pass
                    elif packet_dict[entry]['ID'] == 'HT Capabilities':
                        try:
                            quadruplets[i][2] = calculate_combined_sum(packet_dict[entry])
                        except Exception as e:
                            pass
                    elif packet_dict[entry]['ID'] == 'Vendor Specific':
                        if 'oui' in packet_dict[entry].keys():
                            quadruplets[i][3] += process_oui(packet_dict[entry]['oui'], packet_dict[entry]['info'])
                        else:
                            quadruplets[i][3] += process_input_string(packet_dict[entry]['info'])

            new_df = pd.DataFrame(
                {"vht_cap": [quadruplets[i][0]], "ext_cap": [quadruplets[i][1]], "ht_cap": [quadruplets[i][2]], "vendor": [quadruplets[i][3]]})
            df = pd.concat(
                [df, new_df],
                ignore_index=True
            )
            values_list.append(quadruplets[i])
            local_mac_list.append(src)

    cluster_devices = 0

    # Check that at least the 2% of packets have a locally administered MAC address
    if (pkt_counter - global_counter) > min_percentage * pkt_counter:
        logger.info("Model clustering")
        # Perform the clustering
        if cluster_method == "optics":
            clustering = OPTICS(min_samples=min_samples, metric=distance_metric)
        else:
            clustering = OPTICS(eps=epsilon, min_samples=min_samples, metric=distance_metric, cluster_method="dbscan")
        cluster_labels = list(clustering.fit(df).labels_)
        cluster_tmp = list()
        values_tmp = list()
        cluster_mac = defaultdict(list)
        # Filter the noise group
        for i, x in enumerate(cluster_labels):
            if x != -1:
                cluster_mac[x].append(local_mac_list[i])
                cluster_tmp.append(x)
                values_tmp.append(values_list[i])

        bloom_filter_insertion(main_bf, cluster_mac)
        # Generate a dictionary to store all the single MAC addresses associated with a certain device model
        cluster_mac_set = {k: set(v) for k, v in cluster_mac.items()}

        cluster_labels = cluster_tmp
        values_list = values_tmp
        cluster_values = {cl: [] for cl in set(cluster_labels)}

        for i, val in enumerate(values_list):
            cluster = cluster_labels[i]
            cluster_values[cluster].append(val)

        # Perform the average of the IEs inside clusters
        cluster_values = {
            key: [sum(sub_list) / len(sub_list) for sub_list in zip(*value)] for key, value in cluster_values.items()
        }

        logger.info("Counting devices")
        device_numbers = dict()
        cluster_devices = 0
        if counting_method == "advanced":
            for key in cluster_values.keys():
                # Choose the closest device with similar characteristics
                min_dist = rates_dict[
                    min(rates_dict.keys(),
                        key=lambda k: spatial.distance.euclidean(rates_dict[k][0], cluster_values[key]))
                ][0]
                closest_rates = [rates_dict[k][1] for k in rates_dict.keys() if min_dist == rates_dict[k][0]]
                # If multiple matches are found, take the average rate
                L = sum(closest_rates) / len(closest_rates)
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

                if device_numbers[key] > len(cluster_mac_set[key]):
                    device_numbers[key] = len(cluster_mac_set[key])
            cluster_devices += sum(device_numbers.values())
        elif counting_method == "simple":
            cluster_devices = len(set(cluster_values.keys()))

        logger.info("Associating global MAC addresses with a cluster")
        for k1 in global_values_dict.keys():
            distances = list()
            for k2 in cluster_values.keys():
                tmp = spatial.distance.euclidean(global_values_dict[k1], cluster_values[k2])
                distances.append((k2, tmp))
            min_k = min(distances, key=lambda x: x[1])
            # Add the global MAC address k1 to a cluster
            cluster_mac_set[min_k[0]].add(k1)

    logging.info(f"Devices that use globally unique MAC addresses: {global_counter}")
    logging.info(f"Devices that use locally administered MAC addresses: {cluster_devices}")
    total_devices = global_counter + cluster_devices
    logger.info(f"Total device detected: {total_devices}")

    end_time = datetime.datetime.now().timestamp()

    logger.info(f"End counting, total time: {round(end_time - start_time, 2)} seconds")
