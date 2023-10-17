# ARGO - Wireless Device Counting and Clustering

This Python script is designed to analyze wireless network traffic captured in a PCAP file and count devices that use either globally unique MAC addresses or locally administered MAC addresses. It also performs clustering of devices based on their network capabilities.

## Files

- `ARGO.py`: The main Python script responsible for device counting and clustering based on network traffic in a PCAP file.
- `models.json`: A JSON file that serves as a device-model database, containing information about different devices and their capabilities.

## Dependencies

- `datetime`: For time-related functions.
- `sys`: Provides access to some variables used or maintained by the interpreter.
- `argparse`: Allows command-line argument parsing.
- `pyshark`: A Python wrapper for the Wireshark packet analyzer.
- `logging`: Used for logging information and errors.
- `json`: For reading a device-model database in JSON format.
- `pandas`: Provides data structures for efficient data manipulation.
- `scipy.spatial`: For calculating distances between data points.
- `sklearn.cluster.DBSCAN`: Implements the DBSCAN clustering algorithm.

## Constants and Configuration

- `LAYERS`: The number of protocol layers to analyze in each packet.
- `FIELDS_NAME`: A list of field names to be extracted from packet layers.

## Command Line Arguments

The script accepts the following command-line arguments:

- `--input_file`: Path to the PCAP trace file.
- `--max_ratio`: Maximum Ratio for clustering algorithm.
- `--power_threshold`: Threshold for the capturing power.
- `--default_counter`: Default number assigned to a cluster if the Maximum Ratio condition is not met.
- `--min_percentage`: Minimum percentage of probe requests with locally administered MAC addresses for clustering.
- `--epsilon`: Epsilon parameter for DBSCAN clustering.
- `--min_samples`: Min samples parameter for DBSCAN clustering.
- `--dbscan_metric`: Metric parameter for DBSCAN clustering.
- `--rate_modality`: Choose the rate to extract from the database.

## Code Execution

1. The script starts by parsing the command-line arguments.
2. It reads a device-model database from a JSON file named "devices.json."
3. It initializes variables for counting and clustering devices.
4. The script reads and processes packets from the PCAP file.
5. It checks the signal power of each packet and discards packets with power below the threshold.
6. The script extracts relevant fields from each packet, including MAC addresses, capabilities, and other information.
7. It categorizes MAC addresses as globally unique or locally administered.
8. The script collects information about VHT, Extended, and HT capabilities for clustering.
9. It counts devices with globally unique MAC addresses and checks if the minimum percentage condition for clustering is met.
10. If clustering is performed, it uses DBSCAN to cluster devices based on their capabilities.
11. The script calculates the average capabilities within each cluster.
12. It estimates the number of devices within each cluster and counts them.
13. Finally, the script logs information about the number of devices detected.

## Output

The script generates log information about the devices using globally unique MAC addresses, devices using locally administered MAC addresses, and the total number of detected devices.

## Usage

Example usage:

```shell
python ARGO.py --input_file ./example.pcap --max_ratio 100 --power_threshold -70 --default_counter 1 --min_percentage 0.02 --epsilon 4 --min_samples 15 --dbscan_metric euclidean --rate_modality mean_rate
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. The MIT License is a permissive open-source license that allows you to use, modify, and distribute this code, subject to certain conditions.

### MIT License Summary

- **Permissions:** This license allows you to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software.
- **Conditions:** You must include the original copyright notice and the MIT License text in all copies or substantial portions of the software.
- **Liability:** The software is provided "as is," and the authors are not liable for any damages or issues arising from the use of the software.

For the full text of the MIT License, please see the [LICENSE](LICENSE) file in this project.


