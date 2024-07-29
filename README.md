# ARGO (Ai-driven framewoRk for CountinG peOple) - Wireless People Counting Framework

## REFERENCES

If you use the content of this repository, please reference the following paper: 

> R. Rusca, D. Gasco, C. Casetti and P. Giaccone, "Privacy-preserving WiFi fingerprint-based people counting for crowd management" - Computer Communications, 2024 [URL](https://www.sciencedirect.com/science/article/pii/S0140366424002482) [BibTeX](/cite.bib)

This Python script is designed to analyze wireless network traffic captured in a PCAP file and count devices that use either globally unique MAC addresses or locally administered MAC addresses. It also performs clustering of devices based on their network capabilities.

## Files

- `argo.py`: The main Python script responsible for device counting and clustering based on network traffic in a PCAP file.
- `models.json`: A JSON file that serves as a device-model database, containing information about different devices and their capabilities.
- `bloomfilter.py`: Python script containing the basic logic about Bloom Filter data structure.
- `bloomfilter_operations.py`: Python script containing the advanced logic about Bloom Filter data structure.

## Dependencies

- `datetime`: For time-related functions.
- `sys`: Provides access to some variables used or maintained by the interpreter.
- `argparse`: Allows command-line argument parsing.
- `scapy`: A Python wrapper for the Wireshark packet analyzer.
- `logging`: Used for logging information and errors.
- `json`: For reading a device-model database in JSON format.
- `pandas`: Provides data structures for efficient data manipulation.
- `scipy.spatial`: For calculating distances between data points.
- `sklearn.cluster.DBSCAN`: Implements the DBSCAN clustering algorithm.
- `bitarray`: Used to manage the Bloom Filter bit-array.
- `mmh3`: Provides the logic to use MurMur Hashing for Bloom Filter.
- `math`: Includes some useful math operations.
- `numpy`: For managing multi-dimensional arrays.

## Command Line Arguments

The script accepts the following command-line arguments:

- `--input_file`: Path to the PCAP trace file.
- `--max_ratio`: Maximum Ratio for clustering algorithm.
- `--power_threshold`: Threshold for the capturing power.
- `--default_counter`: Default number assigned to a cluster if the Maximum Ratio condition is not met.
- `--min_percentage`: Minimum percentage of probe requests with locally administered MAC addresses for clustering.
- `--epsilon`: Epsilon parameter for DBSCAN clustering.
- `--min_samples`: Min samples parameter for DBSCAN clustering.
- `--distance_metric`: Metric parameter for clustering.
- `--rate_modality`: Choose the rate to extract from the database.
- `--clustering_method`: Clustering method, the possible choices are `dbscan` and `optics`.
- `--counting_method`: Counting method when a cluster is examined, the possible choices are `simple` and `advanced`.

## Code Execution

1. The script starts by parsing the command-line arguments.
2. It reads a device-model database from a JSON file named "models.json."
3. It initializes variables for counting and clustering devices.
4. The script reads and processes packets from the PCAP file.
5. It checks the signal power of each packet and discards packets with power below the threshold.
6. The script extracts relevant fields from each packet, including MAC addresses, capabilities, and other information.
7. It categorizes MAC addresses as globally unique or locally administered.
8. The script collects information about VHT, Extended, and HT capabilities for clustering.
9. It counts devices with globally unique MAC addresses and checks if the minimum percentage condition for clustering is met.
10. If clustering is performed, it uses DBSCAN or OPTICS to cluster devices based on their capabilities.
11. The script calculates the average capabilities within each cluster.
12. It estimates the number of devices within each cluster and counts them.
13. Finally, the script logs information about the number of devices detected.

## Output

The script generates log information about the devices using globally unique MAC addresses, devices using locally administered MAC addresses, and the total number of detected devices.

## Usage

Example usage:

```shell
python argo.py --input_file ./example.pcap --max_ratio 100 --power_threshold -70 --default_counter 1 --min_percentage 0.02 --epsilon 4 --min_samples 15 --dbscan_metric euclidean --rate_modality mean_rate --clustering_method dbscan --counting_method advanced
```

## Authors

All the authors are researchers or master's students at the Politecnico di Torino, Italy.

- **Alex Carluccio** - *Master's student* -
- **Diego Gasco** - *Researcher* -
- **Giuseppe Perrone** - *Master's student* -
- **Riccardo Rusca** - *Researcher* -

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. The MIT License is a permissive open-source license that allows you to use, modify, and distribute this code, subject to certain conditions.

### MIT License Summary

- **Permissions:** This license allows you to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software.
- **Conditions:** You must include the original copyright notice and the MIT License text in all copies or substantial portions of the software.
- **Liability:** The software is provided "as is," and the authors are not liable for any damages or issues arising from the use of the software.

For the full text of the MIT License, please see the [LICENSE](LICENSE) file in this project.


