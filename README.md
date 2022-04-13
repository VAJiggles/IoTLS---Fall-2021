# IoTLS---Fall-2021
Python Code to extract CAs from pcap files in a folder. The code also uses the MAC Addresses of different devices in order to differentiate between devices and run through all their pcap files individually.


The code runs by simply making the following changed in order to incorporate your list of pcap files.
There are a few alterations required for it to run successfully:
  1. Line 94 - Add the path to the directory with the list of devices from which the pcap files have been captured.
  2. Line 101 - This line stores all the MAC addresses of the devices to differentiate between them.
