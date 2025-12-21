This program can be installed on a Raspberry Pi (or any Linux box) to provide an easy Wi-Fi packet capture tool.

User can install any number of suitable Wi-Fi adapters, and they will be set to monitor mode and made available to capture packets.

<img width="457" height="525" alt="single adapter capture" src="https://github.com/user-attachments/assets/dd1adea2-5da5-4daf-b773-631beab2d1b2" />


Channel selection:

The channel selection is broken up into 3 RF Bands: 2.4 GHz, 5 GHz, and 6 GHz.

The 2.4 GHz channels are 5 MHz apart, and are displayed with channels 1, 6, and 11 on the left hand column for easy selection of these preferred channels.

The 5 GHz channels are in rows corresponding to their 80 MHz bonded channels.

The 'All' button selects/de-selects all channels in that RF band.

All captures in 5 GHz and 6 GHz are taken at 80 MHz, so regardless of which channel is selected in a 5 GHz row, it will capture the 80 MHz bonded channel for any main channel of that row.

The channel selection is for the 20 MHz main channel.

Example:

If channel 40 is selected, it will capture traffic on channel 40 (20 MHz wide), bonded 36 and 40 (40 MHz wide), and bonded 36, 40, 44, and 48 (80 MHz wide). 


Dwell time:

This sets how long to stay on each channel. Default is 200 ms.



Filename prefix:

This adds a convenient name to the packet capture file, which gets appended to the time.

Example:

2025-12-21--13-25-13-walkingaroundshops.pcap

If no name is given, it will default to the adapter name.



File split:

This breaks the packet captures into multiple files, after set time. Default is none for one continuous file.


<img width="503" height="487" alt="multi adapter capture" src="https://github.com/user-attachments/assets/e7f446a2-c42a-4268-b2d2-b3003c12b969" />


Multi-adapter capture:

If the system has two or more Wi-Fi capture devices, each device can be set to a different channel, and then selected here to enable capturing multiple adapters into a single capture file.

Filename prefix and file split are the same as above for single adapters.


Download last capture:

This button downloads the most recent capture directly from the web interface.

If capture is currently running, it will download what has been captured so far without interfering with the current packet capture.


Shut down system:

If you need an explanation for this, then this software isn't for you.


All packet captures are saved in the home directory.

