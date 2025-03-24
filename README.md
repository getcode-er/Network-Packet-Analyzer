# Network-Packet-Analyzer
A Network Packet Analyzer (Packet Sniffer) is a tool that captures and inspects network packets in real time. Below is a basic Python-based packet sniffer using the **_scapy_** library.



**⚠️ Important Disclaimer:**  

    🔹 Use this tool only on networks you own or have permission to analyze.
    🔹 Unauthorized packet sniffing is illegal and violates privacy laws.



**How It Works :**

> 1.Capturing Packets:

              ✔ The script listens to network traffic using sniff() from scapy.
              ✔ It captures packets traveling through the network interface (Wi-Fi, Ethernet, etc.).

> 2.Extracting Information:

              ✔ It checks if the packet contains an IP layer.
              ✔ It extracts:  Source IP, Destination IP, Protocol, Ports, Payload data.


> 3.Displaying Packets in Real-Time:

              ✔ The script prints packet details when received.
              ✔ It keeps running until manually stopped (by pressing CTRL + C).



**How to Run:**

>1.Install Dependencies : **_pip install scapy_**

>2.Save the file as **_packet_sniffer.py_**

>3.Run the script as Administrator in terminal using: _**python packet_sniffer.py**_
