## NET RECON

This function allows a user to passively or actively detect hosts on a network

## Usage

```bash
python net_recon.py {-p/-a} -i INTERFACE
```

## Args

-p / --passive : Passive listen on interface specified by -i or --iface  
-a / --active : Active recon on listen interface specified by -i or --iface  
-i INTERFACE / --iface INTERFACE: interface to listen on

## Examples

### To passively listen on WiFi interface

```bash
python net_recon.py -p -i "Wi-Fi"
python net_recon.py --passive -i Wi-Fi
python net_recon.py -p --iface Wi-Fi
python net_recon.py -p --i Wi-Fi
```

### To actively recon devices on WiFi network

```bash
python net_recon.py -a -i "Wi-Fi"
python net_recon.py --active -i Wi-Fi
python net_recon.py -a --iface Wi-Fi
python net_recon.py -a --i Wi-Fi
```

### To show this help screen

```bash
python net_recon.py
```
