# Some scripts for easy Fritzbox handling

Currently only Fritzboxes with FRITZ!OS v6.50 or newer are supported.

### Wake on LAN

* **wakeup.py** – Python script for remotely starting a computer behind a Fritzbox using its WOL functionality

#### Required Python modules

* lxml
* packaging
* requests

#### Configuration

All configuration is done in the config file in JSON format:

* *host*: external fritzbox hostname or ip
* *port*: ssl port
* *username*/*password*: fritzbox login credentials
* *devices*: list of device names with macs that can be used for wakeup

If the password line is not present in the config file, you will be prompted for the password.

#### Usage

```sh
> wakeup.py                           # sends wakeup to 'default' device
> wakeup.py foo                       # sends wakeup to device 'foo' in config file
> wakeup.py -k foo                    # sends wakeup to device 'foo' while ignoring ssl certificate verification
> wakeup.py -c yourconfig.json bar    # sends wakup to device 'bar' using config file 'yourconfig.json' 
> wakeup.py -h                        # shows help
```
