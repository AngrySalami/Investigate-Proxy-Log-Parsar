# Investigate-Proxy-Log-Parsar
A python script that allows for quickly parsing of BlueCoat Proxy Logs and hitting Invesigate API for domains BlueCoat allowed, but that are found to be malicious.

Please generate a new API key from your Investigate console and add the key to the file.

This script will allow a person to quickly parse through a BlueCoat Proxy Log to provide a count of malicious domains that were allowed by the BlueCoat device.

In order for this script to work, the customer must generate a csv log that contains the date, time, whether it was allowed or blocked, and destination.
