#!/bin/sh

# Install Suricata.
# $ sudo apt install software-properties-common
# $ sudo add-apt-repository ppa:oisf/suricata-stable
# $ sudo apt update
# $ sudo apt install suricata
# 
# !! compile script with 'libcap_ng' for drop permission
#
# Setup Suricata configuration.
#
# In /etc/default/suricata, set RUN to "no".
#
# In /etc/suricata/suricata-cuckoo.yaml apply the following changes;
# * Set "unix-command.enabled" to "yes".
# * Set "unix-command.filename" to "cuckoo.socket".
# * Set "outputs.eve-log.enabled" to "yes".
# * Set "run-as.user to "your cuckoo user"
# * Set "run-as.group to "your cuckoo user group"
# * Set "default-rule-path" to "/etc/suricata/rules/"
# * TODO More items.
# $ sudo suricata-update -c /etc/suricata/suricata-cuckoo.yaml -o /etc/suricata/rules
#
# Add "@reboot /opt/cuckoo/utils/suricata.sh" to the root crontab.
#
# Quick script to update the suricata conf (need to test)
# # !/usr/bin/env python
# # import yaml
# #
# # with open('/etc/suricata/suricata-cuckoo.yaml') as f:
# #     data = yaml.load(f, Loader=yaml.FullLoader)
# #     data['unix-command']['enabled'] = 'yes'
# #     data['unix-command']['filename'] = 'cuckoo-socket'
# #     data['outputs']['eve-log']['enabled'] = 'yes'
# #     data['run-as']['user'] = 'cuckoo'
# #     data['run-as']['group'] = 'cuckoo'
# #     data['default-rule-path'] = '/etc/suricata/rules/'
# #     f.write(yaml.dump(data, default_flow_style=False))

. /etc/default/cuckoo

# Do we want to run Suricata in the background?
if [ "$SURICATA" -eq 0 ]; then
    exit
fi

# Shouldn't need this anymore with change to the socket/rules/log paths and drop permission
mkdir -p /var/run/suricata
chown -R root:cuckoo /var/run/suricata
chmod -R 775 /var/run/suricata

suricata -c /etc/suricata/suricata-cuckoo.yaml --unix-socket=/opt/cuckoo/cuckoo.socket -k none -l /var/tmp -D
