#!/bin/sh

## DRAFT
# assumes user is root
# assumes 'cuckoo' user
# assumes '/opt/cuckoo' CWD

req{   ## Required - Cuckoo
    #build tools
    apt install automake libtool build-essential pkg-config make gcc rustc cargo swig

    apt install python python-pip python-dev libffi-dev libssl-dev
    apt install python-virtualenv python-setuptools python-yaml
    apt install libjpeg-dev zlib1g-dev
    apt install libcap2-bin
    apt install p7zip-full rar unace-nonfree cabextract
    apt install libjansson-dev libmagic-dev

    apt install mongodb
    apt install postgresql libpq-dev

    # Reboot
}

pip{
    ## pip to root
        pip install -U pip setuptools

    ## pip to venv
    virtualenv venv
    . venv/bin/activate
        pip install -U pip setuptools
        pip install -U yara-python
        pip install Pillow==6.2.1
        pip install openpyxl==3.0.1
        pip install ujson==1.35
        pip install m2crypto==0.35.2
    deactivate
}

yar{   ## YARA 
    VER_yara=3.11.0
    https://github.com/VirusTotal/yara/releases/tag/v$VER_yara
    tar -zxf yara-$VER_yara.tar.gz
    pushd yara-$VER_yara > /dev/null
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet
    make
    make install
    make check
    popd
}

vol{   ## Volatility (requires Yara, pefile)
    # Volatility2
        #https://github.com/volatilityfoundation/community
        #https://github.com/volatilityfoundation/profiles

    apt install pcregrep libpcre++-dev
    #apt install -y libdistorm3 #-3
    pip install -U distorm3==3.4.1
    pip install -U pycryptodome

    git clone https://github.com/volatilityfoundation/volatility.git volatility
    pushd volatility > /dev/null
    python setup.py install
    popd

    # Volatility3
        #https://volatility3.readthedocs.io/en/latest/
    apt install libcapstone-dev libcapstone2
    pip install capstone
    git clone https://github.com/volatilityfoundation/volatility3.git volatility3
    pushd volatility3 > /dev/null
    python3 setup.py install
    popd
}

sur{   ## suricata 5
    apt-get install libpcre3 libpcre3-dbg libpcre3-dev libpcap-dev          \
                    libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev   \
                    libcap-ng-dev libcap-ng0 libnss3-dev libgeoip-dev       \
                    liblua5.1-dev libhiredis-dev libevent-dev
    apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                    libnetfilter-log-dev libnetfilter-log1      \
                    libnfnetlink-dev libnfnetlink0
    echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig

    # Intel HS
    #git clone git://github.com/intel/hyperscan

    VER_sur=5.0.0
    wget http://www.openinfosecfoundation.org/download/suricata-$VER_sur.tar.gz.sig
    wget http://www.openinfosecfoundation.org/download/suricata-$VER_sur.tar.gz
    gpg --verify suricata-$VER_sur.tar.gz.sig suricata-$VER_sur.tar.gz
    tar -xvzf suricata-$VER_sur
    pushd suricata-$VER_sur > /dev/null
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var                            \
        --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib/     \
        --with-libcap_ng-libraries=/usr/local/lib --with-libcap_ng-includes=/usr/local/include  \
        --enable-lua --enable-nfqueue --enable-geopip --disable-gccmarch-native
    make && make install-full
    popd

    cp /etc/suricata/suricata.yaml /etc/suricata/suricata-cuckoo.yaml
    suricata-update -c /etc/suricata/suricata-cuckoo.yaml -o /etc/suricata/rules
}

sig{   ## sigma
    # pip3 install sigmatools
}

other{
    # KVM
    apt install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt

    ## cuckoo user env
    adduser cuckoo
    # TODO: vbox check
    usermod -a -G vboxusers cuckoo
    # TODO: libvirt check
    usermod -a -G libvirtd cuckoo

    ## tcpdump
    apt install tcpdump apparmor-utils
    aa-disable /usr/sbin/tcpdump
    groupadd pcap
    usermod -a -G pcap cuckoo
    chgrp pcap /usr/sbin/tcpdump
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
    #last resort: chmod +s /usr/sbin/tcpdump

    # update libraries
    ldconfig


    mkdir /opt/cuckoo
    chown cuckoo:cuckoo /opt/cuckoo
    # cuckoo --cwd /opt/cuckoo

    # You could place this line in your .bashrc, for example.
    export CUCKOO=/opt/cuckoo
    cuckoo
}

req
pip
yar
vol
sur
sig
other