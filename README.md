TruckCoin
---------

Intro
-----
TruckCoin is a free open source project derived from NovaCoin, with
the goal of providing a long-term energy-efficient Proof of Stake crypto-currency.
Built on the foundation of Bitcoin and NovaCoin, innovations such as proof-of-stake
help further advance the field of crypto-currency.

Setup
-----
Unpack the files into a directory and run:
 bin/32/truckcoind (headless, 32-bit)
 bin/64/truckcoind (headless, 64-bit)

The software automatically finds other nodes to connect to.  You can
enable Universal Plug and Play (UPnP) with your router/firewall
or forward port 18775 (TCP) to your computer so you can receive
incoming connections.

P2P port: 18775
RPC port: 18776

Upgrade
-------
All you existing coins/transactions should be intact with the upgrade.
To upgrade first backup wallet
truckcoind backupwallet <destination_backup_file>
Then shutdown truckcoind by
truckcoind stop
Start up the new truckcoind.

Links
-----
Visit the TruckCoin website: http://truckcoin.net/ for help and more information.
Block explorers: http://truckcoin.net/ , http://truckcoin.ovh/

Copyright (c) 2013-2020 TruckCoin Developers
Copyright (c) 2013 NovaCoin Developers
Copyright (c) 2011-2012 Bitcoin Developers
Distributed under the MIT/X11 software license, see the accompanying
file license.txt or http://www.opensource.org/licenses/mit-license.php.
This product includes software developed by the OpenSSL Project for use in
the OpenSSL Toolkit (http://www.openssl.org/).  This product includes
cryptographic software written by Eric Young (eay@cryptsoft.com).

