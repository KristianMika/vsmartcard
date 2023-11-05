# Virtual Smart Card

## Build and Install

```bash
autoreconf --verbose --install
./configure --sysconfdir=/etc
make
make install
```

## Meesign Usage

_NOTE:_ You may need to restart pcscd before running vicc

```bash
sudo systemctl restart pcscd
```

```bash
vicc -t meesign --meesign-hostname <hostname> --group_id <signing group ID> --meesign_ca_cert </path/to/your/meesign-ca-cert.pem>
```

- NOTE: _Feel free to append -v -v -v -v for extra verbose mode_

## Initialize the card

```bash
git clone https://github.com/KristianMika/InfinitEID.git
cd InfinitEID/src/InfinitEID-card-management
# install requirements using README.md
python3 cli
```

Press 3x "enter"

wait a few secs

Press "q"

Now you are ready to go. Keep in mind PCSCD sets a 60s suicide timer after every APDU. When the timer runs out,
it kills the context, in our case, vicc aborts. (Will solve this issue later)

Virtual Smart Card emulates a smart card and makes it accessible through PC/SC.
Currently the Virtual Smart Card supports the following types of smart cards:

- Generic ISO-7816 smart card including secure messaging
- German electronic identity card (nPA) with complete support for EAC
  (PACE, TA, CA)
- Electronic passport (ePass/MRTD) with support for BAC
- Cryptoflex smart card (incomplete)

The vpcd is a smart card reader driver for [PCSC-Lite](https://pcsclite.apdu.fr/) and the windows smart
card service. It allows smart card applications to access the vpicc through
the PC/SC API. By default vpcd opens slots for communication with multiple
vpicc's on localhost on port 35963 and port 35964. But the |vpicc| does not
need to run on the same machine as the vpcd, they can connect over the
internet for example.

Although the Virtual Smart Card is a software emulator, you can use
[pcsc-relay](http://frankmorgner.github.io/vsmartcard/pcsc-relay/README.html)
to make it accessible to an external contact-less smart card reader.

Please refer to [our project's website](http://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html) for more information.
