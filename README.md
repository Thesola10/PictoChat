# PictoChat Protocol Adapter
The PictoChat Protocol Adapter (PCPA) set of tools is designed to interact with the Nintendo DS PictoChat protocol, via a compatible Prism54 USB WiFi adapter.

## Distribution
The core `pcpa` library allows for a computer to send and receive black-and-white bitmap data to a PictoChat chatroom. When active, the PC is counted as a connected user.

The `pctt` library (PictoChat Text Toolkit) allows recognition and exchange of plain text through PictoChat, by recognizing the standard PictoChat font. When recognition fails, `pctt` falls back to bitmap data by default.

## Build process
This project not being ready for release yet, there is no official build toolchain for the moment.

## Why it exists
A while ago, a piece of software called [`pictosniff`](https://web.archive.org/web/20070630075933/lekernel.lya-fr.com/pictosniff.html) was created, which allowed users to decode incoming PictoChat messages, but not to interact with them. This library re-uses code from `pictosniff`, which is courtesy of Sebastien Bourdeauducq under the GNU GPL.

## Where I can get a Prism54 WiFi adapter
~~The official Nintendo USB WiFi adapter is powered by the Prism54 chipset, the same which can be found inside of a Nintendo DS, DSi and 3DS.~~
Should be easy enough to find by looking for "Prism54" on Amazon. Bought an official Nintendo USB WiFi adapter and realized I'm a dunce and it, in fact, _can't_ sniff PictoChat packets. Development is paused until I decide to buy another Prism54 dongle and actually test things out. 🤦‍♂️
