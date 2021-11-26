# Handshake Protocol for Wireshark

This is a dissector for Wireshark written in Lua that decodes [Handshake](https://handshake.org) packets.

## Screenshots

![Packet List](https://user-images.githubusercontent.com/5113343/142235940-93d55aef-cf0d-454a-ba4d-19f74fb2471c.png)

![Packet Details](https://user-images.githubusercontent.com/5113343/142236115-7f4bc665-a2e2-4824-872c-29f0b3eadd43.png)

![Packet Details and Bytes](https://user-images.githubusercontent.com/5113343/142236304-db1889ba-449e-48b9-b562-7c65992da8cd.png)

## Progress

Although all packet types have been added, a few haven't been tested yet. Please send a pcap if you are able to capture them (or confirm it works and PR a check mark :D).

| Type | Packet      | Parser | Tested |
| ---- | ----------- | ------ | ------ |
| 0    | VERSION     | ✔️     | ✔️     |
| 1    | VERACK      | ✔️     | ✔️     |
| 2    | PING        | ✔️     | ✔️     |
| 3    | PONG        | ✔️     | ✔️     |
| 4    | GETADDR     | ✔️     | ✔️     |
| 5    | ADDR        | ✔️     | ✔️     |
| 6    | INV         | ✔️     | ✔️     |
| 7    | GETDATA     | ✔️     | ✔️     |
| 8    | NOTFOUND    | ✔️     |        |
| 9    | GETBLOCKS   | ✔️     | ✔️     |
| 10   | GETHEADERS  | ✔️     | ✔️     |
| 11   | HEADERS     | ✔️     | ✔️     |
| 12   | SENDHEADERS | ✔️     | ✔️     |
| 13   | BLOCK       | ✔️     | ✔️     |
| 14   | TX          | ✔️     | ✔️     |
| 15   | REJECT      | ✔️     | ✔️     |
| 16   | MEMPOOL     | ✔️     |        |
| 17   | FILTERLOAD  | ✔️     | ✔️     |
| 18   | FILTERADD   | ✔️     |        |
| 19   | FILTERCLEAR | ✔️     |        |
| 20   | MERKLEBLOCK | ✔️     | ✔️     |
| 21   | FEEFILTER   | ✔️     |        |
| 22   | SENDCMPCT   | ✔️     | ✔️     |
| 23   | CMPCTBLOCK  | ✔️     | ✔️     |
| 24   | GETBLOCKTXN | ✔️     | ✔️     |
| 25   | BLOCKTXN    | ✔️     | ✔️     |
| 26   | GETPROOF    | ✔️     | ✔️     |
| 27   | PROOF       | ✔️     | ✔️     |
| 28   | CLAIM       | ✔️     |        |
| 29   | AIRDROP     | ✔️     | ✔️     |
| 30   | UNKNOWN     | ✔️     |        |

## Installation

Simply clone this repository into Wireshark's plugin directory.
**Make sure the directory is called `handshake` and not anything else.**

> Wireshark (personal) plugin directory:
>
> - Windows: `%APPDATA%\Wireshark\plugins`
> - Linux: `~/.local/lib/wireshark/plugins`
> - macOS: `%APPDIR%/Contents/PlugIns/wireshark`

```bash
cd ~/.local/lib/wireshark/plugins/
git clone https://github.com/htools-org/wireshark-handshake-protocol handshake
```

Then, restart Wireshark or reload plugins (`Ctrl` + `Shift` + `L`).

That's it!

## Usage/Examples

Once installed, Handshake packets will automatically be decoded.

The **Packet Details** pane will have a new tree called **Handshake Protocol Data**. Expand it to explore the packet.

Some handy display filters:

```javascript
// Filter by a specific packet type
handshake && handshake.type == 0;

// [add more]
```

## Contributing

Contributions are always welcome!

Each packet type has its own file to keep the code clean and is mostly commented.

If you plan to add a new type, a good place to start is by cloning `packet_version.lua` and replacing the `name`, `type`, `fields`, and `parse`.
Remember to add the new type in `handshake.lua`!

## Feedback

Feel free to [create a new issue](https://github.com/htools-org/wireshark-handshake-protocol/issues/new) if there's anything missing or could use more info.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Acknowledgements

- [Bitcoin Protocol Documentation](https://en.bitcoin.it/wiki/Protocol_documentation)
- [hsd codebase](https://github.com/handshake-org/hsd/blob/2d1cbe9c17b0ad4e8858c06a8f85625dbee35ba9/lib/net/packets.js)
- [Creating a Wireshark dissector in Lua](https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
