# ESPHole32

A Pi-hole style, network-wide ad and tracker blocker for the **ESP32-WROOM-32**. No PSRAM is needed.

Devices on your network send their DNS lookups to the ESP32. If a domain (or any parent domain) is on the blocklist, the board replies `0.0.0.0` straight away and the ad never loads. Every other lookup goes to a normal DNS server (Cloudflare `1.1.1.1` by default, with Quad9 `9.9.9.9` as backup).

**What it does**
- Holds up to **445,000 domains** in flash, stored as 5-byte hashes in a dedicated 2 MB partition
- Blocks subdomains too: blocking `doubleclick.net` also blocks `stats.g.doubleclick.net`
- Web dashboard with stats, a live query log, per-device counts, one-click Block/Allow, pause (5 min, 30 min, until resumed) and blocklist upload
- Your own block and allow lists. The allow list always wins.
- Wi-Fi setup portal, so no passwords live in the code
- Recovers by itself: falls back to the secondary upstream, and retries Wi-Fi after power cuts
- The dashboard is password-protected (user `admin`)

---

## 1. Install the tools (once)

1. Install **VS Code** and add the **PlatformIO IDE** extension.
2. Install **Python 3**, which runs the blocklist builder.
3. If Windows doesn't see the board when you plug it in, install the USB driver for its USB chip. That's **CP210x** or **CH340**, whichever is printed on the small chip near the USB port.

## 2. Flash the firmware

1. Open the `ESPHole32` folder in VS Code (File → Open Folder).
2. Plug in the ESP32 and click **PlatformIO: Upload** (the → arrow in the bottom bar). The first build downloads the ESP32 toolchain, which takes a few minutes.
   - If it gets stuck on `Connecting....`, hold the board's **BOOT** button until uploading starts.
3. Optionally, open **Serial Monitor** (the plug icon, 115200 baud) to watch the board boot.

## 3. First-time setup

1. On your phone, join the Wi-Fi network **`ESPHole32-Setup`** (password **`esphole32`**). A setup page should open; if not, go to `http://192.168.4.1`.
2. Enter:
   - your Wi-Fi name and password
   - a dashboard password (8+ characters)
   - a hostname (`esphole` for the first board, `esphole2` for the second)
   - **Static IP (recommended):** a DNS server must keep the same address. Either fill in a free IP (e.g. `192.168.1.53`, gateway = your router's IP), or leave it blank and set up a *DHCP reservation* for the board in your router.
3. It reboots and joins your network. Open `http://esphole.local` (or the board's IP) and log in as **admin**.

## 4. Build and install a blocklist

On your PC, from the `ESPHole32` folder:

```bash
python tools/build_blocklist.py                 # StevenBlack unified list (~80-140k domains)
python tools/build_blocklist.py --preset big    # StevenBlack + HaGeZi Multi (more aggressive)
python tools/build_blocklist.py my_list.txt https://some.site/hosts.txt   # your own sources
```

This creates **`blocklist.bin`**. On the dashboard, under **Blocklist**, choose the file and press **Upload**. A full list takes under a minute over Wi-Fi.

The script accepts hosts files, plain domain lists and Adblock `||domain^` lists. Rebuild and re-upload whenever you want fresher lists (monthly is plenty).

*Alternative:* flash the file over USB with
`esptool.py --chip esp32 write_flash 0x1D0000 blocklist.bin`

## 5. Point your network at it

- **Whole network:** in your router's DHCP/LAN settings, set **Primary DNS** to board 1's IP and **Secondary DNS** to board 2's IP. Devices pick this up when they reconnect, or after a reboot.
- **Single device (if you can't change the router):** set that device's DNS manually to the board's IP.
- **Check it works:** browse a news site, then look for red "Blocked" rows in the dashboard's query log.

## Using your second board

Flash the same firmware and give it a different hostname and IP during setup. Upload the same `blocklist.bin` to both boards. With both set in the router, lookups keep working when one board reboots. Custom block/allow lists are per board, so add important entries to both.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| A site or app broke | Find its blocked domain in the query log and press **Allow** |
| Need to change Wi-Fi | Dashboard → **Forget Wi-Fi**, or hold **BOOT** for 10 s while it's running |
| Forgot the dashboard password | Hold **BOOT** 10 s, rejoin `ESPHole32-Setup` and set a new one |
| Nothing appears in the log | Devices aren't using it yet. Check the router's DNS setting, then reconnect the device |
| Some ads still show | See limitations below |
| Board not found at `esphole.local` | Use its IP address instead. Some Android phones don't support `.local` names |

## Limitations (same as any DNS blocker, including Pi-hole)

- **Same-domain ads can't be blocked.** YouTube and Facebook serve ads from the same servers as the content.
- **Encrypted DNS bypasses it.** Browsers with "Secure DNS / DNS-over-HTTPS" turned on, and some apps, skip your DNS server. Turn that setting off in the browser to use ESPHole32.
- **IPv6 DNS from the router.** If your router hands out its own IPv6 DNS server, devices may use that instead. Turn off IPv6 DNS advertisement in the router, or set it to the board.
- UDP only; it doesn't answer DNS over TCP. Almost all lookups are UDP and devices retry elsewhere, so in practice this rarely matters.
- Stats and the query log live in RAM and reset on reboot.
- With hashes there is a tiny chance (roughly 1 in a million lookups with a full list) that an unlisted domain gets blocked by mistake. If that ever happens, add it to the allow list.

## Running the PC tests

The DNS parsing and blocklist lookup code in `src/dnslogic.h` has no Arduino dependencies, so you can test it on a PC (needs `g++` and Python 3):

```bash
cd pc_tests
python ../tools/build_blocklist.py sample_list.txt
g++ -std=c++17 test_dnslogic.cpp -o t && ./t
```

## Project layout

```
platformio.ini            build settings (board: esp32dev)
partitions.csv            4 MB layout: 1.75 MB app, 2.1 MB blocklist, 64 KB settings
src/main.cpp              Wi-Fi, DNS server/forwarder, dashboard + API, upload
src/dnslogic.h            DNS packet parsing, hashing, lookup (PC-testable)
src/web_ui.h              setup portal + dashboard HTML
tools/build_blocklist.py  builds blocklist.bin
pc_tests/                 PC unit tests for dnslogic.h (not built for the board)
```