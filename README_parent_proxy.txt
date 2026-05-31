Parent Proxy Control
====================

！！！仅供学习参考，不得作为非法用途！！！
一切使用后果自负，与作者无关

This is a controllable local HTTP/HTTPS proxy. It does not change router settings.
The child device must manually use this PC as its Wi-Fi proxy.

Files:
- parent_proxy_control.py: main Python script
- parent_proxy_config.json: settings
- start_proxy.bat: start proxy service
- mode_normal.bat: restore normal speed
- mode_slow.bat: slow down traffic
- mode_block.bat: block traffic through the proxy

How to use:
1. Double-click start_proxy.bat on this PC and keep the window open.
2. The window will print one or more addresses like 192.168.x.x:8888 or 113.x.x.x:8888.
3. On the child device, open Wi-Fi proxy settings.
4. Set proxy host to this PC's IP address and proxy port to 8888.
5. Use mode_slow.bat to slow down.
6. Use mode_block.bat to block traffic through the proxy.
7. Use mode_normal.bat to restore normal speed.

Config:
- slow_kbps controls the slow mode speed. 4 means about 4 KB/s.
- listen_port defaults to 8888.

Notes:
- This works for apps that obey system Wi-Fi proxy settings.
- Some games do not use HTTP/HTTPS proxy settings, so they may bypass it.
- If Windows Firewall asks, allow Python on private networks.
- To stop everything, close the start_proxy.bat window and remove the proxy setting from the child device.
