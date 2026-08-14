 Fully functional DPI that passes DNS(proxy) requests through itself,
naturally if they are unencrypted. 


1. All DNS traffic needs to be directed to port 53, where this will be deployed. 
2. It passes HTTP/HTTPS traffic through as a transparent proxy. It does not inspect packet contents, only domains and IP addresses. Traffic redirection to it is also required. 
3. Four blocklist sources: Unified Register of Prohibited Websites of Roskomnadzor, AdGuard, an AdGuard variant, and a plain text file. Can be disabled in settings/config. Does not reload configs and blocklists on the fly; a restart is required. 
4. Port configuration and other settings are in application/properties.



 Полностью рабочий dpi, пропускает сквозь себя dns запросы, естественно если не шифрованные.

1. нужно весь dns трафик направить на 53 порт, где будет это развёрнуто. 
2. Пропускает сквозь себя http/https трафик как прозрачный прокси. контент пакетов не смотрит, только домены и ip адреса. так же нужна переадресация на него трафика. 
3. 4 источника РКН, AddGuard, вариант AddGuard-а, текстовый файл. можно выключать в настройках, в конфиге.не перечитывает конфиги и списки, нужно перегружать. 
3. конфиги портов и прочего в applocation/properties
-------------------------
