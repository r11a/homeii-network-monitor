# Bundled monitoring engine

HOMEii's original code remains MIT licensed. The add-on also distributes separate software:

- Zabbix 7.0.32: AGPL-3.0-only, https://www.zabbix.com/license . Its unmodified corresponding source archive is included at `/usr/share/homeii/sources/zabbix-7.0.32.tar.gz`; the image build recipe is beside it. Upstream: https://cdn.zabbix.com/zabbix/sources/stable/7.0/ . HOMEii communicates with the separate server/API process; it does not copy Zabbix into its Python or React code.
- PostgreSQL 15: PostgreSQL License, https://www.postgresql.org/about/licence/ .
- Debian packages (including PHP, Nginx, fping and Python): individual notices and licenses are installed under `/usr/share/doc/<package>/copyright`. Corresponding Debian source packages are available through https://sources.debian.org/ and the Debian source archive for the installed package version.
- React, Vite, Recharts and other frontend dependencies retain their respective notices and licenses in the source dependency tree.

This file is an inventory, not a replacement license. Redistribution must retain each component's notices and satisfy its applicable source-distribution obligations. Zabbix is a trademark of its respective owner; HOMEii is not an official Zabbix distribution.
# Bundled template

`deploy/icmp_ping.yaml` is the unmodified ICMP Ping template from Zabbix tag 7.0.32, under AGPL-3.0: https://github.com/zabbix/zabbix/blob/7.0.32/templates/net/icmp_ping/template_module_icmp_ping.yaml .

