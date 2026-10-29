/* Exported verbatim by station-init. Missing/failed helpers never execute a
 * stock vendor fallback. Ordinary init and independent recovery still run. */
#ifndef LISA_BOOT_DISPATCH_H
#define LISA_BOOT_DISPATCH_H
static const char lisa_boot_dispatch[]=
"#!/bin/sh\n"
"# Lisa Station boot dispatcher. Keep recovery independent of the controller.\n"
"runner=/bkupgrade/data/opt/lisa-station/bin/station-init\n"
"boot_ready=0\n"
"for i in /etc/init.d/S??*; do\n"
"    [ -f \"$i\" ] || continue\n"
"    # Network initialization precedes the first gated service. Open recovery\n"
"    # now, before any later controller operation can fail or time out.\n"
"    if [ \"$i\" = /etc/init.d/S46hardvold ]; then\n"
"        /etc/init.d/S99zdropbear start </dev/null\n"
"    fi\n"
"    case \"$i\" in\n"
"        /etc/init.d/S46hardvold) \"$runner\" --hardware-start </dev/null;;\n"
"        /etc/init.d/S47alsa-audio-monitor) [ \"$boot_ready\" = 1 ] && \"$runner\" --diagnostics-stage </dev/null;;\n"
"        /etc/init.d/S49chrony) \"$runner\" --time-start </dev/null;;\n"
"        /etc/init.d/S70unbound) \"$runner\" --dns-start </dev/null;;\n"
"        /etc/init.d/S99quasar) [ \"$boot_ready\" = 1 ] && \"$runner\" --vendor-start </dev/null;;\n"
"        *.sh) (trap - INT QUIT TSTP; set -- start; . \"$i\");;\n"
"        *) \"$i\" start;;\n"
"    esac\n"
"    # Establish policy after normal loopback initialization, before Wi-Fi\n"
"    # and all gated actors. A missing/failed loopback stage never opens gates.\n"
"    stage_result=$?\n"
"    if [ \"$i\" = /etc/init.d/S40net.lo ] && [ \"$stage_result\" = 0 ]; then\n"
"        if \"$runner\" --bootstrap </dev/null; then boot_ready=1; fi\n"
"    fi\n"
"done\n";
#endif
