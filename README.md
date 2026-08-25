# Wazuh Log Forwarder (Android)

A small Android app + foreground service that tails the device's `logcat`
output, reformats each line as an RFC 3164 (BSD) syslog message, and streams
it to a Wazuh manager over UDP or TCP. Built for a personal lab / CTF setup —
not a certified Wazuh product (Wazuh has no official Android agent).

## Important limitation: Android log sandboxing

Since Android 4.1, an app can only read **its own** log lines via `logcat`
unless it holds the `READ_LOGS` permission, which cannot be granted through
a normal install — Play Protect / the OS won't let a regular app request it
at runtime. Two ways around this, both supported by the app:

1. **Non-rooted device:** grant it over ADB once, after installing:
   ```bash
   adb shell pm grant dev.tyson.wazuhlogforwarder android.permission.READ_LOGS
   ```
   This requires USB debugging enabled and the device unlocked/authorized.
   The grant survives reboots and persists until the app is uninstalled.

2. **Rooted device:** not specially handled by the app itself, but you can
   root-grant the same permission with a shell-privileged package manager,
   or just install the ADB grant above (works identically on rooted
   devices too — root isn't actually required for this specific grant,
   since `READ_LOGS` is `signature|privileged|development`, and the
   `development` flag is exactly what lets `adb shell pm grant` assign it).

Without the grant, the service still runs and forwards **this app's own**
log lines (handy for testing end-to-end connectivity), and the main screen
tells you whether full access is active.

## Building the APK

Requires a JDK 17+, the Android SDK (platform 34, build-tools 34.0.0),
and Gradle 8.9+. Easiest path is opening this folder in
[Android Studio](https://developer.android.com/studio) and using
**Build > Build APK(s)** — it'll fetch what it needs automatically.

To build from the command line instead, point `JAVA_HOME` and
`ANDROID_HOME` at your own JDK/SDK install locations, then:

```bash
export JAVA_HOME=/path/to/your/jdk-17
export ANDROID_HOME=/path/to/your/android-sdk
export PATH="$JAVA_HOME/bin:$PATH"
gradle assembleDebug
```

The output APK lands at:

```
app/build/outputs/apk/debug/app-debug.apk
```

For a release build you'd also need to sign it (`assembleRelease` +
`apksigner`); debug builds install fine with `adb install` for lab use.

## Installing

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell pm grant dev.tyson.wazuhlogforwarder android.permission.READ_LOGS
```

Then open the app, enter your Wazuh manager's IP/hostname and the port
from the **rsyslog relay** setup below (not 514), pick UDP, and tap
**Start Forwarding**. Use **Send Test Message** to fire a single syslog
line immediately so you can confirm it arrives before trusting the live
stream.

## Wazuh manager side: rsyslog relay → localfile

**Do not use the manager's built-in `<remote><connection>syslog</connection>>`
listener for this.** It looks like the obvious approach and the config is
simple, but in testing it silently swallowed every packet — `wazuh-remoted`
owned the port and packets visibly arrived (confirmed with `tcpdump`), yet
nothing ever reached `analysisd` for rule matching, with no error logged
anywhere, even with `remoted.debug=2`. This appears to be a real limitation/bug
in the direct syslog listener, not a config mistake — see
[wazuh/wazuh#12389](https://github.com/wazuh/wazuh/issues/12389) for a
similar community report. The **actually reliable** approach, and the one
Wazuh's own docs and community recommend for exactly this kind of
non-agent network log source, is: receive the syslog with a real syslog
daemon (`rsyslog`) writing to a file, then have Wazuh tail that file with
a `<localfile>` block — the same pattern commonly used for firewalls/network
devices.

### 1. Add an rsyslog listener that writes a correctly-formatted file

Wazuh's `<localfile><log_format>syslog</log_format>` decoder expects the
classic BSD/RFC3164 shape — `<PRI>Mon dd HH:mm:ss hostname tag: message`
(three-letter month, no year, no timezone, **with** the numeric `<PRI>`
prefix). rsyslog's default file-output template uses ISO 8601 timestamps
and drops the `<PRI>`, which Wazuh won't parse — so use an explicit
template that reproduces the exact wire format:

```bash
sudo tee /etc/rsyslog.d/60-android-logcat.conf << 'EOF'
module(load="imudp")
input(type="imudp" port="5141")

template(name="BSDFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3164% %HOSTNAME% %syslogtag%%msg%\n")

:programname, isequal, "android-logcat" action(type="omfile" file="/var/log/android-logcat.log" template="BSDFormat")
& stop
EOF

sudo touch /var/log/android-logcat.log
sudo chown syslog:syslog /var/log/android-logcat.log   # rsyslogd drops privileges to this user
sudo chmod 644 /var/log/android-logcat.log             # owner (syslog) gets write, everyone else read
sudo systemctl restart rsyslog
```

Point the app's **Port** at `5141` (protocol UDP, same host) — pick a
different port here if you like, just keep it off `514`/`1514` so it
doesn't collide with Wazuh's own listeners. Verify with:
```bash
sudo tail -f /var/log/android-logcat.log
```
after tapping **Send Test Message** — lines should look like
`<134>Aug 23 16:58:17 <device>-<id> android-logcat: ...`.

**Watch for logrotate**: a default `/var/log/*.log` rotation rule can
truncate this file on its own schedule. Give it a dedicated rule
(`/etc/logrotate.d/android-logcat`) rather than relying on the default.

### 2. Tell Wazuh to read that file

```bash
sudo tee -a /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/android-logcat.log</location>
  </localfile>
</ossec_config>
EOF

sudo xmllint --noout /var/ossec/etc/ossec.conf && echo VALID
sudo systemctl restart wazuh-manager
```

### 3. The one gotcha that will burn you if you iterate on this config

`wazuh-logcollector` persists its per-file read position across restarts
(`/var/ossec/queue/logcollector/file_status.json`), specifically so it
doesn't replay old content after a restart. If you truncate or rewrite
the file while testing (as you likely will, tuning the rsyslog template),
that cached position can end up stale/invalid, and `logcollector` will
log `Analyzing file: '...'` once at startup and then **never read another
line**, with no error anywhere. If new content isn't showing up despite
everything else looking correct, clear that state:

```bash
sudo systemctl stop wazuh-manager
sudo rm -f /var/ossec/queue/logcollector/file_status.json
sudo systemctl start wazuh-manager
```

### Debugging this pipeline

Three independent layers, each worth checking in isolation when something
isn't showing up — in order:

```bash
# 1. Is rsyslog receiving packets and writing the file at all?
sudo tail -f /var/log/android-logcat.log

# 2. Is logcollector actually forwarding new lines to analysisd?
echo "logcollector.debug=2" | sudo tee -a /var/ossec/etc/local_internal_options.conf
echo "analysisd.debug=2" | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager
sudo grep "android-logcat.log" /var/ossec/logs/ossec.log

# 3. Is the rule actually firing?
sudo grep -c "Rule: 100100 (level 3)" /var/ossec/logs/alerts/alerts.log
```

One trap to avoid on step 3: don't `grep` for a string and assume any
match is real — this manager also alerts on `sudo` command audit
(`journald` → rule `5402`), which logs your **entire shell command
verbatim**, including whatever search string you just typed. Searching
for `"100100"` will match its own future command-line echo. Search for
the full rule header (`"Rule: 100100 (level 3)"`) with `grep -c` (a count,
not a pager) to sidestep this, or use `less` and search interactively
(`/pattern`) so the search text is never itself logged as a command
argument.

### 4. Add a rule so Android events actually generate an alert

Without a matching rule, events just sit in `archives.log` (and only
there if `logall` is on) — nothing shows up as an alert in the dashboard.
Wazuh's pre-decoding strips the BSD syslog envelope (timestamp/hostname)
but doesn't classify the message with a named decoder or populate
`program_name` on its own — there's no built-in decoder literally named
`syslog` to key off of (`<decoded_as>syslog</decoded_as>` will never
match; confirmed via `wazuh-logtest` showing "No decoder matched" even
on a well-formed line). The reliable approach is to match the raw log
text directly, which works regardless of decoder outcome. Add to
`/var/ossec/etc/rules/local_rules.xml` (as a single top-level `<group>` —
see note below):

```xml
<group name="android_logcat,">
  <rule id="100100" level="3">
    <match>android-logcat:</match>
    <description>Android device log line forwarded via Wazuh Log Forwarder</description>
  </rule>
</group>
```

Verify with `sudo /var/ossec/bin/wazuh-logtest` before trusting it live —
paste a sample line and confirm it matches rule `100100`.

**Note on editing this file:** the Wazuh dashboard's rules file editor
validates XML more strictly than `wazuh-analysisd` itself does (it wants a
single root element; multiple sibling `<group>` blocks in one file, which
`wazuh-analysisd` accepts fine, can trip its validator with a generic
"XML syntax error (1113)"). If you hit that, either keep this file to one
top-level `<group>`, or skip the dashboard editor and edit the file
directly over SSH (`sudo nano /var/ossec/etc/rules/local_rules.xml`,
validate with `sudo xmllint --noout <file>`, then
`sudo systemctl restart wazuh-manager`) — more reliable either way.

Also make sure `logall` / archived events are enabled if you want to see
every line (not just alerts) in `archives.log`:

```xml
<ossec_config>
  <global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

## Live log view and local log files

- **View Live Logs** opens a screen that streams the exact syslog-formatted
  lines the service is sending, as they happen — sourced in-process from the
  service, no network round trip. It supports a substring filter, Pause
  (freezes the view without stopping capture/forwarding), and Clear.
- Independently of forwarding, every line is also written to rotating local
  files under the app's private external storage (`Android/data/dev.tyson.wazuhlogforwarder/files/logs/`
  on the device) — 5MB per file, oldest files pruned past 7 days or 200MB
  total. This gives you a local record even if the Wazuh manager is
  unreachable, and something to inspect without a live connection.
- **Save Log Files as ZIP** bundles all current local log files into one
  `.zip` and lets you pick where to save it (Storage Access Framework —
  Downloads, Drive, wherever) with no storage permission required.

## App behavior notes

- Runs as a foreground service (persistent notification) so Android doesn't
  kill it in the background. Tap **Ignore battery optimizations** to reduce
  the chance the OS throttles it further on aggressive OEM skins (MIUI,
  OneUI battery savers, etc. are known to kill foreground services anyway —
  whitelist the app in those settings too if logs stop arriving overnight).
- "Start forwarding on boot" persists the setting and restarts the service
  after a reboot via a `BOOT_COMPLETED` receiver.
- UDP is fire-and-forget (no delivery confirmation, but simple and low
  overhead — fine for a lab). TCP opens a persistent connection with
  exponential-backoff reconnect if the manager is unreachable.
- Log lines are capped at 1800 characters before sending to stay under
  typical single-packet/single-line syslog limits.
- The syslog HOSTNAME field is `<device-model>-<ANDROID_ID>` — stable per
  device/install, not a hardware identifier like IMEI.
