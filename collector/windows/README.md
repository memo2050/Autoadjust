# Windows collector

Sends real Windows events to your Spark SOC. Read-only: it never changes the computer.

1. Use a Windows computer you own or are authorized to monitor.
2. Turn on the auditing you want (otherwise the events do not exist): Local Security Policy, Advanced Audit Policy: Logon/Logoff, Account Management, Detailed Tracking (Process Creation), Policy Change. For command lines, also enable "Include command line in process creation events".
3. Open PowerShell as Administrator. Test without sending anything:
   `.\Send-SecurityEvents.ps1 -Url https://YOUR-SITE -Token YOUR-INGEST-TOKEN -DryRun`
4. Send for real, and keep it running:
   `.\Send-SecurityEvents.ps1 -Url https://YOUR-SITE -Token YOUR-INGEST-TOKEN -Loop`
   (or create a Scheduled Task that runs it at startup).
5. Open the SOC Analyst workspace. "Windows Event Logs" turns HEALTHY once events arrive, and STALE if nothing arrives for 15 minutes.

Windows Event Forwarding: if you already forward events to a collector server, run this script on that server, or convert exported events to JSON and POST them to `/api/soc/ingest/windows` (array of events with `Id`, `RecordId`, `TimeCreated`, `ProviderName`, `LogName`, `MachineName`, `Data{...}`).

The script was written without a Windows machine and has not been run by its author. Use `-DryRun` first and report any problem.

## Sysmon, Application log and heartbeat (version 2.0)
The collector also reads the **Application** log (crashes and hangs) and, if installed, **Sysmon** (`Microsoft-Windows-Sysmon/Operational`: process creation, network connections, remote threads, process access, file creation, registry, DNS). Sysmon is optional; without it that source is skipped and the Sysmon detections simply have no data. When there is nothing new the script still sends a heartbeat so the SOC can show the computer as connected. This script was written but has never been run on a real Windows computer by the author: test it with `-DryRun` first on one authorized machine.
