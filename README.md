# HackTheBox-Writeups
_You can __+respect me__ thanks!_<br>
<a href="https://app.hackthebox.eu/profile/184235">
  <img src="https://www.hackthebox.eu/badge/image/184235" alt="Hack The Box">
  </img>
</a><br>
<a href=https://www.buymeacoffee.com/f4T1H>
  <img src="https://github.com/f4T1H21/f4T1H21/blob/main/support.png" width="221" height="40" alt="Support">
  </img>
</a>
<br><br>
I'll be posting __retired__ box writeups.

## Boxes
_My favourite one so far:_ ___Breadcrumbs___

<br>

|Box|Writeup|Difficulty|OS|Foothold|Lateral Movement|Privilege Escalation|
|---|-------|----------|--|--------|----------------|--------------------|
|<a href="https://app.hackthebox.eu/machines/TheNotebook"><img width="32" height="32" alt="thenotebook" src="/src/banners/thenotebook.png"></img></a>|[TheNotebook](Boxes/TheNotebook/README.md)|Medium|Linux|[JWT Auth RS256](/Boxes/TheNotebook/README.md#rs256-signing)|[Home backup](Boxes/TheNotebook/README.md#lateral-home-backup)|[Docker Escape Overwriting RunC](/Boxes/TheNotebook/README.md#privesc-docker-escape-overwriting-runc)|
|<a href="https://app.hackthebox.eu/machines/Armageddon"><img width="32" height="32" alt="armageddon" src="/src/banners/armageddon.png"></img></a>|[Armageddon](Boxes/Armageddon/README.md)|Easy|Linux|[Drupalgeddon2](/Boxes/Armageddon/README.md#foothold-drupalgeddon-2)|[MySQL](Boxes/Armageddon/README.md#lateral-movement-mysql)|[snapd (dirty_sock)](/Boxes/Armageddon/README.md#privesc-snapd-dirty_sock-cve-2019-7304)|
|<a href="https://app.hackthebox.eu/machines/Breadcrumbs"><img width="32" height="32" alt="breadcrumbs" src="/src/banners/breadcrumbs.png"></img></a>|[Breadcrumbs](Boxes/Breadcrumbs/README.md)|Hard|Windows|[LFI](/Boxes/Breadcrumbs/README.md#lfi) & [PHP SESSION](/Boxes/Breadcrumbs/README.md#php-session) & [Powershell File Upload](Boxes/Breadcrumbs/#file-upload)|[SQLite DB](Boxes/Breadcrumbs/README.md#sqlite-db)|[Reversing](/Boxes/Breadcrumbs/README.md#reversing) & [SQLi](/Boxes/Breadcrumbs/README.md#sqli)|
|<a href="https://app.hackthebox.eu/machines/Atom"><img width="32" height="32" alt="atom" src="/src/banners/atom.png"></img></a>|[Atom](Boxes/Atom/README.md)|Medium|Windows|[Signature Validation Bypass in electron-updater](/Boxes/Atom/README.md#foothold-signature-validation-bypass-in-electron-updater)||[PortableKanban](/Boxes/Atom/README.md#portablekanban) & [redis](/Boxes/Atom/README.md#redis)|
|<a href="https://app.hackthebox.eu/machines/Ophiuchi"><img width="32" height="32" alt="ophiuchi" src="/src/banners/ophiuchi.png"></img></a>|[Ophiuchi](Boxes/Ophiuchi/README.md)|Medium|Linux|[SnakeYaml Deserialization](/Boxes/Ophiuchi/README.md#foothold-snakeyaml-deserialization)||[WebAssembly formats](/Boxes/Ophiuchi/README.md#privilege-escalation-webassembly-formats)|
|<a href="https://app.hackthebox.eu/machines/Spectra"><img width="32" height="32" alt="spectra" src="/src/banners/spectra.png"></img></a>|[Spectra](Boxes/Spectra/README.md)|Easy|Linux|[WordPress reverse shell](/Boxes/Spectra/README.md#foothold-wordpress-reverse-shell)||[initctl with sudo](/Boxes/Spectra/README.md#root-part)|
|<a href="https://app.hackthebox.eu/machines/Tentacle"><img width="32" height="32" alt="tenet" src="/src/banners/tentacle.png"></img></a>|[Tentacle](Boxes/Tentacle/README.md)|Hard|Linux|[CVE-2020-7247](/Boxes/Tentacle/README.md#foothold-cve-2020-7247)||[Cronjob abuse](/Boxes/Tentacle/README.md#escalating-admin-cronjob-abuse) & [Misconfigured keytab](/Boxes/Tentacle/README.md#escalating-root-misconfigured-keytab)|
|<a href="https://app.hackthebox.eu/machines/Tenet"><img width="32" height="32" alt="tenet" src="/src/banners/tenet.png"></img></a>|[Tenet](Boxes/Tenet/README.md)|Medium|Linux|[PHP Object Injection](/Boxes/Tenet/README.md#foothold-php-object-injection-aka-deserialization)||[Race Condition](/Boxes/Tenet/README.md#privilege-escalation-race-condition)|
|<a href="https://app.hackthebox.eu/machines/ScriptKiddie"><img width="32" height="32" alt="scriptkiddie" src="/src/banners/scriptkiddie.png"></img></a>|[ScriptKiddie](/Boxes/ScriptKiddie/README.md)|Easy|Linux|[Msfvenom Template Injection](/Boxes/ScriptKiddie/README.md#exploiting-and-getting-a-shell)||[msfconsole with sudo](/Boxes/ScriptKiddie/README.md#privilege-escalation-to-root)|

<br>

___- Written by f4T1H -___
