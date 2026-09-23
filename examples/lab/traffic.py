"""Send a finite, synthetic request set to the local lab proxy only."""
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from time import sleep

ORIGIN = 'http://proxy'
PATHS = ['/', '/assets/public/favicon_js.png', '/.env', '/.git/config',
         '/download?file=../../etc/passwd', '/search?q=%27%20OR%20%271%27=%271']

for attempt in range(30):
    try:
        urlopen(Request(ORIGIN + '/', headers={'Host': 'lab.local'}), timeout=2).close()
        break
    except URLError:
        if attempt == 29:
            raise
        sleep(1)

for path in PATHS:
    for _ in range(3 if path.startswith(('/.env', '/.git', '/download', '/search')) else 1):
        try:
            urlopen(Request(ORIGIN + path, headers={'Host': 'lab.local', 'User-Agent': 'sigma-probe-lab'}), timeout=5).close()
        except HTTPError:
            pass  # Rejected requests are still present in the access log.

print('Synthetic lab requests sent. Analyze the proxy log; HTTP status is not proof of exploitation.')
