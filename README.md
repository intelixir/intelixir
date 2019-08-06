```
██╗███╗   ██╗████████╗███████╗██╗     ██╗██╗  ██╗██╗██████╗ 
██║████╗  ██║╚══██╔══╝██╔════╝██║     ██║╚██╗██╔╝██║██╔══██╗
██║██╔██╗ ██║   ██║   █████╗  ██║     ██║ ╚███╔╝ ██║██████╔╝
██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██║ ██╔██╗ ██║██╔══██╗
██║██║ ╚████║   ██║   ███████╗███████╗██║██╔╝ ██╗██║██║  ██║
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```
A (poorly written) potion of threat intelligence.

Intelixir is a demonstration library for SophosLabs Intelix, written in Python.
It's major features are poorly written code, zero tests, few comments, and no docstrings! You're welcome!

## Quickstart

Import the library (github.com/intelixir/intelixir)
```python
from intelixir import SophosLabs
```

Create a SophosLabs and auth to get api token
```python
s = SophosLabs(
    client_id='abcdefghijklmnopqrstuvwzyz',
    client_secret='abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno',
    region='DE')
```

There are three services:
 - lookups (quick lookups for known intelligence)
 - static (analysis - ML, AV, and other static tools)
 - dynamic (sandbox - detonate on a VM and observe behavior)
They all return json-formatted intelligence reports

We can GET existing, basic threat intel via sha256, url, or local filepath
```python
s.lookup_sha256('01ea7b43695112507f3d312c64701d1af88266e87205f0be3103872229b925c9')
s.lookup_url('http://sophostest.com/politics/index.html')
s.lookup_file('putty.exe')
# TODO: s.lookup_apk()
```

We can GET existing threat intel from the static analyzers via job_id or sha256
We can POST files to SophosLabs for static analysis
```python
s.static_job('76e82b693fbcb7300e21fe1f4fc68927')
s.static_sha256('8c2be18f80801afa8129f5e82cbf9c53afb8f9368f88619acbb7d1dc0df0237a')
s.static_file('putty.exe')
```

Dynamic (sandbox) is used the same way
```python
s.dynamic_job('5d09277fef89bc5113f000e51da191bf')
s.dynamic_sha256('8c2be18f80801afa8129f5e82cbf9c53afb8f9368f88619acbb7d1dc0df0237a')
s.dynamic_file('putty.exe')
```

Each method returns the report direct from the API at the time it was called (inc. incomplete jobs / errors)
```python
report = s.lookup_url('https://website.com')
```

Reports of successful analyses are added to a dictionary in our instance of a SophosLabs.
```python
s.reports_lookup
s.reports_static
s.reports_dynamic
s.reports_dynamic['file']['another.exe']
```

Reports are stored in a nested dictionary with a key that corresponds to the method you called
```python
for key in s.reports_lookup:
    print(key)
```

The individual reports are stored with a key that corresponds to the args provided to the method you called
```python
for key in s.reports_lookup['sha256']:
    print(key)
```

You can stop reports from being saved if you don't want them to by setting save to False
```python
s.static_sha256('01ea7b43695112507f3d312c64701d1af88266e87205f0be3103872229b925c9', save=False)
```

Sometimes a job isn't done instantly (dynamic execution takes time)
```python
print(s.dynamic_file('another.exe'))
# {'jobStatus': 'IN_PROGRESS', 'jobId': '5d09277fef89bc5113f000e51da191bf'}
```

After some time has passed, we can recheck the reports for all "IN_PROGRESS" jobs for either static or dynamic analysis.
These return a list of tuples corresponding to the method and the arg provided when you initially requested them
```python
static = s.check_static_jobs()
dynamic = s.check_dynamic_jobs()
# the tuples in the list make it easy to query the reports dicts
for t in static:
    print(s.reports_static[t0][t1])
```