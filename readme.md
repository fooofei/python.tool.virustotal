
## VirusTotal Public API 2.0 With grequests


### get reports

```python
vt_batch_async_report(...)

fetch files report which is already exists in VirusTotal.

```

give an iterable object, which is a vt resource, can be MD5, SHA1, SHA256, vt_scan_id.

return list of Report().

use Report().ok to detect report is valid or invalid.

### rescan

```python
vt_batch_sync_report(...)
vt_batch_async_rescan(...)

tell VirusTotal to rescan resources we gived, not contains file not exists in VirusTotal.

```

give param same as `vt_batch_async_report ()`.

return list of Report(), which only have msg, not contains scans which is vendor's results.

### scan

```python
vt_scan(...)
vt_scan_from_fullpath(...)
vt_batch_async_scan(...)

upload file to VirusTotal.

``` 
give list of `{'md5': , 'file_content': <file binary content> or <file open handler> , 'file_name':<optional>}` 

return list of Report(), which only have msg, not contains scans which is vendor's results.