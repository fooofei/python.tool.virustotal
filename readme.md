
## ViusTotal Public API 2.0 With grequests


### get reports

```python
vt_batch_async_report(...)
```

give an iterable object, which is a vt resource, can be MD5, SHA1, SHA256, vt_scan_id.

return list of sReport().

use Report().ok to detect report is valid.

### rescan

```python
vt_batch_async_rescan(...)
```

give param same as `vt_batch_async_report ()`.

return list of Report(), which only have msg, not contains scans which is vendor's results.

### scan

```python
vt_batch_async_scan(...)
``` 
give list of `{'md5': , 'file_content': <file binary content> or <file open handler> , 'file_name':<optional>}` 

return list of Report(), which only have msg, not contains scans which is vendor's results.