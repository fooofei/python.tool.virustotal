# coding=utf-8

'''

 The project is aimed to use grequests wrap VirusTotal.com API ,
   but the testing is not optimistic.


* not handle requests time out
* not handle limit size of upload file
* not handle exceptions
* not pre testing the VirusTotal.com is can connect, if we querying lots of files one time, such as 10w,
    then every request will cost much time, and fail
* not finished
 
 profile testing ：
    grequests is faster  20%~30%  than requests , but more failure
    
    testing get reports of 30 files, every request query 1 file, cost time: 
      grequests 22.095 (with retry faild requests)  
      requests 28.39
 
 
 2017_05_03 test query  5000 files ， grequests not have any advantage，more slower than requests ，even not know the reason.
     testing framework: grequests + thread pool ,  grequests 
'''

# ------------------------------------------------------------------------------
# CHANGELOG:
# 2017-04-29 v1.00 fooofei: use grequests to wrap virustotal api
# 2017-05-03 v1.01 fooofei: grequests retry
# 2017-05-05 v1.10 fooofei: give sync version of scan API to normal use
# 2017-05-09 v1.11 fooofei: fix requests param bug
# 2017-05-11 v1.20 fooofei: add vt search
# 2017-05-12 v2.00 fooofei: 增加 API 后需要调整结构


from __future__ import print_function

import six
from io_in_out import *

# todo add key here
# VirusTotal_API_Key = ''
from vtapi_key import VirusTotal_API_Key

VirusTotal_Url_Base = u'https://www.virustotal.com/vtapi/v2/file'

VirusTotal_Per_Report_Count = 20  # default 20
VirusTotal_Per_Rescan_Count = 4  # default 4
VirusTotal_Per_Scan_Count = 1  # must 1
VirusTotal_Per_Download_Count = 1  # must 1


def _vt_make_key():
    return {u'apikey': VirusTotal_API_Key}


def vt_make_request_report(anything):
    '''
    VirusTotal.com says support batch (max 4 )
    :param anything: 
    :return: 

    success :

            { 'md5': ,
              'scan_id':,
              'resource':,
              ...
              'scans':{
                        'Baidu':{
                                    'detected': <bool>,
                                    'result': <str_vname>,
                                    'update': <str_date>,
                                    'version': <str_number>
                                }
                        ...
                       }
            }


    file not exists:
        {"response_code": 0, 
        "resource": "b0f6d5758c76762233c29b74094cecd7", 
        "verbose_msg": "The requested resource is not among the finished, queued or pending scans"}

    ',' :
        return []

     '''
    if not anything:
        return None
    # todo with anything
    resource_hash = anything

    params = _vt_make_key()
    params.update({u'resource': resource_hash})
    url = VirusTotal_Url_Base + u'/report'

    # only method url is not requests param, others is requests params
    return {u'method': u'get',
            u'url': url,
            u'request_retry': 3,
            u'requests_kwargs': {
                u'params': params,
                u'timeout': 8,
                u'proxies': VirusTotal_Proxy,
            }
            }


def vt_make_request_rescan(anything):
    '''
    support batch 
    :param anything: 
    :return: 

    response like:

        {"permalink": "https://www.virustotal.com/file/76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c/analysis/1493342667/", 
        "response_code": 1, 
        "sha256": "76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c", 
        "resource": "3fdb88cb17f320b55a372ecf09e3e4c5", 
        "scan_id": "76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c-1493342667"
        }

    file not exists:
      {"response_code": 0, "resource": "b0f6d5758c76762233c29b74094cecd7"}

    '''
    if not anything:
        return None
    # todo with anything
    resource_hash = anything

    params = _vt_make_key()
    params.update({u'resource': resource_hash})
    url = VirusTotal_Url_Base + u'/rescan'
    return {u'method': u'post',
            u'url': url,
            u'request_retry': 3,
            u'requests_kwargs': {
                u'params': params,
                u'timeout': 5,
                u'proxies': VirusTotal_Proxy,
            }
            }


def vt_make_request_scan(file_content, file_name=u'file_from_pyvirustotal_make_request'):
    '''
    :param file_content: 
    :param file_name:  can be fake name
    :return: 
    
    success:
        {"scan_id": "832ee70cffeeaa5ec6c55df3a7bbf0e5110a608c7b080907ff94d79a9d5b1573-1493347340", 
        "sha1": "31a3ae809755bc6fc85f4c27901f49259c19fc8b", 
        "resource": "832ee70cffeeaa5ec6c55df3a7bbf0e5110a608c7b080907ff94d79a9d5b1573", 
        "response_code": 1, 
        "sha256": "832ee70cffeeaa5ec6c55df3a7bbf0e5110a608c7b080907ff94d79a9d5b1573", 
        "permalink": "https://www.virustotal.com/file/832ee70cffeeaa5ec6c55df3a7bbf0e5110a608c7b080907ff94d79a9d5b1573/analysis/1493347340/", 
        "md5": "2443d6a0cfe56209c869bb0b4bb16c5d", 
        "verbose_msg": 
        "Scan request successfully queued, come back later for the report"
        }
    
    '''
    if not file_content:
        return None
    params = _vt_make_key()
    files = {u'file': (file_name, file_content)}
    url = VirusTotal_Url_Base + u'/scan'
    return {u'method': u'post',
            u'url': url,
            u'request_retry': 2,
            u'requests_kwargs': {
                u'params': params,
                u'files': files,
                u'timeout': 20,
                u'proxies': VirusTotal_Proxy,
            }
            }


def vt_make_request_search(search_modifier, page_offset):
    '''
    :param search_modifier:  search keywords, can contains blank
    :param page_offset: None or return by VirusTotal.com
    :return: 
    '''

    # url = VirusTotal_Url_Base + u'/search'
    url = u'https://www.virustotal.com/intelligence/search/programmatic/'
    params = _vt_make_key()
    params.update({u'page': page_offset or u'undefined', u'query': search_modifier})

    return {
        u'method': u'post',
        u'url': url,
        u'request_retry': 3,
        u'requests_kwargs': {
            u'params': params,
            u'timeout': 20,
            u'proxies': VirusTotal_Proxy,
        }

    }


def vt_make_request_download(hashvar):
    if not hashvar:
        return None
    url = VirusTotal_Url_Base + u'/download'
    # only for personal key
    # url = u'https://www.virustotal.com/intelligence/download/'
    params = _vt_make_key()
    params.update({u'hash': hashvar})
    return {u'method': u'get',
            u'url': url,
            u'request_retry': 4,
            u'requests_kwargs': {
                u'params': params,
                u'timeout': 20,
                u'proxies': VirusTotal_Proxy,
            }
            }


def _vt_filter_valid_resources(hashes):
    import re
    if not hashes:
        return []
    _SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{64}-[0-9]{10}$")
    return filter(lambda e: io_simple_check_hash(e) or _SCAN_ID_RE.match(e), hashes)


def vt_make_resource_from_hashs(hashs):
    '''
    从 tuple 或者 list 的 hash 集合中获取 resource
    :param hashs: 
    :return:  valid resource 
    
    VirusTotal says :
     You can also specify a CSV list made up of a combination of hashes and scan_ids 
     (up to 4 items with the standard request rate),
      this allows you to perform a batch request with one single call.
    
    '''
    if not hashs:
        return u''
    valid_hashs = _vt_filter_valid_resources(hashs)
    if valid_hashs:
        return u','.join(valid_hashs)
    return u''


class VtApiError(ValueError):
    pass


class JsonReport(object):
    def __init__(self, r):
        import json

        if not r:
            raise VtApiError(u'result is None')

        if isinstance(r, six.string_types):
            try:
                self._report = json.loads(r)
            except ValueError as er:
                raise VtApiError(repr(er))

        elif isinstance(r, dict):
            self._report = r
        else:
            raise VtApiError(u'report not support type {0}'.format(type(r)))

        if not self._report:
            raise VtApiError(u'report is {0}'.format(self._report))
        if not isinstance(self._report, dict):
            raise VtApiError(u'report is not dict, check your submit')

    def __getitem__(self, item):
        attr = {
            u'id': u'resource'
        }.get(item, item)

        if attr == u'md5' and attr not in self._report:
            attr = u'resource'

            v = self._report.get(attr, None)
            # return v or None
            return v and io_simple_check_md5(v) and v or None
        if attr == u'state':
            return self.state
        return self._report.get(attr, None)

    def __eq__(self, other):
        return self._report.__eq__(other._report)

    def __ne__(self, other):
        return self._report.__ne__(other._report)

    def __str__(self):
        v = []
        v.append(u'md5 - {0} ({1})'.format(
            self[u'md5'],
            self.state,
        ))
        if u'verbose_msg' in self._report:
            x = u'verbose_msg -- {0}'.format(self[u'verbose_msg'])
            v.append(x)
        v.append(self._report)
        return u'\n\t'.join(map(six.text_type, v))

    def __repr__(self):
        return u'<JsonReport md5 - {0} ({1})>'.format(
            self[u'md5'],
            self.state,
        )

    @property
    def state(self):
        return {
            -2: u"analyzing",
            1: u"ok",
            0: u"file not exists",
        }.get(self.response_code, u"unknown {0}".format(self.response_code))

    @property
    def response_code(self):
        return self[u'response_code']

    @property
    def ok(self):
        return self.response_code == 1

    @property
    def file_not_exists(self):
        return self.response_code == 0

    @property
    def analyzing(self):
        return self.response_code == -2


class Report(JsonReport):
    '''
    pre use 
    if Report(r).ok :
    to detect the report if is valid.
    '''
    # can be read by outside
    reliable_vendors = [u'BitDefender', u'Kaspersky', u'ESET-NOD32', u'Avira', u'Microsoft', u'McAfee']
    careful_vendors = []
    careful_vendors.extend(reliable_vendors)
    careful_vendors.extend(
        [u'Avast', u'AVG', u'McAfee-GW-Edition', u'Kingsoft', u'Jiangmin', u'Baidu', u'Rising', u'Tencent',
         u'Qihoo-360']
    )

    def __init__(self, r):
        JsonReport.__init__(self, r)

    def __getitem__(self, item):
        if item == u'detect_rate':
            return self.detect_rate()
        return JsonReport.__getitem__(self, item)

    def __str__(self):
        if not self.ok:
            return JsonReport.__str__(self)
        r = self.default_report()
        r = map(lambda row_pair: map(six.text_type, row_pair), r)
        row_pair_format = lambda e: u'{0:>18} -- {1}'.format(e[0], e[1])
        y = [u'md5 - {0} ({1})'.format(
            self[u'md5'],
            self.state,
        )]
        y.extend(map(row_pair_format, r))
        return u'\n'.join(y)

    def get_vendor(self, vendor):
        '''
        :return:  vendor result / None
        '''
        v = self[u'scans']
        return v and v.get(vendor, None) or None

    @staticmethod
    def report_vendor_detect(vendor_report):
        return vendor_report and vendor_report[u'detected'] or None

    @staticmethod
    def report_vendor_vname(vendor_report):
        return vendor_report and vendor_report[u'result'] or None

    def vendor_detect(self, vendor):
        '''
        :return: True False None
        '''
        v = self.get_vendor(vendor)
        return self.report_vendor_detect(v)

    def vendor_vname(self, vendor):
        v = self.get_vendor(vendor)
        return self.report_vendor_vname(v)

    def first_positive(self):
        scans = self[u'scans']
        if scans and isinstance(scans, dict):
            for k, v in scans.items():
                if self.report_vendor_detect(v):
                    return (k, self.report_vendor_vname(v))
        return (None, None)

    def first_reliable_positive(self):
        for vendor in self.reliable_vendors:
            if self.vendor_detect(vendor):
                return (vendor, self.vendor_vname(vendor))
        return (None, None)

    def simple_report(self):
        header = [u'md5', u'state', u'detect_rate', u'scan_date']
        return [(e, self[e]) for e in header]

    def default_report(self):
        header = [u'state', u'md5', u'sha1', u'sha256', u'detect_rate', u'scan_date']
        r = []
        for e in header:
            r.append((e, self[e]))
        r.append((u'', u''))
        for vendor in self.careful_vendors:
            r.append((vendor, self.vendor_vname(vendor)))
        return r

    def all_report(self):
        header = [u'md5', u'detect_rate', u'scan_date']
        r = []
        for e in header:
            r.append((e, self[e]))
        r.append((u'', u''))
        scans = self[u'scans']
        if scans and isinstance(scans, dict):
            for k, v in scans.items():
                r.append((k, self.report_vendor_vname(v)))
        return r

    def scan_report(self):
        header= [u'md5',u'scan_id',u'permalink',u'verbose_msg']
        return [(e, self[e]) for e in header]

    def positives(self):
        return self[u'positives']

    def detect_rate(self):
        return u'{0}/{1}'.format(self.positives(), self[u'total'])

    @staticmethod
    def dispatch_report(r):
        '''
        receive report , maybe multi or single
        :param r: 
        :return: []
        '''
        if not r :
            return None
        import json
        try:
            t = []
            # fn = lambda e: Report(e) if u'scans' in e else JsonReport(e)
            fn = lambda e: Report(e)
            rs = json.loads(r)
            if isinstance(rs, list):
                t.extend(map(fn, rs))
            elif isinstance(rs, dict):
                t.append(fn(rs))
            else:
                raise VtApiError(u'not support type {0} \n{1}'.format(type(rs), rs))
            return t
        except ValueError as er:
            raise VtApiError(repr(er))


def _vt_report_resources_to_set(reports):
    # resource can be md5 or others
    return set(e[u'resource'] for e in reports)


def _vt_default_request(req):
    import requests
    if not req:
        return None
    res = requests.request(req.get(u'method', u'get')
                           , req.get(u'url')
                           , **req.get(u'requests_kwargs'))
    if res.status_code == 200 and res.content:
        return (res.content)
    return None


def _vt_default_request_retry(req):
    import requests
    from requests import sessions
    if not req:
        return None
    er = None
    request_retry = req.get(u'request_retry', 1)
    with sessions.Session() as ses:
        for _ in range(request_retry):
            try:
                r = ses.request(method=req.get(u'method', u'get')
                                , url=req.get(u'url')
                                , **req.get(u'requests_kwargs'))
                return r.content if r.status_code == 200 and r.content else None
            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout,
                    requests.exceptions.SSLError) as er:
                pass
    raise er


def vt_report_from_resource(resource):
    '''
    :param resource: 
    :return: raw content from VirusTotal.com request 
    '''
    req = vt_make_request_report(resource)
    return _vt_default_request_retry(req)


def vt_rescan_from_resource(resource):
    '''
    :param resource: 
    :return:  raw content from VirusTotal.com request  / None
    '''
    req = vt_make_request_rescan(resource)
    return _vt_default_request_retry(req)


def vt_scan(file_content, file_name):
    '''
    
    :param file_content: file binary content
    :param file_name: <optional>
    :return:  raw content from VirusTotal.com request / None
    '''
    q = {u'file_content': file_content}
    if file_name:
        q[u'file_name'] = file_name
    req = vt_make_request_scan(**q)
    return _vt_default_request_retry(req)


def vt_scan_from_fullpath(fullpath, fake_name=None):
    '''
    use in thread pool
    '''
    with open(fullpath, 'rb') as fh:
        return Report.dispatch_report(vt_scan(fh, fake_name if fake_name else os.path.basename(fullpath)))


def vt_search(search_modifier):
    '''
    :param search_modifier: 
    :return: generator object, per page 25 count
    '''
    import json
    page_offset = None

    while True:
        r = _vt_default_request_retry(vt_make_request_search(search_modifier=search_modifier,
                                                             page_offset=page_offset))
        if not r:
            raise StopIteration
        try:
            resp_dict = json.loads(r)
            if not (resp_dict.get(u'result', 0) == 1):
                raise ValueError(resp_dict.get(u'error', u''))
            # every page 25 count
            h = resp_dict.get(u'hashes', [])
            if not h:
                raise StopIteration
            yield h
            page_offset = resp_dict.get(u'next_page', None)
            # len(page_offset) = 1500
            if not page_offset:  # no more hashes
                raise StopIteration
        except ValueError:
            raise StopIteration


def vt_batch_sync_report(hashs):
    '''
    :param hashs: 
    :return:  list of Report()
    '''
    return_reports = []
    func_reports_extend = lambda r: return_reports.extend(r) if r else None

    for ev in io_iter_split_step(data=hashs, split_unit_count=VirusTotal_Per_Report_Count):
        x = vt_make_resource_from_hashs(ev)  # hashes list -> '<hash1>,<hash2>,<...>'
        x = vt_report_from_resource(x)  # -> return from VirusTotal.com raw content
        x = Report.dispatch_report(x)  # -> list of Report
        func_reports_extend(x)
    return return_reports


class ExceptionRequestsCollector(object):
    def __init__(self):
        self.exception_requests = []

    def _grequests_exception_handler(self, request, exception):
        '''
        errors 
        
            ("bad handshake: SysCallError(-1, 'Unexpected EOF')",)
        '''
        self.exception_requests.append(request)
        io_stderr_print(exception)
        io_stderr_print(request.kwargs.items())


def _grequests_map_retry(requests, size=None, gtimeout=None):
    import grequests
    ret = []

    this_requests = requests

    while len(ret) < len(requests):
        collector = ExceptionRequestsCollector()
        responses = grequests.map(this_requests, size=size, exception_handler=collector._grequests_exception_handler,
                                  gtimeout=gtimeout)
        valid_responses = filter(lambda e: True if e else False, responses)
        ret.extend(valid_responses)
        exception_requests = collector.exception_requests
        if len(exception_requests) == len(this_requests):
            # all fail
            break
        this_requests = exception_requests
    return ret


def _vt_batch_async_framework(datas
                              , pfns_datas_to_requests_param
                              , split_unit_count
                              , grequests_pool_size):
    '''
    use by report or rescan
    :param hashs:  must be isinstance(data, collections.Iterable):
          caller make sure not duplicate
            MD5, SHA1, SHA256, 
            vt_scan_id (sha256-timestamp as returned by the file upload API)
    :return: list of grequests responses
    
    retry version backup :
        hashs = _vt_filter_valid_resources(hashs)
        return_reports = []
    
        i = 0
        retry_times += 1  #  not more need, we retry in  _grequests_map_retry()
        all_resources = set(hashs)
        ok_resources = set()
        while len(return_reports) < len(hashs) and i < retry_times:
            fail_resources = all_resources - ok_resources
            if not fail_resources:
                break
            r2 = _vt_batch_asnyc_framework_noretry(fail_resources,
                                                   pfn_resource_to_request=pfn_resource_to_request,
                                                   split_unit_count=split_unit_count,
                                                   grequests_pool_size=grequests_pool_size)
    
            if not r2 and len(fail_resources) / split_unit_count > 10:
                break  # 10 次(不一定是 10 个)都查询失败了，应该是断网了
    
            # 使用增量计算
            ok_resources = _vt_report_resources_to_set(r2)
            all_resources = fail_resources
            return_reports.extend(r2)
            i += 1
    
        return return_reports
    
    '''
    import grequests

    if not datas:
        return []

    reqs = []

    func_req_make_request = lambda req: grequests.request(req.get(u'method'), req.get(u'url'),
                                                          **req.get(u'requests_kwargs')) if req else None

    func_request_append = lambda q: reqs.append(q) if q else None

    for ev in io_iter_split_step(data=datas, split_unit_count=split_unit_count):
        x = pfns_datas_to_requests_param(ev)
        x = func_req_make_request(x)
        func_request_append(x)
    return _grequests_map_retry(reqs, size=grequests_pool_size, gtimeout=20)


def _vt_responses_to_reports(responses):
    return_reports = []
    for e in responses:
        if e and e.status_code == 200 and e.content:
            v = Report.dispatch_report(e.content)
            return_reports.extend(v)
    return return_reports


def vt_batch_async_report(hashes, **kwargs):
    '''
    :param hashes:   resources to get vt report
    :param kwargs: 
        request_tasks(split_unit_count): int 
        grequests_pool_size: int
        if_analyzing_wait: bool, if report is tell analyzing, then get the report again util it not analyzing
    :return: list of Report()
    '''
    import time
    from functools import partial

    pfns_datas_to_requests_param = \
        lambda e: vt_make_request_report(vt_make_resource_from_hashs(_vt_filter_valid_resources(e)))

    # currying the function _vt_batch_async_framework()
    _small_func = partial(_vt_batch_async_framework
                          , pfns_datas_to_requests_param=pfns_datas_to_requests_param
                          , split_unit_count=kwargs.get(u'request_tasks', VirusTotal_Per_Report_Count)
                          , grequests_pool_size=kwargs.get(u'grequests_pool_size', 4))

    _hashes_to_reports = lambda h: _vt_responses_to_reports(_small_func(h))

    rs = _hashes_to_reports(hashes)
    start_time = time.clock()
    v = kwargs.get(u'if_analyzing_wait', False)
    while v:
        # set the time limit
        if int(time.clock() - start_time) > 60 * len(hashes):
            break
        analyzing_reports = filter(lambda e: e.analyzing, rs)
        analyzing_md5s = [e[u'md5'] for e in analyzing_reports]
        if analyzing_md5s:
            rs = filter(lambda e: not e.analyzing, rs)
            time.sleep(4)
            rs.extend(_hashes_to_reports(analyzing_md5s))
        else:
            break  # no more to get report
    return rs


def vt_batch_async_rescan(hashes, **kwargs):
    '''
    rescan the file exists in VirusTotal.com
    
    use Report(<request.content>).file_not_exists to detect the file if is exists in VirusTotal.com, 
      then can use scan to upload
    
    :param hashes: 
    :param kwargs: 
        request_tasks(split_unit_count): int 
        grequests_pool_size: int
    :return:  list of Report()
    '''

    pfns_datas_to_requests_param = \
        lambda e: vt_make_request_rescan(vt_make_resource_from_hashs(_vt_filter_valid_resources(e)))

    v = _vt_batch_async_framework(hashes
                                  , pfns_datas_to_requests_param=pfns_datas_to_requests_param
                                  , split_unit_count=kwargs.get(u'request_tasks', VirusTotal_Per_Rescan_Count)
                                  , grequests_pool_size=kwargs.get(u'grequests_pool_size', 4))
    return _vt_responses_to_reports(v)


def vt_batch_async_scan(pairs, **kwargs):
    '''
    :param pairs: 
        [
            {'file_content': <file binary content or file open handler> , 'file_name':<optional>, 'md5': }:, ...
        ]
    :param kwargs: 
        grequests_pool_size: int
    :return:  list of Report()
    
    刚上传成功后， get report ，也可能会有 file not exists, 手动去网站查询，是可以查询到的
    
    '''

    def _datas_to_request_scan_param(pps):
        if not pps:
            return None
        assert (len(pps) == 1)
        ev = pps[0]
        fc = ev[u'file_content']
        fn = ev[u'file_name'] if u'file_name' in ev else None
        if fn:
            return vt_make_request_scan(file_content=fc, file_name=fn)
        else:
            return vt_make_request_scan(file_content=fc)

    v = _vt_batch_async_framework(pairs
                                  , pfns_datas_to_requests_param=_datas_to_request_scan_param
                                  , split_unit_count=VirusTotal_Per_Scan_Count
                                  , grequests_pool_size=kwargs.get(u'grequests_pool_size', 4))
    return _vt_responses_to_reports(v)


def vt_batch_async_scan_fullpath(datas):
    '''
    :param datas:  list of dict 
         [
              {u'fullpath': , } , {u'md5': }, 
        ] 
    :return: list of Reports
    '''

    # dict 的 update() 返回 None , 继续 or e ，那么会返回 e ，方便把更新过的 dict 收集到 list 中
    _add_file_content = lambda e: e.update({u'file_content': open(e[u'fullpath'], 'rb')
                                            }) or e
    r = []
    for ev in io_iter_split_step(datas, 20):
        ev = map(_add_file_content, ev)
        v = vt_batch_async_scan(ev)
        r.extend(v)
    return r


def vt_batch_async_report_fullpath(datas_list, force_rescan=False, upload_vt_not_exists=True):
    '''
    把查询结果填充到 datas 里
    如果查询的文件不在 vt 就从 fullpath 里上传文件扫描，然后取结果
    外部调用一次传入不要太多，一次 1000 够了，分批次进行
            
    :param datas: list of dict 
            [
              {u'fullpath': , } , {u'md5': }, 
            ] 
    :return:  list of Report()
    '''

    _reports_md5_to_set = lambda reports: set(e[u'md5'] for e in reports)
    _md5_set_to_datas_list = lambda md5s, datas_dict: [datas_dict[e] for e in md5s]
    _reports_list_to_dict = lambda reports: {e[u'md5']: e for e in reports}

    datas_dict = {e[u'md5']: e for e in datas_list}
    md5s_all = set(e[u'md5'] for e in datas_list)

    reports_all = vt_batch_async_report(md5s_all, if_analyzing_wait=True)

    reports_part_rescan = []
    reports_part_upload = []

    if force_rescan:
        # 可以优化这里， 使用 rescan 之后的马上 get report 还是上次的结果，也不会告诉说正在 analyzing
        # 完全不需要再次 get report
        reports_vt_exists = filter(lambda e: not e.file_not_exists, reports_all)
        md5s_vt_exists = _reports_md5_to_set(reports_vt_exists)
        vt_batch_async_rescan(md5s_vt_exists)
        reports_part_rescan = vt_batch_async_report(md5s_vt_exists, if_analyzing_wait=True)
        if not upload_vt_not_exists:
            reports_part_upload = filter(lambda e: e.file_not_exists, reports_all)

    if upload_vt_not_exists:
        reports_vt_not_exists = filter(lambda e: e.file_not_exists, reports_all)
        md5s_vt_not_exists = _reports_md5_to_set(reports_vt_not_exists)
        datas_list_vt_not_exists = _md5_set_to_datas_list(md5s_vt_not_exists, datas_dict)

        # sys.stderr.write(u'\t get {} not exits\n'.format(len(md5s_vt_not_exists)))

        vt_batch_async_scan_fullpath(datas_list_vt_not_exists)
        reports_part_upload = vt_batch_async_report(md5s_vt_not_exists, if_analyzing_wait=True)

        if not force_rescan:
            reports_part_rescan = filter(lambda e: not e.file_not_exists, reports_all)

    if force_rescan or upload_vt_not_exists:
        reports_all = reports_part_rescan + reports_part_upload

    # Report()s puts to datas

    reports_all_dict = _reports_list_to_dict(reports_all)
    for e in datas_list:
        e.update({u'report': reports_all_dict[e[u'md5']]})

    return reports_all


def vt_batch_async_download(path_save_dir, hashes, **kwargs):
    pfns_datas_to_requests_param = lambda e: vt_make_request_download(e[0]) if e else None
    v = _vt_batch_async_framework(hashes
                                  , pfns_datas_to_requests_param=pfns_datas_to_requests_param
                                  , split_unit_count=VirusTotal_Per_Download_Count

                                  # 8 的时候 总有 2 个 ("bad handshake: SysCallError(-1, 'Unexpected EOF')",) 错误
                                  # 也不是固定的 2 个 hash 错误， 但一定是固定的 2 个
                                  , grequests_pool_size=kwargs.get(u'grequests_pool_size', 6))
    #
    # not find a way to save hash with Requests, use it to check Response valid
    #
    for e in v:
        con = e.content
        m = io_hash_memory(con)
        p = os.path.join(path_save_dir, u'{0}'.format(m))
        if os.path.exists(p):
            os.remove(p)
        with open(p, 'wb') as f:
            f.write(con)


def vt_check_reports_equal(r_new, r_old):
    r_new_dict = {e[u'resource']: e for e in r_new}
    r_old_dict = {e[u'resource']: e for e in r_old}
    if r_new_dict != r_old_dict:
        print(u'error not equal new len {} old len {}'.format(len(r_new), len(r_old)))
        for e in r_new:
            e_res = e[u'resource']
            if e_res not in r_old_dict:
                print(u'\t{} not in old'.format(e))
            elif e != r_old_dict[e_res]:
                print(u'\t new not equal')
                print(u'\t {}'.format(e))
                print(u'\t old')
                print(u'\t {}'.format(r_old_dict[e_res]))

        assert (False)
