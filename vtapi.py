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


from __future__ import print_function

import six
from io_in_out import *

# todo add key here
# VirusTotal_API_Key = ''
from vtapi_key import VirusTotal_API_Key

VirusTotal_Url_Base = u'https://www.virustotal.com/vtapi/v2/file'
VirusTotal_Proxy = None


def _vt_make_request_param(resource):
    '''
    use in report and rescan
    :param resource: 
    :return: 
    '''
    return {u'apikey': VirusTotal_API_Key,
            u'resource': resource}


def vt_make_request_report(anything):
    '''
    support batch (max 4 )
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
    # todo with anything
    resource_hash = anything

    params = _vt_make_request_param(resource_hash)
    url = VirusTotal_Url_Base + u'/report'

    # only method url is not requests param, others is requests params
    return {u'method': u'get',
            u'url': url,
            u'params': params,
            u'timeout': 8,
            u'proxies': VirusTotal_Proxy,
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
    # todo with anything
    resource_hash = anything

    params = _vt_make_request_param(resource_hash)
    url = VirusTotal_Url_Base + u'/rescan'
    return {u'method': u'post',
            u'url': url,
            u'params': params,
            u'timeout': 5,
            u'proxies': VirusTotal_Proxy,
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
    params = {u'apikey': VirusTotal_API_Key}
    files = {u'file': (file_name, file_content)}
    url = VirusTotal_Url_Base + u'/scan'
    return {u'method': u'post',
            u'url': url,
            u'params': params,
            u'files': files,
            u'timeout': 20,
            u'proxies': VirusTotal_Proxy,
            }


def _vt_filter_valid_resources(hashs):
    import re
    _SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{64}-[0-9]{10}$")
    return filter(lambda e: io_simple_check_hash(e) or _SCAN_ID_RE.match(e), hashs)


def vt_make_resource_from_hashs(hashs):
    '''
    从 tuple 或者 list 的 hash 集合中获取 resource
    :param hashs: 
    :return:  valid resource or None
    
    VirusTotal says :
     You can also specify a CSV list made up of a combination of hashes and scan_ids 
     (up to 4 items with the standard request rate),
      this allows you to perform a batch request with one single call.
    
    '''
    if not hashs:
        return None
    valid_hashs = _vt_filter_valid_resources(hashs)
    if valid_hashs:
        return u','.join(valid_hashs)
    return None


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

    # when retry, we cannot use pop, we have to save req
    # req_dup = copy.deepcopy(req) # file handle cannot use deepcopy
    res = requests.request(req.pop(u'method',u'get'), req.pop(u'url'), **req)
    if res.status_code == 200 and res.content:
        return (res.content)
    return None

def _vt_request_retry(req, request_retry=1):
    import requests
    er = None
    for _ in range(0,request_retry):
        back_keys = [u'method', u'url']
        back = {key: req.get(key, None) for key in back_keys}
        try:
            return _vt_default_request(req)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout,
                requests.exceptions.SSLError) as er:
            req.update(back)
    return er

def vt_report_from_resource(resource):
    '''
    :param resource: 
    :return: raw content from VirusTotal.com request 
    '''
    if not resource:
        return None
    req = vt_make_request_report(resource)
    return _vt_request_retry(req,request_retry=3)


def vt_rescan_from_resource(resource):
    '''
    :param resource: 
    :return:  raw content from VirusTotal.com request  / None
    '''
    req = vt_make_request_rescan(resource)
    return _vt_default_request(req)


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
    return _vt_request_retry(req,request_retry=3)


def vt_scan_from_fullpath(fullpath, fake_name=None):
    '''
    use in thread pool
    '''
    with open(fullpath,'rb') as fh:
        return Report.dispatch_report(vt_scan(fh,fake_name if fake_name else os.path.basename(fullpath)))


def vt_batch_sync_report(hashs, split_unit_count=15):
    '''
    :param hashs: 
    :param split_unit_count: 
    :return:  list of Report()
    '''
    return_reports = []

    _fn = lambda x, y: y(x) if x else None

    for ev in io_iter_split_step(data=hashs, split_unit_count=split_unit_count):
        reduce(_fn, [ev,
                     vt_make_resource_from_hashs,
                     vt_report_from_resource,
                     Report.dispatch_report,
                     return_reports.extend])
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


def _grequests_map_retry(requests, size=None, gtimeout=None):
    import grequests
    ret = []

    this_requests = requests
    while len(ret) < len(requests):
        collector = ExceptionRequestsCollector()
        responses = grequests.map(this_requests, size=size, exception_handler=collector._grequests_exception_handler,
                                  gtimeout=gtimeout)
        ret.extend(filter(lambda e: True if e else False, responses))
        exception_requests = collector.exception_requests
        if len(exception_requests) == len(this_requests):
            # all fail
            break
        this_requests = exception_requests
    return ret

def _vt_batch_asnyc_framework_noretry(resources,
                                      pfn_resource_to_request,
                                      split_unit_count,
                                      grequests_pool_size):
    '''
    use by report or rescan
    :param hashs:  must be isinstance(data, collections.Iterable):
    :return: list of Report()
    '''
    import grequests

    reqs = []
    for ev in io_iter_split_step(data=resources, split_unit_count=split_unit_count):
        e = vt_make_resource_from_hashs(ev)
        if e:
            req = pfn_resource_to_request(e)
            q = grequests.request(req.pop(u'method'), req.pop(u'url'), **req)
            reqs.append(q)

    responses = _grequests_map_retry(reqs, size=grequests_pool_size, gtimeout=20)
    return_reports = []
    for e in responses:
        if e and e.status_code == 200 and e.content:
            v = Report.dispatch_report(e.content)
            return_reports.extend(v)
    return return_reports


def _vt_batch_async_framework(hashs, pfn_resource_to_request,
                              split_unit_count,
                              retry_times,
                              grequests_pool_size):
    '''
    user by report or rescan
    
    :param hashs:  outer make sure not duplicate
        MD5, SHA1, SHA256, 
        vt_scan_id (sha256-timestamp as returned by the file upload API)
    :return: list of Report() 
    '''
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


def vt_batch_async_report(hashs,**kwargs):
    '''
    :param hashs:  resources to get vt report
    :param if_analyzing_wait:  if report is tell analyzing, then get the report again util it not analyzing
    :param split_unit_count: every report's resource count
    :return:  list of Report()
    '''
    import time
    from functools import partial

    # currying the function _vt_batch_async_framework()
    _small_func = partial(_vt_batch_async_framework,
                          pfn_resource_to_request=vt_make_request_report,
                          split_unit_count=kwargs.get(u'request_tasks',15),
                          grequests_pool_size=kwargs.get(u'grequests_pool_size',4),
                          retry_times=0)
    rs = _small_func(hashs)
    start_time = time.clock()
    v =  kwargs.get(u'if_analyzing_wait',False)
    while v:
        # set the time limit
        if int(time.clock() - start_time) > 60 * len(hashs):
            break
        analyzing_reports = filter(lambda e: e.analyzing, rs)
        analyzing_md5s = [e[u'md5'] for e in analyzing_reports]
        if analyzing_md5s:
            rs = filter(lambda e: not e.analyzing, rs)
            time.sleep(4)
            rs.extend(_small_func(analyzing_md5s))
        else:
            break  # no more to get report
    return rs


def vt_batch_async_rescan(hashs, split_unit_count=15):
    '''
    rescan the file exists in VirusTotal.com
    
    use Report(<request.content>).file_not_exists to detect the file if is exists in VirusTotal.com, 
      then can use scan to upload
    
    :param hashs: 
    :param split_unit_count: 
    :return:  list of Report()
    '''
    return _vt_batch_async_framework(hashs,
                                     pfn_resource_to_request=vt_make_request_rescan,
                                     split_unit_count=split_unit_count,
                                     retry_times=0,
                                     grequests_pool_size=4)


def _vt_batch_asnyc_scan_noretry(resources):
    '''
    helper functions
    '''
    import grequests

    reqs = []
    for ev in resources:
        fc = ev[u'file_content']
        fn = ev[u'file_name'] if u'file_name' in ev else None
        if fn:
            req = vt_make_request_scan(file_content=fc, file_name=fn)
        else:
            req = vt_make_request_scan(file_content=fc)
        q = grequests.request(req.pop(u'method'), req.pop(u'url'), **req)
        reqs.append(q)

    responses = _grequests_map_retry(reqs, size=8)
    return_reports = []
    for e in responses:
        if e and e.status_code == 200 and e.content:
            v = Report.dispatch_report(e.content)
            return_reports.extend(v)
    return return_reports


def vt_batch_async_scan(pairs):
    '''
    :param pairs: [
        {'file_content': <file binary content or file open handler> , 'file_name':<optional>, 'md5': }:, ...
        ]
    :return:  list of Report()
    
    刚上传成功后， get report ，也可能会有 file not exists, 手动去网站查询，是可以查询到的
    
    '''
    _pairs_to_md5_set = lambda p: set(e[u'md5'] for e in p)
    _md5_set_to_pairs = lambda md5s, p: filter(lambda e: e[u'md5'] in md5s, p)
    _reports_md5_to_set = lambda reports: set(e[u'md5'] for e in reports)

    return_reports = []

    i = 0
    retry_times = 0  # 50 # 5 次都少
    all_md5s = _pairs_to_md5_set(pairs)
    ok_md5s = set()
    while len(return_reports) < len(pairs):
        fail_md5s = all_md5s - ok_md5s
        if not fail_md5s:
            break
        r2 = _vt_batch_asnyc_scan_noretry(_md5_set_to_pairs(fail_md5s, pairs))
        if not r2 and len(fail_md5s) > 5:
            break  # we think the network is not available
        # 使用增量计算
        ok_md5s = _reports_md5_to_set(r2)
        all_md5s = fail_md5s
        return_reports.extend(r2)
        i += 1
    return return_reports


def vt_batch_async_scan_fullpath(datas):
    '''
    :param datas:  list of dict 
         [
              {u'fullpath': , } , {u'md5': }, 
        ] 
    :return: 
    '''

    # dict 的 update() 返回 None , 继续 or e ，那么会返回 e ，方便把更新过的 dict 收集到 list 中
    _add_file_content = lambda e: e.update({u'file_content':
                                                open(e[six.binary_type(u'fullpath')], six.binary_type(u'rb'))
                                            }) or e

    for ev in io_iter_split_step(datas, 20):
        ev = map(_add_file_content, ev)
        vt_batch_async_scan(ev)


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
