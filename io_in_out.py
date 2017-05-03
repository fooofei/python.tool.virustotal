# -*- coding: UTF-8 -*-


'''
输入输出函数

其他脚本中的进入的字符串参数和输出到屏幕的字符串参数都需要经过转换
进入的字符串需要转为 unicode （为了支持路径中的中文）
输出到屏幕的字符串需要从 unicode 转为 str （为了兼容重定向符号 > ,某些时候我们需要把脚本运行结果重定向到文件）

兼容 python 2.6, 2.7, 3

scandir.walk  benchmark :

    # 7w files
    for e in io_iter_files_from_arg(sys.argv[1::]) :
        pass
    os.walk - 1.16999983788
    scandir.walk - 0.280000209808

'''

# ------------------------------------------------------------------------------
# feedback : fooofei
# CHANGELOG:
# 2017-02-22 v2.00 修复其他国语言编码异常
# 2017-02-23 v2.10 add io map
# 2017-03-14 v2.20 io_out_arg 增加参数
# 2017-04-28 v2.30 add io_iter_split_step, 一步步取文件，在遇到大量文件的时候，可以指定步长取文件，比如 10000 一次
# 2017-05-02 v2.30 add io_path_format

from __future__ import with_statement
import os
import sys

try:
    from scandir import walk as local_walk
except ImportError:
    from os import walk as local_walk


pyver = sys.version_info[0]  # major
if pyver >= 3:
    io_in_code = str # io 读取时应该转换成为的目标编码
    io_out_code = bytes
    io_raw_input = input
else:
    io_in_code = unicode
    io_out_code = str
    io_raw_input = raw_input
io_str_codes = (io_in_code, io_out_code)


def io_in_arg(arg):
    if not arg:
        return arg
    if isinstance(arg, io_in_code):
        return arg
    codes = ['utf-8', 'gbk']
    for c in codes:
        try:
            return arg.decode(c)
        except UnicodeDecodeError as er:
            pass
    else:
        raise er


def io_bytes_arg(arg):
    '''
    python 与 ctypes 交互也用这个， ctypes 需要 py3 中的 bytes 类型
    :param arg:
    :return:
    '''
    if not arg:
        return arg
    if isinstance(arg, io_in_code):
        codes = ['utf-8', 'gbk']
        for c in codes:
            try:
                return arg.encode(c)
            except UnicodeEncodeError as er:
                pass
        else:
            raise er
    return arg


def io_iter_files_from_arg(args):
    for e in args:
        if os.path.isfile(e):
            yield io_in_arg(e)
        elif os.path.isdir(e):
            e = io_in_arg(e)
            for root, sub, files in local_walk(e):
                for i in files:
                    yield os.path.join(root, i)
    raise StopIteration

def io_iter_root_files_from_arg(args):
    for e in args:
        if os.path.isfile(e):
            yield io_in_arg(e)
        elif os.path.isdir(e):
            e = io_in_arg(e)
            for sub in os.listdir(e):
                p = os.path.join(e,sub)
                yield p
    raise StopIteration

def io_out_arg(arg, default_encoding=sys.stdout.encoding, pfn_check = None):
    '''
    python 脚本内的字符串传递给其他 c 模块时或者输出到屏幕时的编码转换
    :param arg:
    :param default_encoding:
    :param pfn_check: 用来校验转换是否可取，unicode 中文路径，用 utf-8 可以成功转换，但是 os.path.exists() return False,
           所以需要继续使用 gbk 编码转换
    :return:
    '''
    global pyver
    if pyver < 3:
        codes = []
        if default_encoding:
            codes.append(default_encoding)
        codes.extend(['utf-8', 'gbk'])
        er = 'not accept'
        for c in codes:
            try:
                x =  arg.encode(c)
                if pfn_check:
                    try:
                        if not pfn_check(x):
                            continue
                    except Exception as er1:
                        continue
                return x
            except UnicodeEncodeError as er:
                pass
        else:
            raise ValueError(repr(er))
    else:
        return arg


def io_sys_std_err_or_out(writer,arg):
    io_conv_func = lambda e: io_out_arg(e,writer.encoding) if isinstance(e, io_str_codes) else str(e)
    if isinstance(arg, (tuple, list, dict)):
        x = map(io_conv_func, arg)
        arg = '\t'.join(x)
    else:
        arg = io_conv_func(arg)
    r = writer.write(arg)
    writer.flush()
    return r


def io_sys_stdout(arg):
    return io_sys_std_err_or_out(sys.stdout,arg)

def io_sys_stderr(arg):
    return io_sys_std_err_or_out(sys.stderr,arg)

def io_print(arg):
    io_sys_stdout(arg)
    print ('')
    sys.stdout.flush()

def io_stderr_print(arg):
    io_sys_stderr(arg)
    global pyver
    if pyver < 3:
        print >>sys.stderr,''
    else:
        eval('print("",file=sys.stderr)')


def io_files_from_arg(args):
    r = []
    for e in args:
        if os.path.isfile(e):
            r.append(io_in_arg(e))
        elif os.path.isdir(e):
            e = io_in_arg(e)
            for root, sub, files in local_walk(e):
                for i in files:
                    x = os.path.join(root, i)
                    r.append(x)
        else:
            io_print(u'unaccept arg {0}'.format(io_in_arg(e)))
    return r


def io_is_path_valid(pathname):
    '''
    路径是否有效
    http://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta
    :param pathname:
    :return: bool
    '''
    import errno
    ERROR_INVALID_NAME = 123
    try:
        _, pathname = os.path.splitdrive(pathname)
        root_dirname = os.environ.get('HOMEDRIVE', 'C:') if sys.platform == 'win32' else os.path.sep
        root_dirname = root_dirname.rstrip(os.path.sep) + os.path.sep

        for pathname_part in pathname.split(os.path.sep):
            try:
                os.lstat(root_dirname + pathname_part)
            except OSError as exc:
                if hasattr(exc, 'winerror'):
                    if exc.winerror == ERROR_INVALID_NAME:
                        return False
                elif exc.errno in [errno.ENAMETOOLONG, errno.ERANGE]:
                    return False
    except TypeError:
        return False
    else:
        return True

def io_path_format(fullpath,replace_with=None):
    '''
    remove forbidden chars in path
    :param fullpath: 
    :return: 
    '''
    if not isinstance(fullpath,io_in_code):
        raise ValueError(u'only support type {0}'.format(io_in_code))

    windows_path_forbidden_chars = u'\\/*?:"<>|'
    remove_map = dict((ord(char),replace_with if replace_with else None) for char in windows_path_forbidden_chars )
    return fullpath.translate(remove_map)

def io_thread_map(thread_func,thread_data,max_workers=20):
    '''
    等价于 :
        for e in thread_data:
            r = thread_func(e)
    '''

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        r = pool.map(thread_func, thread_data)
        pool.shutdown(wait=True)
        return list(r)

def io_thread_map_one_ins(thread_func,thread_data,ins_generator_func,max_workers=8):
    '''
    等价于 :
        for e in thread_data:
            r = thread_func(ins_generator_func(),e)
    区别于 io_thread_pool : 适用于 1 个线程 1 个实例的情景
    '''
    import threading
    from concurrent.futures import ThreadPoolExecutor

    thread_local_data = threading.local()
    def _func_in_thread(every_thread_data):
        try:
            thread_local_data.ins
        except AttributeError:
            thread_local_data.ins = ins_generator_func()
        return thread_func(thread_local_data.ins,every_thread_data)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        r = pool.map(_func_in_thread, thread_data)
        pool.shutdown(wait=True)
        return list(r)

def dict_item_getter(data, keys):
    '''
      dict_item_getter({'1': {'2': {'3': 'hello'}}}, ['1', '2', '3']) = 'hello'
    '''
    f = lambda x, y: x[y] if y in x else None
    return reduce(f, keys, data)


def io_directory_merge(src,dst):
    '''

    需求 ： 把 sub 目录整体移动到 parent 内，效果为： parent/sub
         如果 parent 目录内已经有 sub 目录，则覆盖合并，已存在的同名文件覆盖


    def unit_test_shutil_copytree():

        不符合需求，此调用要求 parent 目录必须不存在

        import shutil
        parent = r"F:\everysamples\0000\bbs\2\parent"
        sub = r"F:\everysamples\0000\bbs\2\sub"
        shutil.copytree(sub,parent)

    def unit_test_distutils_dir_util():
        from distutils.dir_util import copy_tree,remove_tree
        parent = r"F:\everysamples\0000\bbs\2\parent"
        sub = r"F:\everysamples\0000\bbs\2\sub"

        if not (not os.path.exists(parent) or os.path.isdir(parent)):
            raise ValueError('parent must not exist or is dir')
        copy_tree(src=sub,dst=os.path.join(parent,os.path.basename(sub)))
        remove_tree(directory=sub)
        '''
    from distutils.dir_util import  copy_tree,remove_tree

    if not (not os.path.exists(dst) or os.path.isdir(dst)):
        raise ValueError('parent must not exist or is dir')
    # src must be an exist directory
    # 如果文件存在会自动覆盖
    copy_tree(src=src,dst=os.path.join(dst,os.path.basename(src)))
    remove_tree(directory=src)


def io_hash_stream(stream, hash_algorithm=u'md5',block_size=2 ** 20):
    import hashlib
    hash_ins = {u'md5':hashlib.md5(),
                u'sha1':hashlib.sha1()}.get(hash_algorithm,None)
    if not hash_ins:
        raise ValueError('not get proper hash algorithm')
    while 1:
        data = stream.read(block_size)
        if not data:
            break
        hash_ins.update(data)
    return hash_ins.hexdigest()

def io_hash_memory(memory,hash_algorithm=u'md5'):
    from io import BytesIO
    with BytesIO(memory) as f:
        return io_hash_stream(f,hash_algorithm)


def io_hash_fullpath(fullpath,hash_algorithm=u'md5'):
    with open(fullpath,'rb') as f:
        return io_hash_stream(stream=f,hash_algorithm=hash_algorithm)


def io_line_is_hash(line):
    import re
    return (re.match(u"[a-fA-F\d]{64}", line) or
            re.match(u"[a-fA-F\d]{40}", line) or
            re.match(u"[a-fA-F\d]{32}", line))

def _io_simple_check_hash(line,hash_length):
    fn = lambda e: all(i in '1234567890abcdefABCDEF' for i in e)
    return len(line) == hash_length and fn(line)

def io_simple_check_md5(line):
    return _io_simple_check_hash(line,32)

def io_simple_check_sha1(line):
    return _io_simple_check_hash(line,40)

def io_simple_check_sha256(line):
    return _io_simple_check_hash(line,64)

def io_simple_check_hash(line):
    return io_simple_check_md5(line) or io_simple_check_sha1(line) or io_simple_check_sha256(line)


def io_iter_split_step(data, split_unit_count):
    '''
    :param data:  must be isinstance(data, collections.Iterable):
    :param split_unit_count: 
    :return:  iter(tuple)

    def test_io_split_step():
        print (list(io_iter_split_step([1,2],5)))
        print (list(io_iter_split_step([1,2,3,4,5,6,7],4)))
        print (list(io_iter_split_step([1,2,3,4,5,6,7],3)))

    [(1, 2)]
    [(1, 2, 3, 4), (5, 6, 7)]
    [(1, 2, 3), (4, 5, 6), (7,)]

    '''
    a = iter(data)
    while True:
        r = []
        for _ in range(0, split_unit_count):
            try:
                e = next(a)
                r.append(e)
            except StopIteration:
                if r:
                    yield tuple(r)
                    r = []
                else:
                    raise StopIteration
        if r:
            yield tuple(r)
            r = []


'''
end
'''


def test_unicode_list():
    arg = [u'你好', u"中国"]
    io_print(arg)


def test_tupple():
    a = (1, '2', '34', u'中国')
    io_print(a)


def test():
    test_unicode_list()


def test_path():
    io_print(u'stdout_encoding:{0}'.format(sys.stdout.encoding))
    p = io_files_from_arg(sys.argv[1::])
    for e in p:
        io_print(e)
        io_print(io_is_path_valid(e))


def test_io_is_path_valid():
    '''
    c:\1->valid
    c:\21?->invalid
    c:\21*->invalid
    c:\21:->invalid
    c:\21"->invalid
    c:\21|->invalid
    c:\21<->invalid
    c:\21>->invalid 
    '''

    _func = lambda p :u'{}->{}'.format(p,u'valid' if io_is_path_valid(p) else u'invalid')

    io_print(_func(u'c:\\1'))
    io_print(_func(u'c:\\21?'))
    io_print(_func(u'c:\\21*'))
    io_print(_func(u'c:\\21:'))
    io_print(_func(u'c:\\21"'))
    io_print(_func(u'c:\\21|'))
    io_print(_func(u'c:\\21<'))
    io_print(_func(u'c:\\21>'))

if __name__ == '__main__':
    test()
    test_tupple()
    test_path()
    test_io_is_path_valid()
