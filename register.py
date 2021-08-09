#  coding: utf-8
'''
原理
    判断路径下是否存在识别文件，若存在就解密对比，若不存在就进入机器码注册：
    获取系统C盘序列号作为识别ID，并添加随机数作为混淆，生成最终机器码。
    将机器码发给软件开发者，开发者将机器码解密后，添加自己的标识符号并加密生成key，发给用户。
    用户输入key，程序对比并保存。
    用户下次打开软件时，重新开始步骤‘1’。
说明
    加密：将序列号经过Des加密，再经过base64编码。
    解密：将密码经过base64解码，再经过Des解密。
    写文件：将二进制字符转为十六进制保存。
    读文件：将十六进制转为二进制。
'''
#  coding: utf-8

import win32api
import pyDes
from binascii import b2a_hex, a2b_hex
import base64
import requests
import re
import os
import random
import json
import time


def DebugPrint(*args):
    print(*args)


Des_Key = "12345678"  # Key
Des_IV = "00000000"  # 自定IV向量
TYPE = 'DB'  # DB


class Register:
    def __init__(self, TYPE):
        self.TYPE = TYPE
        self.Des_Key = Des_Key
        self.Des_IV = Des_IV

    def getCVolumeSerialNumber(self):
        CVolumeSerialNumber = win32api.GetVolumeInformation("C:\\")[1]
        # print(CVolumeSerialNumber)
        if CVolumeSerialNumber:
            return str(CVolumeSerialNumber)
        else:
            return 0

    def DesEncrypt(self, str):
        k = pyDes.des(self.Des_Key, pyDes.CBC, self.Des_IV, pad=None, padmode=pyDes.PAD_PKCS5)
        encryptStr = k.encrypt(str)
        string = base64.b64encode(encryptStr)
        print(string)
        return string  # 转base64编码返回

    def DesDecrypt(self, string):
        string = base64.b64decode(string)
        k = pyDes.des(self.Des_Key, pyDes.CBC, self.Des_IV, pad=None, padmode=pyDes.PAD_PKCS5)
        decryptStr = k.decrypt(string)
        # print(decryptStr)
        return decryptStr

    # {'Type':'DB', 'stat':'Buy/Trial/TimeTri', 'Serial':'0', 'Random':'0-1000', 'Mix':''}
    def Regist_New(self):
        if os.path.isfile('conf.bin'):
            with open('conf.bin', 'rb') as fp:
                key = a2b_hex(fp.read())
                # print(key)
            serialnumber = self.getCVolumeSerialNumber()
            decryptstr = self.DesDecrypt(key).decode('utf8')
            decryptstr = eval(decryptstr)
            # print(decryptstr)
            if serialnumber == decryptstr['Serial']:
                if self.TYPE == decryptstr['Type']:
                    if 'Buy' == decryptstr['stat']:
                        DebugPrint('>> Permanently Purchased')
                        print(">> 验证完成")
                        return 1
                    elif 'Trial' == decryptstr['stat']:
                        DebugPrint('>> Single Trial')
                        return 2
                    elif decryptstr['stat'].startswith('TimeTri'):
                        self.CheckTimeTri()
                        DebugPrint('>> Time Limited Purchase')
                        return 3
                else:
                    DebugPrint('>> Invalid conf.bin')
        rand = str(random.randrange(1, 1000))
        serialnumber = self.getCVolumeSerialNumber()
        # print(serialnumber)
        content = str({'stat': '', 'Serial': serialnumber, 'Random': rand, 'Type': self.TYPE})
        encryptstr = self.DesEncrypt(content).decode('utf8')
        print(">> Serial Number:", encryptstr)
        while True:
            key = input(">> Verification Code:")
            try:
                decryptstr = self.DesDecrypt(key.encode('utf8')).decode('utf8')
                decryptstr = eval(decryptstr)
                print(decryptstr)
                if serialnumber == decryptstr['Serial']:
                    if 'Buy' == decryptstr['stat']:
                        DebugPrint('>> Permanently Purchased')
                        with open('conf.bin', 'wb') as fp:
                            fp.write(b2a_hex(key.encode('utf8')))
                            DebugPrint(">> Validation Completed")
                        return 1
                    elif 'Trial' == decryptstr['stat']:
                        DebugPrint('>> Single Trial')
                        return 2
                    elif decryptstr['stat'].startswith('TimeTri'):
                        DebugPrint('>> Time Limited Purchase')
                        with open('conf.bin', 'wb') as fp:
                            fp.write(b2a_hex(key.encode('utf8')))
                            DebugPrint(">> Validation Completed")
                        return 3
                    else:
                        DebugPrint(">> Input Epy")
            except Exception as e:
                print(e)
                DebugPrint(">> Input Err")
                continue

    def Regist(self):
        if os.path.isfile('conf.bin'):
            with open('conf.bin', 'rb') as fp:
                key = a2b_hex(fp.read())
                print(key)
            serialnumber = self.getCVolumeSerialNumber()
            decryptstr = self.DesDecrypt(key).decode('utf8')
            print(decryptstr)
            if serialnumber in decryptstr:
                if 'Buy' in decryptstr:
                    DebugPrint('>> Permanently Purchased')
                    print(">> 验证完成")
                    return 1
                elif 'Trial' in decryptstr:
                    DebugPrint('>> Single Trial')
                    return 2
                elif 'TimeTri' in decryptstr:
                    self.CheckTimeTri()
                    DebugPrint('>> Time Limited Purchase')
                    return 3

        rand = str(random.randrange(1, 1000))
        serialnumber = self.getCVolumeSerialNumber() + rand
        print(serialnumber)
        encryptstr = self.DesEncrypt(serialnumber).decode('utf8')
        print(">> Serial Number:", encryptstr)
        while True:
            key = input(">> Verification Code:")
            try:
                decryptstr = self.DesDecrypt(key.encode('utf8')).decode('utf8')
                # print(decryptstr)
                if serialnumber in decryptstr:
                    if 'Buy' in decryptstr:
                        DebugPrint('>> Permanently Purchased')
                        with open('conf.bin', 'wb') as fp:
                            fp.write(b2a_hex(key.encode('utf8')))
                            DebugPrint(">> Validation Completed")
                        return 1
                    elif 'Trial' in decryptstr:
                        DebugPrint('>> Single Trial')
                        return 2
                    elif 'TimeTri' in decryptstr:
                        DebugPrint('>> Time Limited Purchase')
                        with open('conf.bin', 'wb') as fp:
                            fp.write(b2a_hex(key.encode('utf8')))
                            DebugPrint(">> Validation Completed")
                        return 3
            except Exception as e:
                print(e)
                DebugPrint(">> Input Err")
                continue

    def GetTime(self):
        url = r'http://api.m.taobao.com/rest/api3.do?api=mtop.common.getTimestamp'
        try:
            html = requests.get(url).json()
            if 'SUCCESS' in html['ret'][0]:
                return html['data']['t']
        except:
            return time.time()

    def CheckTimeTri(self):
        with open('conf.bin', 'rb') as fp:
            key = a2b_hex(fp.read())
            # print(key)
            decryptstr = self.DesDecrypt(key).decode('utf8')
            decryptstr = eval(decryptstr)
            # print(decryptstr)
            triallTime = int(re.findall(r'\[(.*)\]', decryptstr['stat'])[0])
            # print('triallTime:', triallTime)
            # print('GetTime:', GetTime())
            if int(self.GetTime()) >= triallTime:
                DebugPrint('>> Time Expires')
                fp.close()
                os.remove('conf.bin')
                DebugPrint("\r\n\r\n>> Program End~")
                input(">> Any Key to Exit")
                os._exit(0)
            return 1


def verify():
    Reg = Register(TYPE)
    key = input('Key => ')
    decryptstr = Reg.DesDecrypt(key)
    decryptstr = eval(decryptstr)
    print(decryptstr)

    decryptstr['stat'] = 'Buy'
    res = Reg.DesEncrypt(str(decryptstr))
    print('Buy =>', res)

    decryptstr['stat'] = 'Trial'
    res = Reg.DesEncrypt(str(decryptstr))
    print('Trial =>', res)

    minute = 30
    times = int(Reg.GetTime()) + 1000 * 60 * minute
    decryptstr['stat'] = 'TimeTri[%d]' % times
    res = Reg.DesEncrypt(str(decryptstr))
    print('TimeTrial =>', res)


def encrypt():
    Reg = Register(TYPE)
    res = Reg.Regist_New()
    print(res)


if __name__ == '__main__':
    verify()
    encrypt()