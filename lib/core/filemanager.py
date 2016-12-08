# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import os
import email
import mimetypes
import magic
import re
import subprocess
import py7zlib
import zipfile
import rarfile
import tarfile
import gzip
import struct
import shutil
import md5
import uuid
import logging

from gzip import FEXTRA, FNAME
from email.header import Header
from lib.exceptions import SAMSAnalysisError
from lib.categoryfilters import ExtArchFilters, ExtExecFilters, ExtOfficeFilters
from lib.common.constants import _ROOT, _ANALYSIS_DIR, _TMP_DIR, _QUEUE_DIR

log = logging.getLogger(__name__)

class ArchiveManager(object):
    """
        Basic class - archive manager.
    """
    def __init__(self):
        log.setLevel(logging.INFO)
        self.exe = ExtExecFilters()
        self.docs = ExtOfficeFilters()
        self.arch = ('gzip', 'bz2', 'zip', 'tgz', 'rar', 'cab', 'arj', '7z',
                     'tar', 'ace', 'jar')
        self.arch_type = ExtArchFilters()
        self.exe = ExtExecFilters()
        log.info('Initialize archive manager')
        
    def sample_pack(self, dst, password):
        try:
            pwd = '-p'+password
            proc = subprocess.Popen(['7za', 'a', '-tzip',
                                     os.path.join(dst, '_sample.zip'),
                                     os.path.join(dst, 'sample')],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.wait()
            proc = subprocess.Popen(['7za', 'a', '-tzip', pwd,
                                     '-mem=ZipCrypto',
                                     os.path.join(dst, 'sample.zip'),
                                     os.path.join(dst, '_sample.zip')],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output, err = proc.communicate()
            proc.wait()
            os.remove(os.path.join(dst, '_sample.zip'))
            return True
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False

    def mail_pack(self, src, password):
        try:
            pwd = '-p'+password
            dst = os.path.dirname(src)
            proc = subprocess.Popen(['7za', 'a', '-tzip', pwd,
                                     '-mem=ZipCrypto',
                                     os.path.join(dst, 'mails.zip'),
                                     src],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output, err = proc.communicate()
            proc.wait()
            return True
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False

    def check_file_type(self, flist):
        if flist:
            for f in flist:
                if f[f.rfind('.')+1:] in self.exe.list:
                    return True
                if not re.search(self.arch_type.pattern_end, f) is None:
                    return True
        return False
    
    def explore_arch(self, archtype, filename):
        if not re.search(self.arch_type.pattern_part, filename) is None:
            log.info('Email does not contain suspicious files')
            return []
        if archtype == 'RAR':
            return self.rar_explore(filename)
        if archtype == 'Zip':
            return self.zip_explore(filename)
        if archtype == 'bzip2':
            return self.tar_explore(filename, 'r:bz2')
        if archtype == 'gzip' or archtype == 'tar':
            if filename.endswith('.tgz'):
                return self.tar_explore(filename, 'r:gz')
            elif filename.endswith('.tar') or filename.endswith('.tar.gz'):
                return self.tar_explore(filename, 'r')
            elif filename.endswith('.gz'):
                return self.gz_explore(filename)
        if archtype == '7-zip':
            return self.a7z_explore(filename)
        if archtype == 'JAR':
            return [filename]
        if archtype == 'ace':
            return [filename]
        if archtype == 'arj':
            return [filename]
        if filename.endswith('.cab'):
            return [filename]
        log.info('No archive type matches')
        return []

    def extract_arch(self, path, flist):
        try:
            # python magic
            for f in flist:
                try:
                    filename = os.path.join(path,'attachments',f['attach_name'])
                    #ms = magic.open(magic.MAGIC_NONE)
                    #ms.load()
                    fileinfo = str.lower(magic.from_file(filename))
                except Exception as e:
                    log.error('Processing failed: %s' % e)
                    return False
                success = False
                for archtype in self.arch_type.list:
                    if fileinfo.find(archtype.lower()) == 0:
                        if archtype == 'RAR':

                            if not self.rar_extract(os.path.join(path, 'sample'), filename):
                                self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                            success = True
                            break
                        if archtype == 'Zip':
                            if not self.zip_extract(os.path.join(path, u'sample'), filename):
                                self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                            success = True
                            break
                        if archtype == 'bzip2':
                            self.tar_extract(os.path.join(path, 'sample'), filename, 'r:bz2')
                            success = True
                            break
                        if archtype == 'gzip' or archtype == 'tar':
                            if filename.endswith('.tgz'):
                                self.tar_extract(os.path.join(path, 'sample'), filename, 'r:gz')
                                success = True
                                break
                            elif filename.endswith('.tar'):
                                self.tar_extract(os.path.join(path, 'sample'), filename, 'r')
                                success = True
                                break
                            elif filename.endswith('.gz'):
                                self.gz_extract(os.path.join(path, 'sample'), filename)
                                success = True
                                break
                        if archtype == '7-zip':
                            if not self.a7z_extract(os.path.join(path, 'sample'), filename):
                                self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                            success = True
                            break
                        self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                        success = True
                        break
                if 'rich' in fileinfo:
                    self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                elif not success:
                    archtype = filename.split('.')[-1].lower()
                    _exe = ExtExecFilters()
                    _docs = ExtOfficeFilters()
                    if archtype in _exe.list:
                        self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                        success = True
                    if not success:
                        if archtype in _docs.list:
                            self.copy_to_analysis(filename, os.path.join(path, 'sample', os.path.basename(filename)))
                            success = True
            return True
        except:
            return False

    def copy_to_analysis(self, filename, dst):
        shutil.copy(filename, dst)
        
    def rar_explore(self, filename):
        try:
            flist = []
            rf = rarfile.RarFile(filename)
            for f in rf.infolist():
                flist.append(f.filename)
            return flist
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return [os.path.basename(filename)]
        
    def rar_extract(self, dst, filename):
        result = False
        try:
            rf = rarfile.RarFile(filename)
            for l in rf.infolist():
                nfname = self.generate_new_filename(l.filename)
                result = self.save_extract_file(rf.read(l), os.path.join(dst, nfname))
            if result:
                return True
            else:
                return False
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False

    def zip_explore(self, filename):
        try:
            flist = []
            zf = zipfile.ZipFile(filename, 'r')
            for f in zf.infolist():
                flist.append(f.filename)
            return flist
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return flist

    def generate_new_filename(self, _str):
        filename = str(uuid.uuid4())
        filename = filename + _str[_str.rfind('.'):]
        return filename
    
    def save_extract_file(self,_buffer, fname):
        try:
            fp = open(fname, 'wb')
            fp.write(_buffer)
            fp.close()
            return True
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False            
        
    def zip_extract(self, dst, filename):
        result = False
        try:
            zf = zipfile.ZipFile(filename, 'r')
            nlist = zf.namelist()
            for l in nlist:
                if l.rfind('.') >= 0:
                    nfname = self.generate_new_filename(str(l))
                    result = self.save_extract_file(zf.read(l), os.path.join(dst, nfname))
            if result:
                return True
            else:
                return False 
        except Exception as e:
            log.error('Processing failed: %s' % e)
            err = str(e)
            if err.find('password required')>=0:
                passlist = ['111']
                for p in passlist:
                    proc = subprocess.Popen(['7z', 
                                            'e', 
                                            filename, 
                                            '-o'+dst, '-p'+p],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                    output, err = proc.communicate()
                    if err.find('ERROR:')>=0:
                        for item in os.listdir(dst):
                            os.remove(os.path.join(dst,item))
            else:
                proc = subprocess.Popen(['7z', 
                                        'e', 
                                        filename, 
                                        '-o'+dst, '-p'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                output, err = proc.communicate()
            dirlist = os.listdir(dst)
            if len(dirlist)>0:
                for k in dirlist:
                    n_fname = os.path.join(dst, self.generate_new_filename(k.encode('utf-8')))
                    os.rename(os.path.join(dst, k),n_fname)
                return True
            return False

    def a7z_explore(self, filename):
        try:
            flist = []
            zf = open(filename, 'rb')
            arch = py7zlib.Archive7z(zf)
            lf = arch.getnames()
            for f in lf:
                flist.append(f)
            return flist
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return flist

    def a7z_extract(self, dst, filename):
        try:
            proc = subprocess.Popen(['7z', 
                                    'e', 
                                    filename, 
                                    '-o'+dst],
                                    stdout=subprocess.PIPE,
                                    stdin='\n',
                                    stderr=subprocess.PIPE)
            output, err = proc.communicate(input='\n')
            if err.find('ERROR:')>=0:
                for item in os.listdir(dst):
                    os.remove(os.path.join(dst,item))
            for k in os.listdir(dst):
                n_fname = os.path.join(dst, self.generate_new_filename(k.encode('utf-8')))
                os.rename(os.path.join(dst, k),n_fname)
            return True
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False

    def tar_explore(self, filename, mode):
        try:
            flist = []
            tar = tarfile.open(filename, mode)
            for f in tar.getmembers():
                flist.append(f.name)
            return flist
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return flist

    def tar_extract(self, dst, filename, mode):
        try:
            tar = tarfile.open(filename, mode)
            for tarinfo in tar:
                if tarinfo.isreg():
                    tarinfo.name = self.generate_new_filename(str(tarinfo.name))
                    tar.extract(tarinfo.name, dst)
            return True
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False

    def gz_explore(self, filename):
        try:
            flist = []
            flist.append(self.read_gzip_info(filename))
            return flist
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return flist
        
    def gz_extract(self, dst, filename):
        try:
            fname = self.generate_new_filename(str(self.read_gzip_info(filename)))
            ff = os.path.join(dst, fname)
            gz = gzip.open(filename, 'rb')
            gze = open(ff, 'wb')
            gze.write(gz.read())
            gze.close()
            gz.close()
            return True
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return False

    def read_gzip_info(self, filename):
        gz = gzip.open(filename, 'rb')
        gf = gz.fileobj
        pos = gf.tell()

        # Read archive size
        gf.seek(-4, 2)
        size = struct.unpack('<I', gf.read())[0]

        gf.seek(0)
        magic = gf.read(2)
        if magic != '\037\213':
            log.info('Not a gzipped file')

        method, flag, mtime = struct.unpack('<BBIxx', gf.read(8))
        if not flag & FNAME:
            # Not stored in the header, being used the filename sans .gz
            gf.seek(pos)
            fname = gf.name
            if fname.endswith('.gz'):
                fname = fname[:-3]
            return fname
            #return fname, size
        if flag & FEXTRA:
            # Read & discard the extra field, if present
            gf.read(struct.unpack('<H', gf.read(2)))

        # Read a null-terminated string containing the filename
        fname = []
        while True:
            s = gf.read(1)
            if not s or s == '\000':
                break
            fname.append(s)

        gf.seek(pos)
        return ''.join(fname)

    def force_decode(string, codecs=['utf8', 'cp1252']):
        for i in codecs:
            try:
                return string.decode(i)
            except:
                return None

class FileManager(ArchiveManager):
    def __init__(self, cfg):
        self.cfg = cfg
        log.setLevel(logging.INFO)
        self.arch_type = ExtArchFilters()
        self.attachname = ''
        log.info('Initialize file manager')

    def run(self, task):
        try:
            self.initialize(task)
            if self.proccessing():
                return True
            else:
                return False
        except SAMSAnalysisError as e:
            log.error(e)
            return False

    def initialize(self, task):
        self.file_path = task['file']
        self.profile_path = os.path.dirname(self.file_path)
        self.sample_path = os.path.join(self.profile_path, 'sample')
        self.key_id = str(task['_id'])

    def proccessing(self):
        try:
            msg_data = self.filemsg_read(self.file_path)
            if 'dozor@dozor.ru' in msg_data.get('from'):
                data = self.get_payload(msg_data)
                tmp = data[1].get_payload()
                msg_data = tmp[0]
            os.makedirs(os.path.join(_ANALYSIS_DIR, 'malware', self.key_id, 'sample'))
            os.makedirs(os.path.join(_ANALYSIS_DIR, 'malware', self.key_id, 'attachments'))
            self.attachname = self.save_attachment(msg_data, os.path.join(_ANALYSIS_DIR, 'malware', self.key_id,'attachments'))
            self.extract_arch(self.profile_path, self.attachname)
            self.sample_pack(self.profile_path, 'infected')
            self.mail_pack(self.file_path, 'infected')
            if self.attachname is None:
                raise SAMSAnalysisError('Processing the message file: %s' % self.file_path)
                log.info('Processing the message file: %s' % self.file_path)
                return False
        except Exception as e:
            raise SAMSAnalysisError('Processing the message file: %s' % self.file_path)
            log.error('Processing the message file: %s' % e)
            return False
        return True

    def get_msg_dozor(self, msg):
        tmp = msg.get_payload()
        return tmp[1].get_payload()

    """ Get payload (attachments)"""
    def get_payload(self, content):
        return content.get_payload()
    
    def filemsg_read(self, path):
        sfile = open(path, 'r')
        msg = email.message_from_string(sfile.read())
        sfile.close()
        return msg
    
    def get_msg_data(self, msg_data):
        try:
            msg = email.message_from_string(msg_data)
            if 'dozor@dozor.ru' in msg.get('from'):
                msg = self.get_msg_dozor(msg)
                msg = msg[0]
                data = msg.get_payload()
            else:
                data = msg
            return data
        except Exception as e:
            log.error('Processing failed: %s' % e)
            return None

    def save_file(self, filename, payload):
        fp = open(filename, 'wb')
        fp.write(payload)
        fp.close()
        log.info('File saved: %s' % filename)
        return True

    def save_attachment(self, data, path):
        attache_list = []
        success = False
        for part in data.walk():
            maintype = part.get_content_maintype()
            if maintype == 'multipart' or maintype == 'image':
                continue
            contencode = part['Content-Transfer-Encoding']
            if contencode == 'base64':
                if part.get_filename():
                    filename = self.convert_str(part.get_filename(), contencode)
                    extfile = filename.split('.')[-1]
                    filename = md5.md5(filename).hexdigest()+'.'+extfile
                    success = self.save_file(os.path.join(path, filename), part.get_payload(decode=True))
                    attache_list.append({'attach_name':filename})
        if success:
            return attache_list
        else:
            log.info('What the F..k!!!!')
            return None

    def normal_str(self, _str, method):
        if method == 'base64':
            try:
                tmp = email.header.decode_header(_str)
                if tmp[0][1]:
                    nstr = tmp[0][0].decode(tmp[0][1])
                else:
                    nstr = tmp[0][0]
            except:
                nstr = _str
        else:
            nstr = _str
        return nstr

    def convert_str(self, strl, method):
        r_str = ''
        if method == 'base64':
            try:
                if not strl is None:
                    p_strs = strl.strip()
                    p_strs = p_strs.replace('\r\n\t','')
                    p_strs = p_strs.replace('\r\n','')
                    if p_strs.find('?=')>=0:
                        p_strs = p_strs.split('?=')
                    else:
                        p_strs = [p_strs]
                    sdf = False
                    if len(p_strs) > 1:
                        sdf = True
                    for item in p_strs:
                        t_str = item.strip()
                        if t_str != '':
                            if sdf and t_str.startswith('=?'):
                                dec_str = email.header.decode_header(t_str+'?=')
                                for s in dec_str:
                                    if (not s[1] is None) and (s[1] != 'utf-8'):
                                        r_str += '' + s[0].decode(s[1]).encode('utf-8','replace')
                                    else:
                                        r_str += '' + s[0]
                            else:
                                r_str = t_str.encode('utf-8','ignore')
            except:
                r_str = strl.encode('utf-8','ignore')
                log.error('Processing failed!')
        else:
            r_str = strl
        return r_str.strip()
