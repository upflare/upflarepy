# -*- coding: utf-8 -*-

import hashlib
import hmac
import base64
import urlparse
import re

class App(object):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

    def sign(self, base):
        signature = hmac.new(self.secret, base, hashlib.sha1).digest()
        return base64.urlsafe_b64encode(signature[-6:])

    def do(self, method, action, data):
        parts = [self.key]
        if action:
            parts.append(action)
        parts.append(data)
        signature = self.sign('%s /%s' % (method.upper(), '/'.join(parts)))
        parts.append(signature)
        return '/%s' % ('/'.join(parts),)

class Resize(object):

    def __init__(self, width=0, height=0, crop=False):
        self._width = width
        self._height = height
        self._crop = crop

    def __str__(self):
        resize = ''
        if self._width > 0 and self._height > 0 and self._width == self._height:
            resize = 's%d' % self._width
        elif self._width > 0 and self._height > 0:
            resize = 'w%d-h%d' % (self._width, self._height)
        elif self._width > 0:
            resize = 'w%d' % self._width
        elif self._height > 0:
            resize = 'h%d' % self._height
        if resize and self._crop:
            resize += '-c'
        return resize

    def __unicode__(self):
        return unicode(str(self))

    def __repr__(self):
        return str(self)

class Download(App):

    FILENAME_PATTERN = re.compile(r'^[A-Za-z0-9\-_]*(\.[A-Za-z0-9\-_]+)+$')
    HASH_PATTERN = re.compile(r'^[0-9a-f]{40}$')
    UPLOAD_PATTERN = re.compile(r'^[A-Za-z0-9]{32}$')

    def __init__(self, data, **kwargs):
        super(Download, self).__init__(**kwargs)
        self._data = data
        self._resize = None
        self._filename = ''

    def __str__(self):
        parts = [self._data]
        if self._resize:
            resize = str(self._resize)
            if resize:
                parts.append(resize)
        if self._filename:
            parts.append(self._filename)
        return super(Download, self).do('GET', '', ','.join(parts))

    def __unicode__(self):
        return unicode(str(self))

    def __repr__(self):
        return str(self)

    def resize(self, *args, **kwargs):
        if len(args) > 0:
            assert(len(args) == 1)
            assert(len(kwargs) == 0)
            self._resize = args[0]
            return self
        self._resize = Resize(**kwargs)
        return self

    def filename(self, filename=''):
        assert(self.FILENAME_PATTERN.match(filename))
        self._filename = filename
        return self

def download_url(url, **kwargs):
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    assert(scheme in ['http', 'https'])
    assert('@' not in netloc)
    assert(path.startswith('/'))
    assert(params == '')
    fragment = ''
    url = urlparse.urlunparse((scheme, netloc, path, params, query, fragment))
    data = base64.urlsafe_b64encode(url)
    return Download(data=data, **kwargs)

def download_hash(hash, **kwargs):
    assert(Download.HASH_PATTERN.match(hash))
    return Download(data=hash, **kwargs)

def download_upload(id, **kwargs):
    assert(Download.UPLOAD_PATTERN.match(id))
    return Download(data=id, **kwargs)

