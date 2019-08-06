# -*- coding: utf-8 -*-

"""
intelixir.api
~~~~~~~~~~~~
This module implements the SophosLabs Intelix API.
:author: (c) 2019 by @secbug.
:license: Apache 2.0, see LICENSE for more details.
"""

import requests
import json
import hashlib
from urllib.parse import urlparse, quote


class SophosLabs:
    def __init__(self, client_id, client_secret, region, token=None):
        # Set default server root and url for when region is not defined
        self.server_root = 'api.labs.sophos.com'
        self.server_url = 'https://de.' + self.server_root

        # Create dicts to store all reports
        self.reports_lookup = {'sha256': {}, 'file': {}, 'url': {}}
        self.reports_static = {'sha256': {}, 'file': {}, 'job': {}}
        self.reports_dynamic = {'sha256': {}, 'file': {}, 'job': {}}

        # Dict to store all incomplete jobs to re-evaluate with check_jobs()
        self.jobs_static = []
        self.jobs_dynamic = []

        try:
            self.server_url = self._set_server(str(region).upper())
        except KeyError as error:
            print("Provide a region when instantiating")
            raise

        if client_id and client_secret:
            if token:
                raise ValueError('Dictionary must contain either a token OR both client_id and client_secret pair')
            else:
                self._auth(client_id, client_secret)

        if token and not (client_id or client_secret):
            self.token = token

        if not self.token:
            raise ValueError('Dictionary must contain either a token OR both client_id and client_secret pair')

    def _set_server(self, region):
        if region == 'DE':
            return 'https://de.'+self.server_root
        else:
            raise ValueError('Invalid region')

    def _auth(self, client_id, client_secret):
        d = {'grant_type': 'client_credentials'}
        r = requests.post("https://" + self.server_root + "/oauth2/token", auth=(client_id, client_secret), data=d)
        j = json.loads(r.text)
        if r.status_code == 200:
            self.token = j['access_token']
            self.headers = {'Authorization': self.token}
        else:
            raise Exception('Authentication failed')

    def _get_sha256(self, file):
        with open(file, 'rb') as f:
            b = f.read()
            sha256 = hashlib.sha256()
            sha256.update(b)
            return sha256.hexdigest()

    def _check_file(self, file):
        try:
            with open(file, 'r') as f:
                return True
        except IOError:
            print("Unable to open file")
            return False

    def _request(self, method, url, file=None, params=None):
        r = None
        if method == 'GET':
            r = requests.get(url, headers=self.headers, params=params)
        if method == 'POST':
            if file:
                fo = open(file, 'rb')
                files = {'file': fo}
                r = requests.post(url, headers=self.headers, files=files, params=params)
                fo.close()
            else:
                r = requests.post(url, headers=self.headers, params=params)
        j = json.loads(r.text)
        return j

    def _report(self, api, kind, key, response):
        if api == 'lookup':
            if 'requestId' in response:
                self.reports_lookup[kind][key] = response
        if api == 'static':
            if 'jobStatus' in response:
                if response['jobStatus'] == 'SUCCESS':
                    self.reports_static[kind][key] = response['report']
        if api == 'dynamic':
            if 'jobStatus' in response:
                if response['jobStatus'] == 'SUCCESS':
                    self.reports_dynamic[kind][key] = response['report']

    def lookup_sha256(self, sha256, save=True):
        if len(sha256) == 64 and isinstance(sha256, str):
            r = self._request('GET', self.server_url+'/lookup/files/v1/'+sha256)
            if save:
                self._report('lookup', 'sha256', sha256, r)
            return r

    def lookup_url(self, url, save=True):
        u = urlparse(url)
        if u.scheme and u.netloc:
            r = self._request('GET', self.server_url+'/lookup/urls/v1/'+quote(url, safe=''))
            if save:
                self._report('lookup', 'url', url, r)
            return r

    def lookup_file(self, file, save=True):
        if self._check_file(file):
            sha256 = self._get_sha256(file)
            r = self._request('GET', self.server_url+'/lookup/files/v1/'+sha256)
            if save:
                self._report('lookup', 'file', file, r)
            return r

    def lookup_apk(self, apk):
        #TODO: the apk (zip) needs unpacking to hash the cert and get other meta data for the request
        return False

    def static_sha256(self, sha256, save=True):
        if len(sha256) == 64 and isinstance(sha256, str):
            r = self._request('GET', self.server_url+'/analysis/file/static/v1/reports', params={'sha256': sha256})
            if 'jobStatus' in r:
                if r['jobStatus'] == 'IN_PROGRESS':
                    self.jobs_static.append(('sha256', sha256, r['jobId']))
            if save:
                self._report('static', 'sha256', sha256, r)
            return r

    def static_file(self, file, save=True):
        if self._check_file(file):
            r = self._request('POST', self.server_url+'/analysis/file/static/v1/', file=file)
            if 'jobStatus' in r:
                if r['jobStatus'] == 'IN_PROGRESS':
                    self.jobs_static.append(('file', file, r['jobId']))
            if save:
                self._report('static', 'file', file, r)
            return r

    def static_job(self, job_id, save=True):
        if isinstance(job_id, str):
            r = self._request('GET', self.server_url+'/analysis/file/static/v1/reports/'+job_id)
            if 'jobStatus' in r:
                if r['jobStatus'] == 'IN_PROGRESS':
                    self.jobs_static.append(('job', job_id, r['jobId']))
            if save:
                self._report('static', 'job', job_id, r)
            return r

    def dynamic_sha256(self, sha256, save=True):
        if len(sha256) == 64 and isinstance(sha256, str):
            r = self._request('GET', self.server_url+'/analysis/file/dynamic/v1/reports', params={'sha256': sha256})
            if 'jobStatus' in r:
                if r['jobStatus'] == 'IN_PROGRESS':
                    self.jobs_dynamic.append(('sha256', sha256, r['jobId']))
            if save:
                self._report('dynamic', 'sha256', sha256, r)
            return r

    def dynamic_file(self, file, save=True):
        if self._check_file(file):
            r = self._request('POST', self.server_url+'/analysis/file/dynamic/v1/', file=file)
            if 'jobStatus' in r:
                if r['jobStatus'] == 'IN_PROGRESS':
                    self.jobs_dynamic.append(('file', file, r['jobId']))
            if save:
                self._report('dynamic', 'file', file, r)
            return r

    def dynamic_job(self, job_id, save=True):
        if isinstance(job_id, str):
            r = self._request('GET', self.server_url+'/analysis/file/dynamic/v1/reports/'+job_id)
            if 'jobStatus' in r:
                if r['jobStatus'] == 'IN_PROGRESS':
                    self.jobs_dynamic.append(('job', job_id, r['jobId']))
            if save:
                self._report('dynamic', 'job', job_id, r)
            return r

    def check_static_jobs(self):
        complete = []
        for j in self.jobs_static:
            r = self._request('GET', self.server_url+'/analysis/file/dynamic/v1/reports/'+j[2])
            if 'jobStatus' in r:
                if r['jobStatus'] == 'SUCCESS':
                    self._report('static', j[0], j[1], r)
                    complete.append((j[0], j[1]))
                    self.jobs_static.remove(j)
        return complete

    def check_dynamic_jobs(self):
        complete = []
        for j in self.jobs_dynamic:
            r = self._request('GET', self.server_url+'/analysis/file/dynamic/v1/reports/'+j[2])
            if 'jobStatus' in r:
                if r['jobStatus'] == 'SUCCESS':
                    self._report('dynamic', j[0], j[1], r)
                    complete.append((j[0], j[1]))
                    self.jobs_dynamic.remove(j)
        return complete
