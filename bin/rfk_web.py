#!/usr/bin/python
'''
Created on 30.04.2012

@author: teddydestodes
'''
import os
import sys

basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(basedir,'lib'))

import rfk
from rfk.database import init_db


rfk.init(basedir)
init_db("%s://%s:%s@%s/%s?charset=utf8" % (rfk.CONFIG.get('database', 'engine'),
                                               rfk.CONFIG.get('database', 'username'),
                                               rfk.CONFIG.get('database', 'password'),
                                               rfk.CONFIG.get('database', 'host'),
                                               rfk.CONFIG.get('database', 'database')))
from rfk.site import app
app.template_folder = os.path.join(basedir,'var','template')
app.static_folder = os.path.join(basedir,'web_static')
app.config['BABEL_LOCALE_PATH'] = os.path.join(basedir,'var','translations')
app.config['BASEDIR'] = basedir
app.static_url_path = '/static'

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)