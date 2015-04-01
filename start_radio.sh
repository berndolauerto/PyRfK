#!/bin/bash
PATH=$HOME/local/bin:$PATH

# activate virtualenv
cd $HOME/weltklang/
source bin/activate

# start uwsgi
uwsgi -i etc/uwsgi.ini

# start icecast2
icecast -b -c $HOME/local/etc/icecast.xml

# start liquidsoap daemon
$HOME/weltklang/bin/rfk-liquidsoap

