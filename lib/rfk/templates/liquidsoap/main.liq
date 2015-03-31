set('log.file.path','$logfile')
set('log.file', true)
set('log.stdout', true)
set('log.level', $loglevel)
set('server.telnet', true)
set('harbor.bind_addr', '$address')

# Header for HTTP requests, including the secret access token.
header = [("Content-Type", "application/json"), ("key", "$backendpassword")]
# Base URL for HTTP requests. Make sure it includes a trailing slash.
baseurl = "$backendurl"

def crossfade(a, b)
    add(normalize=false,
    [ sequence([ blank(duration=5.),
    fade.initial(duration=10., b) ]),
    fade.final(duration=10., a) ])
end

def auth(login, password) =
    payload = json_of(compact=true, [("username", login), ("password", password)])
    ret = http.post(data=payload, headers=header, "#{baseurl}auth")
    bool_of_string(snd(ret))
end

userid = ref "none"

def append_userid(mdata) =
    [("userid", !userid)]
end

def live_start(mdata)
    ret = http.post(data=json_of(compact=true, mdata), headers=header, "#{baseurl}connect")
    ignore(userid := snd(ret))
end

def live_stop()
    ignore(http.post(data=json_of(compact=true, !userid), headers=header, "#{baseurl}disconnect"))
    ignore(userid := "none")
end

def writemeta(mdata)
    ignore(http.post(data=json_of(compact=true, mdata), headers=header, "#{baseurl}metadata"))
end

def get_playlist_item() =
    ret = http.get(headers=header, "#{baseurl}playlist")
    request.create(snd(ret))
end

def get_listener(~protocol, ~data, ~headers,uri) =
    http_response(
        protocol=protocol,
        code=200,
        data=snd(http.get(headers=header, "#{baseurl}listenercount"))
    )
end


live = (input.harbor(port = $port,
                     on_connect=live_start,
                     on_disconnect=live_stop,
                     buffer=5.,
                     max=20.,
                     timeout=30.,
                     auth=auth,
                     "/live.ogg")
                     :source(*+1,0,0))
live = audio_to_stereo(live)
live = strip_blank(live)

# Not needed; leave it as reference
#ignore(output.dummy(fallible=true, live))

harbor.http.register(port=$port, method="GET",
                     "^/admin/listclients",
                     get_listener)

playlist = request.dynamic(get_playlist_item)
playlist = merge_tracks(playlist)
playlist = drop_metadata(playlist)
playlist = rewrite_metadata([("title", "Nobody is streaming right now")], playlist)
playlist = rewrite_metadata([("artist", "radiochan")], playlist)

$emergency
emergency = mksafe(emergency)
emergency = merge_tracks(emergency)
emergency = drop_metadata(emergency)
emergency = rewrite_metadata([("title", "Something is wrong, please contact an admin!")], emergency)
emergency = rewrite_metadata([("artist", "radiochan")], emergency)

live = map_metadata(append_userid, live)
live = on_metadata(writemeta , live)

$lastFM

full = fallback(track_sensitive=false, transitions=[crossfade, crossfade, crossfade], [live, playlist, emergency])
