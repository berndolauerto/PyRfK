set('log.file.path','$logfile')
set('log.file', true)
set('log.stdout', true)
set('log.level', $loglevel)
set('server.telnet', true)
set('harbor.bind_addr', '$address')

def crossfade(a, b)
    add(normalize=false,
    [ sequence([ blank(duration=5.),
    fade.initial(duration=10., b) ]),
    fade.final(duration=10., a) ])
end

def auth(login, password) =
    ret = get_process_lines("$script auth #{quote(login)} #{quote(password)}")
    ret = list.hd(ret)
    bool_of_string(ret)
end

userid = ref "none"

def append_userid(mdata) =
  [("userid", !userid)]
end

def live_start(mdata)
    ret = get_process_lines("$script connect #{quote(json_of(compact=true, mdata))}")
    ignore(userid := list.hd(ret))
end

def live_stop()
    ignore(test_process("$script disconnect #{quote(json_of(compact=true, !userid))}"))
    ignore(userid := "none")
end

def writemeta(mdata)
    ignore(system("$script meta #{quote(json_of(compact=true, mdata))}"))
end

def get_playlist_item() = 
  result =
    list.hd(
      get_process_lines("$script playlist"))
  request.create(result)
end

def get_listener(~protocol, ~data, ~headers,uri) =
   http_response(
     protocol=protocol,
     code=200,
     data=get_process_output("$script listenercount")
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
playlist = rewrite_metadata([("title", "Kein Strömbernd")], playlist)
playlist = rewrite_metadata([("artist", "Radio freies Krautchan")], playlist)

$fallback

live = map_metadata(append_userid, live)
live = on_metadata(writemeta , live)

$lastFM

full = fallback(track_sensitive=false, transitions=[crossfade], [live, playlist, emergency])
