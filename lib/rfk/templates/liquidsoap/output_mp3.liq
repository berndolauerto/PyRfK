$name=output.icecast(%mp3.vbr(stereo=true, samplerate=44100, quality=$quality, id3v2=true),
                    host="$host", port=$port, protocol="http",
                    user="$username", password="$password",
                    mount="$mount",
                    url="$url", public=false,
                    description="$description",
                    fallible=true,
                    full)
