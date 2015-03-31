$name=output.icecast(%aacplus(channels=2, samplerate=44100, bitrate=$quality),
                    host="$host", port=$port, protocol="http",
                    user="$username", password="$password",
                    mount="$mount",
                    url="$url", public=false,
                    description="$description",
                    fallible=true,
                    full)
