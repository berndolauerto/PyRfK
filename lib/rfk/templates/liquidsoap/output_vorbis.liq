$name=output.icecast(%vorbis(samplerate=44100, channels=2, quality=0.$quality),
                    host="$host", port=$port, protocol="http",
                    user="$username", password="$password",
                    mount="$mount",
                    url="$url", public=false,
                    description="$description",
                    fallible=true,
                    full)
