$name=output.icecast(%opus(channels=2, samplerate=48000, bitrate=$quality, max_bandwidth="full_band",
                           frame_size=20., application="audio"),
                    host="$host", port=$port, protocol="http",
                    user="$username", password="$password",
                    mount="$mount",
                    url="$url", public=false,
                    description="$description",
                    fallible=true,
                    full)
