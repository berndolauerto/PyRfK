var _refreshIntervalMs = 3000;
var _refreshInterval = 0;
var _volume = 0.5;
var _currentSong = "";
var audio = null;

function pageLoaded() {
	player_load();
	getCurrentTrack();
	_refreshInterval = setInterval(getCurrentTrack, _refreshIntervalMs);
}

function getCurrentTrack() {
	// receive data here
	$.getJSON('/api/site/nowplaying', function(data) {

		if (!data.data.track) {
			meta = "No tags available";
		}
		else {
			meta = data.data.track.artist + ' - ' + data.data.track.title;
		}

		// if data is different update with nice effect
		if ( meta != _currentSong ) {
			_currentSong = meta;
			$('#nowPlayingTrack').fadeOut( 'normal', function() {
				$('#nowPlayingTrack').html( meta );
			});
			$('#nowPlayingTrack').fadeIn( 'normal' );
		}
	});
}

function updateVolume() {
	// Store last user-defined volume in localStorage
	localStorage.setItem('rfk_webplayer_volume', _volume);

	audio.volume = _volume;
}

function player_load() {
	audio.load();

	// If localStorage contains a last user-defined volume, we us this instead of the default value
	lsVol = localStorage.getItem('rfk_webplayer_volume');
	if (  lsVol != null ) {
		audio.volume = lsVol;
	} else {
		// No luck, we use the defaultvolume
		audio.volume = _volume;
	}

	audio.play();
}

function player_startPause() {
	if ( $('#player').length > 0 ) {
		audio.pause();
		audio.src = "";
		audio.load();
		$('#player').empty();
		$('#player').remove();
	}
	else if ( $('#player').length == 0 ) {
		location.reload();
	}
}

function player_event_playing(event) {
	$('#frontrow').fadeOut('normal', function() {});
}

$(document).ready(function() {

	// Control: start & stop
	$('#ctrlStartStop i').click(function() {
		player_startPause();
		if ( $(this).hasClass('fa-stop') ) {
			$(this).removeClass('fa-stop');
			$(this).addClass('fa-play');
		}
		else {
			$(this).removeClass('fa-play');
			$(this).addClass('fa-stop');
		}
	});

	// If localStorage contains last user-defined volume, we use it to set the UI-slider accordingly
	lsVol = localStorage.getItem('rfk_webplayer_volume');
	sliderValue = 50;
	if (  lsVol != null ) {
		sliderValue = ( lsVol * 100);
	}

	$( "#slider" ).slider({
		orientation: "horizontal",
		handle:"square",
		min: 0,
		max: 100,
		value: sliderValue
	}).on('slide',function(event) {
		_volume = (event.value / 100);
		console.log(event);
		updateVolume();
	});

	window.resizeTo(680, 280);

	audio = document.getElementById("player");
	audio.addEventListener("playing", player_event_playing, false);

	pageLoaded();

});
