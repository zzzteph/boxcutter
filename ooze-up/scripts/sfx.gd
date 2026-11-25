## ============================================================================
##  SFX - every sound is synthesised at startup (no audio files).
## ============================================================================
class_name Sfx
extends Node

const RATE := 22050

var streams := {}
var players: Array[AudioStreamPlayer] = []
var muted := false
var _next := 0


func _ready() -> void:
	_build_all()
	for i in 12:
		var p := AudioStreamPlayer.new()
		add_child(p)
		players.append(p)


func play(sound: String, pitch := 1.0, vol_db := 0.0) -> void:
	if muted or not streams.has(sound) or players.is_empty():
		return
	var p := players[_next]
	_next = (_next + 1) % players.size()
	p.stream = streams[sound]
	p.pitch_scale = pitch
	p.volume_db = vol_db
	p.play()


func set_muted(m: bool) -> void:
	muted = m
	AudioServer.set_bus_mute(0, m)


# --- synthesis ---------------------------------------------------------------

## Mix one voice into `buf`. Frequencies glide exponentially from f0 to f1.
func _tone(buf: PackedFloat32Array, start: float, dur: float, f0: float, f1: float, wave: String,
		vol: float, attack := 0.004, curve := 2.0) -> void:
	var s0 := int(start * RATE)
	var n := mini(int(dur * RATE), buf.size() - s0)
	var phase := 0.0
	var lp := 0.0
	var k := clampf(f0 / RATE * 6.0, 0.02, 1.0)
	for i in n:
		var t := float(i) / n
		var f := f0 * pow(f1 / f0, t) if f0 > 0.0 and f1 > 0.0 else f0
		phase += f / RATE
		var x := 0.0
		match wave:
			"sine":
				x = sin(phase * TAU)
			"tri":
				x = 1.0 - 4.0 * absf(fposmod(phase, 1.0) - 0.5)
			"square":
				x = 1.0 if fposmod(phase, 1.0) < 0.5 else -1.0
			"saw":
				x = 2.0 * fposmod(phase, 1.0) - 1.0
			"noise":
				lp += (randf() * 2.0 - 1.0 - lp) * k
				x = lp * 1.8
		var env := minf(1.0, float(i) / (attack * RATE)) * pow(1.0 - t, curve)
		buf[s0 + i] += x * vol * env


func _buffer(dur: float) -> PackedFloat32Array:
	var b := PackedFloat32Array()
	b.resize(int(dur * RATE))
	b.fill(0.0)
	return b


func _to_stream(buf: PackedFloat32Array) -> AudioStreamWAV:
	var data := PackedByteArray()
	data.resize(buf.size() * 2)
	for i in buf.size():
		data.encode_s16(i * 2, int(clampf(buf[i], -1.0, 1.0) * 32000.0))
	var s := AudioStreamWAV.new()
	s.format = AudioStreamWAV.FORMAT_16_BITS
	s.mix_rate = RATE
	s.stereo = false
	s.data = data
	return s


func _build_all() -> void:
	var b: PackedFloat32Array

	b = _buffer(0.11)
	_tone(b, 0.0, 0.10, 420.0, 900.0, "tri", 0.55, 0.002, 2.5)
	_tone(b, 0.0, 0.025, 3000.0, 3000.0, "noise", 0.18, 0.001, 1.0)
	streams["place"] = _to_stream(b)

	b = _buffer(0.2)
	_tone(b, 0.0, 0.18, 320.0, 130.0, "square", 0.2, 0.002, 1.5)
	_tone(b, 0.0, 0.09, 1800.0, 1800.0, "noise", 0.25, 0.001, 1.0)
	streams["replace"] = _to_stream(b)

	b = _buffer(0.18)
	_tone(b, 0.0, 0.07, 170.0, 160.0, "square", 0.22, 0.002, 0.8)
	_tone(b, 0.09, 0.08, 135.0, 125.0, "square", 0.22, 0.002, 0.8)
	streams["deny"] = _to_stream(b)

	b = _buffer(0.05)
	_tone(b, 0.0, 0.045, 1500.0, 1050.0, "sine", 0.28, 0.001, 3.0)
	streams["tick"] = _to_stream(b)

	b = _buffer(0.34)
	var notes := [784.0, 988.0, 1319.0]
	for i in notes.size():
		_tone(b, i * 0.065, 0.14, notes[i], notes[i], "tri", 0.38, 0.003, 1.6)
	streams["bonus"] = _to_stream(b)

	b = _buffer(0.5)
	notes = [523.0, 659.0, 784.0, 1047.0]
	for i in notes.size():
		_tone(b, i * 0.07, 0.2, notes[i], notes[i], "tri", 0.34, 0.003, 1.4)
		_tone(b, i * 0.07, 0.2, notes[i] * 2.0, notes[i] * 2.0, "sine", 0.12, 0.003, 2.0)
	streams["cross"] = _to_stream(b)

	b = _buffer(0.42)
	_tone(b, 0.0, 0.4, 300.0, 1500.0, "sine", 0.4, 0.01, 1.0)
	_tone(b, 0.05, 0.35, 600.0, 2400.0, "tri", 0.15, 0.01, 1.5)
	streams["powerup"] = _to_stream(b)

	b = _buffer(0.6)
	_tone(b, 0.0, 0.55, 900.0, 900.0, "noise", 0.7, 0.001, 1.6)
	_tone(b, 0.0, 0.5, 150.0, 35.0, "sine", 0.7, 0.002, 1.2)
	streams["bomb"] = _to_stream(b)

	b = _buffer(1.0)
	_tone(b, 0.0, 0.95, 330.0, 55.0, "saw", 0.22, 0.004, 1.1)
	_tone(b, 0.0, 0.95, 220.0, 40.0, "square", 0.1, 0.004, 1.3)
	_tone(b, 0.0, 0.35, 700.0, 700.0, "noise", 0.35, 0.001, 1.5)
	streams["gameover"] = _to_stream(b)

	b = _buffer(0.14)
	_tone(b, 0.0, 0.13, 880.0, 880.0, "sine", 0.4, 0.003, 1.5)
	streams["beep"] = _to_stream(b)

	b = _buffer(0.4)
	_tone(b, 0.0, 0.38, 1320.0, 1320.0, "sine", 0.35, 0.003, 1.3)
	_tone(b, 0.0, 0.38, 660.0, 660.0, "tri", 0.25, 0.003, 1.3)
	streams["go"] = _to_stream(b)

	b = _buffer(0.8)
	notes = [392.0, 523.0, 659.0, 784.0]
	for i in notes.size():
		_tone(b, i * 0.1, 0.4 if i == 3 else 0.16, notes[i], notes[i], "tri", 0.34, 0.004, 1.3)
		_tone(b, i * 0.1, 0.4 if i == 3 else 0.16, notes[i] * 1.5, notes[i] * 1.5, "sine", 0.1, 0.004, 1.5)
	streams["zone"] = _to_stream(b)

	b = _buffer(0.35)
	_tone(b, 0.0, 0.33, 180.0, 900.0, "saw", 0.13, 0.01, 0.8)
	_tone(b, 0.0, 0.33, 2500.0, 2500.0, "noise", 0.15, 0.05, 1.0)
	streams["ff"] = _to_stream(b)

	b = _buffer(0.04)
	_tone(b, 0.0, 0.035, 1000.0, 900.0, "sine", 0.25, 0.001, 2.0)
	streams["click"] = _to_stream(b)
