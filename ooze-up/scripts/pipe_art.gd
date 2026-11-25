## ============================================================================
##  PIPE ART - procedural drawing of pipes, goo, rocks, tanks and icons.
## ============================================================================
## Pure drawing helpers that take any CanvasItem, so the board, the queue and
## the UI buttons all share one look. Sizes are fractions of the tile size T.
class_name PipeArt
extends RefCounted

const W_OUTLINE := 0.50
const W_BODY := 0.43
const W_HILITE := 0.08
const W_CHANNEL := 0.13
const W_GOO := 0.21
const FLANGE_LEN := 0.58
const FLANGE_DEPTH := 0.10

static var _font: Font
static var _tank_sb: StyleBoxFlat
static var _base_sb: StyleBoxFlat
## Anti-aliasing for all vector art. Off in PS1 mode for hard pixel edges.
static var aa := not Tuning.PS1_MODE


static func font() -> Font:
	if _font == null:
		var base: Font = ThemeDB.fallback_font
		if Tuning.PS1_MODE and base is FontFile:
			# Hard-edged glyphs, snapped to whole pixels: a period-correct bitmap feel.
			var ff := (base as FontFile).duplicate() as FontFile
			ff.antialiasing = TextServer.FONT_ANTIALIASING_NONE
			ff.hinting = TextServer.HINTING_NORMAL
			ff.subpixel_positioning = TextServer.SUBPIXEL_POSITIONING_DISABLED
			base = ff
		var fv := FontVariation.new()
		fv.base_font = base
		fv.variation_embolden = 0.9
		_font = fv
	return _font


## The rounded, bevelled floor of a board cell.
static func draw_tile_base(ci: CanvasItem, rect: Rect2, pal: Dictionary, checker: bool) -> void:
	if _base_sb == null:
		_base_sb = StyleBoxFlat.new()
		_base_sb.anti_aliasing = aa
	var T := rect.size.x
	var r := rect.grow(-T * 0.035)
	var base: Color = pal["tile"]
	if checker:
		base = base.lightened(0.04)
	_base_sb.bg_color = base
	_base_sb.set_corner_radius_all(int(T * 0.14))
	_base_sb.border_width_bottom = int(maxf(2.0, T * 0.06))
	_base_sb.border_color = pal["tile_lo"]
	ci.draw_style_box(_base_sb, r)
	ci.draw_line(r.position + Vector2(T * 0.14, T * 0.03), Vector2(r.end.x - T * 0.14, r.position.y + T * 0.03), pal["tile_hi"], maxf(1.5, T * 0.03))


static func fade(c: Color, a: float) -> Color:
	return Color(c.r, c.g, c.b, c.a * a)


## Stroke the path from side a to side b (portion t0..t1). `shift` moves the
## stroke sideways toward the upper-left light source, in pixels.
static func stroke(ci: CanvasItem, center: Vector2, T: float, a: int, b: int, width: float, color: Color,
		t0 := 0.0, t1 := 1.0, shift := 0.0) -> void:
	if t1 <= t0:
		return
	if b == Pieces.opposite(a):
		var p0: Vector2 = center + Pieces.SIDE_MID[a] * T
		var p1: Vector2 = center + Pieces.SIDE_MID[b] * T
		var q0 := p0.lerp(p1, t0)
		var q1 := p0.lerp(p1, t1)
		if shift != 0.0:
			var d := (p1 - p0).normalized()
			var perp := Vector2(-d.y, d.x)
			if perp.dot(Vector2(-1, -1)) < 0.0:
				perp = -perp
			q0 += perp * shift
			q1 += perp * shift
		ci.draw_line(q0, q1, color, width, aa)
	else:
		var ma: Vector2 = Pieces.SIDE_MID[a]
		var mb: Vector2 = Pieces.SIDE_MID[b]
		var c := ma + mb
		var a0 := (ma - c).angle()
		var d := wrapf((mb - c).angle() - a0, -PI, PI)
		var r := 0.5 * T
		if shift != 0.0:
			var mid := Vector2.from_angle(a0 + d * 0.5)
			r += shift if mid.dot(Vector2(-1, -1)) > 0.0 else -shift
		var n := maxi(3, int(ceil(16.0 * (t1 - t0))) + 1)
		ci.draw_arc(center + c * T, r, a0 + d * t0, a0 + d * t1, n, color, width, aa)


static func _flange(ci: CanvasItem, center: Vector2, T: float, side: int, dark: Color, metal: Color, light: Color) -> void:
	var m: Vector2 = center + Pieces.SIDE_MID[side] * T
	var inward: Vector2 = -(Pieces.SIDE_MID[side] as Vector2) * 2.0
	var size := Vector2(FLANGE_LEN * T, FLANGE_DEPTH * T)
	if side == Pieces.E or side == Pieces.W:
		size = Vector2(size.y, size.x)
	var cpos := m + inward * FLANGE_DEPTH * T * 0.5
	var rect := Rect2(cpos - size * 0.5, size)
	ci.draw_rect(rect, dark)
	var inner := rect.grow(-maxf(1.0, T * 0.022))
	ci.draw_rect(inner, metal)
	ci.draw_rect(Rect2(inner.position, Vector2(inner.size.x, maxf(1.0, inner.size.y * 0.3))), fade(light, 0.7))


## A pipe piece. With `tile`, draws its goo, one-way arrows and reservoir tank.
static func draw_pipe(ci: CanvasItem, center: Vector2, T: float, piece: int, pal: Dictionary,
		tile: Tile = null, alpha := 1.0, time := 0.0, bubbles := true) -> void:
	var oneway := tile != null and tile.special == Tile.SP_ONEWAY
	var reservoir := tile != null and tile.special == Tile.SP_RESERVOIR
	var metal: Color = fade(pal["brass"] if oneway else pal["metal"], alpha)
	var dark: Color = fade(pal["brass_dark"] if oneway else pal["metal_dark"], alpha)
	var light: Color = fade(pal["metal_light"], alpha)
	var shade: Color = fade((pal["brass"] if oneway else pal["metal"]).darkened(0.35), alpha)
	var chan: Color = fade((pal["brass"] if oneway else pal["metal"]).darkened(0.55), alpha)
	var chans := Pieces.channels(piece)
	for i in chans.size():
		var a: int = chans[i][0]
		var b: int = chans[i][1]
		stroke(ci, center, T, a, b, W_OUTLINE * T, dark)
		stroke(ci, center, T, a, b, W_BODY * T, metal)
		stroke(ci, center, T, a, b, W_HILITE * T, fade(light, 0.8), 0.0, 1.0, W_BODY * T * 0.3)
		stroke(ci, center, T, a, b, W_HILITE * T, shade, 0.0, 1.0, -W_BODY * T * 0.3)
		_flange(ci, center, T, a, dark, metal, light)
		_flange(ci, center, T, b, dark, metal, light)
		stroke(ci, center, T, a, b, W_CHANNEL * T, chan)
		stroke(ci, center, T, a, b, W_CHANNEL * T * 0.35, fade(Color(0, 0, 0, 0.35), alpha), 0.0, 1.0, W_CHANNEL * T * 0.25)
		if oneway:
			_chevrons(ci, center, T, tile.oneway_entry, Pieces.exit_dir(piece, tile.oneway_entry), fade(pal["brass"].lightened(0.45), alpha))
		if tile != null and not reservoir:
			var ch := i if piece == Pieces.CROSS else 0
			if tile.fill_entry[ch] >= 0:
				var en: int = tile.fill_entry[ch]
				goo(ci, center, T, en, Pieces.exit_dir(piece, en), tile.fill[ch], tile.fill_color[ch], alpha, time, tile.rnd + i * 37, bubbles)
	if reservoir:
		_tank(ci, center, T, tile, pal, alpha, time)


## Goo inside a channel, from the entry side up to progress p.
static func goo(ci: CanvasItem, center: Vector2, T: float, en: int, ex: int, p: float, col: Color,
		alpha := 1.0, time := 0.0, rnd := 0, bubbles := true) -> void:
	var w := W_GOO * T
	var c := fade(col, alpha)
	stroke(ci, center, T, en, ex, w, c, 0.0, p)
	stroke(ci, center, T, en, ex, w * 0.3, fade(col.lightened(0.6), 0.85 * alpha), 0.0, p, w * 0.22)
	if p < 1.0:
		var hp := center + Pieces.path_point(en, ex, p) * T
		ci.draw_circle(hp, w * 0.62, c)
		ci.draw_circle(hp + Vector2(-w, -w) * 0.15, w * 0.24, fade(col.lightened(0.7), alpha))
	elif bubbles:
		for k in 2:
			var tt := fposmod(time * 0.55 + k * 0.5 + float(rnd % 97) / 97.0, 1.0)
			var bp := center + Pieces.path_point(en, ex, tt) * T
			ci.draw_circle(bp, w * 0.17, fade(col.lightened(0.75), 0.75 * alpha))


static func _chevrons(ci: CanvasItem, center: Vector2, T: float, en: int, ex: int, col: Color) -> void:
	for t in [0.3, 0.72]:
		var p := center + Pieces.path_point(en, ex, t) * T
		var p2 := center + Pieces.path_point(en, ex, t + 0.02) * T
		var tan := (p2 - p).normalized()
		var perp := Vector2(-tan.y, tan.x)
		var pts := PackedVector2Array([p - tan * 0.05 * T + perp * 0.075 * T, p + tan * 0.06 * T, p - tan * 0.05 * T - perp * 0.075 * T])
		ci.draw_polyline(pts, col, maxf(2.0, T * 0.045), aa)


static func _sb() -> StyleBoxFlat:
	if _tank_sb == null:
		_tank_sb = StyleBoxFlat.new()
		_tank_sb.anti_aliasing = aa
	return _tank_sb


## Reservoir: a big glass tank the goo slowly fills.
static func _tank(ci: CanvasItem, center: Vector2, T: float, tile: Tile, pal: Dictionary, alpha: float, time: float) -> void:
	var p: float = tile.fill[0] if tile.fill_entry[0] >= 0 else 0.0
	var en: int = tile.fill_entry[0]
	var ex: int = Pieces.exit_dir(tile.piece, en) if en >= 0 else -1
	if en >= 0:
		goo(ci, center, T, en, ex, minf(1.0, p * 9.0) * 0.12, tile.fill_color[0], alpha)
	var size := Vector2(0.80, 0.80) * T
	var rect := Rect2(center - size * 0.5, size)
	var sb := _sb()
	sb.bg_color = fade(pal["metal_dark"], alpha)
	sb.set_corner_radius_all(int(T * 0.16))
	sb.set_border_width_all(0)
	ci.draw_style_box(sb, rect)
	var inner := rect.grow(-T * 0.07)
	sb.bg_color = fade(pal["channel"].lightened(0.08), alpha)
	sb.set_corner_radius_all(int(T * 0.11))
	ci.draw_style_box(sb, inner)
	if p > 0.0:
		var gcol: Color = tile.fill_color[0]
		var h := inner.size.y * p
		var lr := Rect2(inner.position.x, inner.end.y - h, inner.size.x, h)
		sb.bg_color = fade(gcol, alpha)
		sb.set_corner_radius_all(int(T * 0.11) if p > 0.85 else 0)
		sb.corner_radius_bottom_left = int(T * 0.11)
		sb.corner_radius_bottom_right = int(T * 0.11)
		ci.draw_style_box(sb, lr)
		if p < 1.0:
			var wave := PackedVector2Array()
			for i in 9:
				var x := inner.position.x + inner.size.x * i / 8.0
				wave.append(Vector2(x, inner.end.y - h + sin(time * 5.0 + i * 1.3) * T * 0.015))
			ci.draw_polyline(wave, fade(gcol.lightened(0.6), alpha), maxf(2.0, T * 0.03), aa)
	for k in [0.25, 0.5, 0.75]:
		var y: float = inner.end.y - inner.size.y * k
		ci.draw_line(Vector2(inner.end.x - T * 0.12, y), Vector2(inner.end.x - T * 0.03, y), fade(pal["metal_light"], 0.6 * alpha), maxf(1.0, T * 0.02))
	ci.draw_line(inner.position + Vector2(T * 0.07, T * 0.08), Vector2(inner.position.x + T * 0.07, inner.end.y - T * 0.12),
			fade(Color.WHITE, 0.28 * alpha), maxf(2.0, T * 0.045), aa)
	for corner in [rect.position, Vector2(rect.end.x, rect.position.y), rect.end, Vector2(rect.position.x, rect.end.y)]:
		var cc: Vector2 = corner + (center - corner).normalized() * T * 0.06
		ci.draw_circle(cc, T * 0.025, fade(pal["metal_light"], 0.8 * alpha))
	if en >= 0 and p >= 0.88:
		# Goo spilling out of the tank into the exit stub.
		var t1 := lerpf(0.9, 1.0, clampf((p - 0.88) / 0.12, 0.0, 1.0))
		stroke(ci, center, T, en, ex, W_GOO * T, fade(tile.fill_color[0], alpha), 0.9, t1)


## The goo source: a pump tank with a riser going north.
static func draw_source(ci: CanvasItem, center: Vector2, T: float, tile: Tile, pal: Dictionary, goo_col: Color,
		time: float, countdown_frac: float) -> void:
	var dark: Color = pal["metal_dark"]
	var metal: Color = pal["metal"]
	var light: Color = pal["metal_light"]
	stroke(ci, center, T, Pieces.S, Pieces.N, W_OUTLINE * T, dark, 0.5, 1.0)
	stroke(ci, center, T, Pieces.S, Pieces.N, W_BODY * T, metal, 0.5, 1.0)
	stroke(ci, center, T, Pieces.S, Pieces.N, W_HILITE * T, fade(light, 0.75), 0.5, 1.0, W_BODY * T * 0.25)
	_flange(ci, center, T, Pieces.N, dark, metal, light)
	stroke(ci, center, T, Pieces.S, Pieces.N, W_CHANNEL * T, pal["channel"], 0.5, 1.0)
	if tile.fill_entry[0] >= 0:
		var p: float = tile.fill[0]
		stroke(ci, center, T, Pieces.S, Pieces.N, W_GOO * T, tile.fill_color[0], 0.5, maxf(0.5, p))
	var rect := Rect2(center + Vector2(-0.44, -0.08) * T, Vector2(0.88, 0.52) * T)
	var sb := _sb()
	sb.set_border_width_all(0)
	sb.bg_color = dark
	sb.set_corner_radius_all(int(T * 0.14))
	ci.draw_style_box(sb, rect)
	var inner := rect.grow(-T * 0.06)
	sb.bg_color = goo_col.darkened(0.25)
	sb.set_corner_radius_all(int(T * 0.1))
	ci.draw_style_box(sb, inner)
	for i in 4:
		var bx := inner.position.x + inner.size.x * fposmod(i * 0.29 + time * 0.07, 1.0)
		var by := inner.end.y - inner.size.y * fposmod(i * 0.37 + time * 0.6, 1.0)
		ci.draw_circle(Vector2(bx, by), T * 0.03, goo_col.lightened(0.5))
	ci.draw_line(inner.position + Vector2(T * 0.06, T * 0.05), Vector2(inner.end.x - T * 0.06, inner.position.y + T * 0.05),
			fade(Color.WHITE, 0.35), maxf(2.0, T * 0.03), aa)
	# Pressure gauge: fills as the countdown runs out.
	var gc := center + Vector2(0.0, 0.2) * T
	ci.draw_circle(gc, T * 0.15, dark)
	ci.draw_circle(gc, T * 0.12, Color(0.95, 0.95, 0.9))
	var ang := lerpf(PI * 0.75, PI * 2.25, clampf(countdown_frac, 0.0, 1.0))
	ci.draw_arc(gc, T * 0.09, PI * 0.75, ang, 16, Color(0.9, 0.2, 0.15), maxf(2.0, T * 0.03), aa)
	ci.draw_line(gc, gc + Vector2.from_angle(ang) * T * 0.1, Color(0.15, 0.15, 0.15), maxf(2.0, T * 0.025), aa)


static func draw_rock(ci: CanvasItem, center: Vector2, T: float, tile: Tile, pal: Dictionary) -> void:
	if tile.shape.is_empty():
		return
	var outline := PackedVector2Array()
	var body := PackedVector2Array()
	var hi := PackedVector2Array()
	var shadow := PackedVector2Array()
	for p in tile.shape:
		outline.append(center + p * T * 1.1)
		body.append(center + p * T)
		hi.append(center + (p * 0.6 + Vector2(-0.07, -0.08)) * T)
		shadow.append(center + p * T * 1.1 + Vector2(0.04, 0.07) * T)
	ci.draw_colored_polygon(shadow, Color(0, 0, 0, 0.35))
	ci.draw_colored_polygon(outline, pal["rock_dark"])
	ci.draw_colored_polygon(body, pal["rock"])
	ci.draw_colored_polygon(hi, fade(pal["rock_hi"], 0.45))
	var r := tile.rnd
	for k in 3:
		var a := float((r >> (k * 5)) % 360) * PI / 180.0
		var d := 0.12 + float((r >> (k * 3 + 2)) % 10) / 60.0
		ci.draw_circle(center + Vector2.from_angle(a) * d * T, T * (0.025 + 0.01 * k), fade(pal["rock_dark"], 0.7))
	ci.draw_line(center + Vector2(-0.05, 0.05) * T, center + Vector2(0.1, 0.16) * T, fade(pal["rock_dark"], 0.8), maxf(1.5, T * 0.025), aa)


static func draw_coin(ci: CanvasItem, pos: Vector2, radius: float, value: int, time: float, show_text := true, bob := true) -> void:
	if bob:
		pos.y += sin(time * 3.0 + pos.x * 0.05) * radius * 0.08
	ci.draw_circle(pos + Vector2(radius * 0.1, radius * 0.16), radius, Color(0, 0, 0, 0.3))
	ci.draw_circle(pos, radius, Color("8a5a00"))
	ci.draw_circle(pos, radius * 0.84, Color("ffc928"))
	ci.draw_circle(pos + Vector2(-0.2, -0.2) * radius, radius * 0.4, Color(1, 1, 0.8, 0.35))
	var star := PackedVector2Array()
	var spin := time * 1.5
	for i in 10:
		var rr := radius * (0.55 if i % 2 == 0 else 0.24)
		star.append(pos + Vector2.from_angle(-PI / 2 + i * PI / 5 + sin(spin) * 0.1) * rr)
	ci.draw_colored_polygon(star, Color("fff6c0"))
	if show_text:
		var fs := int(maxf(10.0, radius * 0.75))
		var txt := "+%d" % value
		var tp := pos + Vector2(-radius * 2.0, radius + fs * 1.0)
		ci.draw_string_outline(font(), tp, txt, HORIZONTAL_ALIGNMENT_CENTER, radius * 4.0, fs, int(fs * 0.35), Color(0.2, 0.1, 0.0))
		ci.draw_string(font(), tp, txt, HORIZONTAL_ALIGNMENT_CENTER, radius * 4.0, fs, Color("fff2a0"))


static func powerup_color(kind: int) -> Color:
	match kind:
		Tile.PU_SLOW:
			return Color("4ab8ff")
		Tile.PU_BOMB:
			return Color("ff4a3a")
		Tile.PU_WILD:
			return Color("d66bff")
	return Color.WHITE


static func draw_powerup(ci: CanvasItem, pos: Vector2, radius: float, kind: int, time: float, bob := true) -> void:
	if bob:
		pos.y += sin(time * 3.4 + pos.x * 0.07) * radius * 0.08
	ci.draw_circle(pos + Vector2(radius * 0.1, radius * 0.16), radius, Color(0, 0, 0, 0.3))
	match kind:
		Tile.PU_SLOW:
			ci.draw_circle(pos, radius, Color("0d3a66"))
			ci.draw_circle(pos, radius * 0.84, Color("bfe6ff"))
			for i in 12:
				var a := i * TAU / 12.0
				ci.draw_line(pos + Vector2.from_angle(a) * radius * 0.62, pos + Vector2.from_angle(a) * radius * 0.74, Color("0d3a66"), maxf(1.0, radius * 0.06))
			var t := time * 0.6
			ci.draw_line(pos, pos + Vector2.from_angle(t - PI / 2) * radius * 0.55, Color("0d3a66"), maxf(2.0, radius * 0.12), aa)
			ci.draw_line(pos, pos + Vector2.from_angle(t * 0.08 - PI / 2 + 2.0) * radius * 0.38, Color("0d3a66"), maxf(2.0, radius * 0.14), aa)
			ci.draw_circle(pos, radius * 0.1, Color("ff4a3a"))
		Tile.PU_BOMB:
			ci.draw_line(pos + Vector2(radius * 0.35, -radius * 0.7), pos + Vector2(radius * 0.7, -radius * 1.05), Color("c89a5a"), maxf(2.0, radius * 0.12), aa)
			var flick := 0.7 + 0.3 * sin(time * 30.0)
			ci.draw_circle(pos + Vector2(radius * 0.72, -radius * 1.08), radius * 0.2 * flick, Color("ffd23a"))
			ci.draw_circle(pos + Vector2(radius * 0.72, -radius * 1.08), radius * 0.1 * flick, Color.WHITE)
			ci.draw_circle(pos, radius * 0.9, Color("101014"))
			ci.draw_circle(pos, radius * 0.78, Color("2e2e38"))
			ci.draw_circle(pos + Vector2(-0.3, -0.3) * radius, radius * 0.24, Color(1, 1, 1, 0.45))
			ci.draw_rect(Rect2(pos + Vector2(radius * 0.12, -radius * 0.95), Vector2(radius * 0.4, radius * 0.3)), Color("55555f"))
		Tile.PU_WILD:
			var hue := fposmod(time * 0.25, 1.0)
			ci.draw_circle(pos, radius, Color.from_hsv(hue, 0.8, 0.5))
			ci.draw_circle(pos, radius * 0.84, Color.from_hsv(fposmod(hue + 0.15, 1.0), 0.6, 1.0))
			var star := PackedVector2Array()
			for i in 10:
				var rr := radius * (0.72 if i % 2 == 0 else 0.34)
				star.append(pos + Vector2.from_angle(-PI / 2 + i * PI / 5 + time * 0.8) * rr)
			ci.draw_colored_polygon(star, Color(1, 1, 1, 0.9))
			var fs := int(maxf(10.0, radius * 0.9))
			ci.draw_string(font(), pos + Vector2(-radius, fs * 0.36), "?", HORIZONTAL_ALIGNMENT_CENTER, radius * 2.0, fs, Color.from_hsv(hue, 0.9, 0.55))
