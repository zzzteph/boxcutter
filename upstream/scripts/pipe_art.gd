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
const NARROW_SCALE := 0.6     ## Width of a narrow pipe relative to a normal one.
const W_BULGE := 0.74         ## Reservoir: width of the swollen middle section.
const W_BULGE_GOO := 0.42     ## Reservoir: width of the goo chamber inside it.
const BULGE_T0 := 0.2         ## Reservoir: where the chamber starts along the pipe.

static var _font: Font
static var _tank_sb: StyleBoxFlat
static var _base_sb: StyleBoxFlat
## Anti-aliasing for all vector art. Off in PS1 mode for hard pixel edges.
static var aa := Tuning.SMOOTH_EDGES


static func font() -> Font:
	if _font == null:
		var base: Font = ThemeDB.fallback_font
		if not Tuning.SMOOTH_EDGES and base is FontFile:
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


## A closed tile: a plain raised steel block (opening it shows what's under).
static func draw_locked(ci: CanvasItem, rect: Rect2, pal: Dictionary) -> void:
	if _base_sb == null:
		_base_sb = StyleBoxFlat.new()
	_base_sb.anti_aliasing = aa
	var T := rect.size.x
	var r := rect.grow(-T * 0.035)
	var block: Color = (pal["metal_dark"] as Color).lerp(pal["tile"], 0.4)
	_base_sb.bg_color = block
	_base_sb.set_corner_radius_all(int(T * 0.1))
	_base_sb.border_width_bottom = int(maxf(2.0, T * 0.08))
	_base_sb.border_color = block.darkened(0.45)
	ci.draw_style_box(_base_sb, r)
	_base_sb.border_width_bottom = 0
	# Raised face: a lighter top edge and a slightly lighter centre panel.
	var light: Color = (pal["metal"] as Color).lightened(0.1)
	ci.draw_line(r.position + Vector2(T * 0.1, T * 0.04), Vector2(r.end.x - T * 0.1, r.position.y + T * 0.04), fade(light, 0.7), maxf(1.0, T * 0.035))
	_base_sb.bg_color = block.lightened(0.06)
	_base_sb.set_corner_radius_all(int(T * 0.06))
	ci.draw_style_box(_base_sb, Rect2(r.position + Vector2(T * 0.14, T * 0.14), r.size - Vector2(T * 0.28, T * 0.3)))
	for cpos in [Vector2(0.15, 0.15), Vector2(0.85, 0.15), Vector2(0.15, 0.8), Vector2(0.85, 0.8)]:
		var p: Vector2 = rect.position + cpos * T
		ci.draw_circle(p, T * 0.04, block.darkened(0.5))
		ci.draw_circle(p - Vector2(T, T) * 0.01, T * 0.025, light)


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
		tile: Tile = null, alpha := 1.0, time := 0.0, bubbles := true, narrow := false) -> void:
	var oneway := tile != null and tile.special == Tile.SP_ONEWAY
	# Narrow pipes: the same steel, as a thin tube between full-size couplings.
	var thin := narrow or (tile != null and tile.narrow)
	var k := NARROW_SCALE if thin else 1.0
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
		stroke(ci, center, T, a, b, W_OUTLINE * T * k, dark)
		stroke(ci, center, T, a, b, W_BODY * T * k, metal)
		stroke(ci, center, T, a, b, W_HILITE * T * k, fade(light, 0.8), 0.0, 1.0, W_BODY * T * k * 0.3)
		stroke(ci, center, T, a, b, W_HILITE * T * k, shade, 0.0, 1.0, -W_BODY * T * k * 0.3)
		_flange(ci, center, T, a, dark, metal, light)
		_flange(ci, center, T, b, dark, metal, light)
		if thin:
			# A small coupling ring in the middle, like the flanges.
			stroke(ci, center, T, a, b, W_OUTLINE * T * 0.8, dark, 0.45, 0.55)
			stroke(ci, center, T, a, b, W_BODY * T * 0.72, metal, 0.465, 0.535)
		stroke(ci, center, T, a, b, W_CHANNEL * T * k, chan)
		stroke(ci, center, T, a, b, W_CHANNEL * T * k * 0.35, fade(Color(0, 0, 0, 0.35), alpha), 0.0, 1.0, W_CHANNEL * T * k * 0.25)
		if reservoir:
			_bulge(ci, center, T, a, b, dark, metal, light, shade, chan, alpha)
		if oneway:
			_chevrons(ci, center, T, tile.oneway_entry, Pieces.exit_dir(piece, tile.oneway_entry), fade(pal["brass"].lightened(0.45), alpha))
		if tile != null:
			var ch := i if piece == Pieces.CROSS else 0
			if tile.fill_entry[ch] >= 0:
				var en: int = tile.fill_entry[ch]
				var ex := Pieces.exit_dir(piece, en)
				goo(ci, center, T, en, ex, tile.fill[ch], tile.fill_color[ch], alpha, time, tile.rnd + i * 37, bubbles, k)
				if reservoir and tile.fill[ch] > BULGE_T0:
					# The wide chamber fills as the goo crawls through it.
					var t1 := minf(tile.fill[ch], 1.0 - BULGE_T0)
					stroke(ci, center, T, en, ex, W_BULGE_GOO * T, fade(tile.fill_color[ch], alpha), BULGE_T0, t1)
					stroke(ci, center, T, en, ex, W_BULGE_GOO * T * 0.25, fade(tile.fill_color[ch].lightened(0.6), 0.85 * alpha), BULGE_T0, t1, W_BULGE_GOO * T * 0.22)


## Goo inside a channel, from the entry side up to progress p.
static func goo(ci: CanvasItem, center: Vector2, T: float, en: int, ex: int, p: float, col: Color,
		alpha := 1.0, time := 0.0, rnd := 0, bubbles := true, w_scale := 1.0) -> void:
	var w := W_GOO * T * w_scale
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


## Reservoir: the same steel pipe swelling into a wide chamber in the middle,
## which the goo takes a long time to fill.
static func _bulge(ci: CanvasItem, center: Vector2, T: float, a: int, b: int,
		dark: Color, metal: Color, light: Color, shade: Color, chan: Color, alpha: float) -> void:
	var t0 := BULGE_T0 - 0.04
	var t1 := 1.0 - t0
	stroke(ci, center, T, a, b, W_BULGE * T + W_OUTLINE * T * 0.2, dark, t0, t1)
	stroke(ci, center, T, a, b, W_BULGE * T, metal, t0, t1)
	stroke(ci, center, T, a, b, W_HILITE * T * 1.4, fade(light, 0.8), t0, t1, W_BULGE * T * 0.32)
	stroke(ci, center, T, a, b, W_HILITE * T * 1.4, shade, t0, t1, -W_BULGE * T * 0.32)
	# Rings where the pipe widens.
	for r in [[t0, t0 + 0.05], [t1 - 0.05, t1]]:
		stroke(ci, center, T, a, b, W_BULGE * T + W_OUTLINE * T * 0.3, dark, r[0], r[1])
		stroke(ci, center, T, a, b, W_BULGE * T * 0.96, metal.lightened(0.08), r[0] + 0.01, r[1] - 0.01)
	stroke(ci, center, T, a, b, W_BULGE_GOO * T * 1.1, chan, BULGE_T0, 1.0 - BULGE_T0)
	stroke(ci, center, T, a, b, W_BULGE_GOO * T * 0.4, fade(Color(0, 0, 0, 0.35), alpha), BULGE_T0, 1.0 - BULGE_T0, W_BULGE_GOO * T * 0.3)


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


static func powerup_color(kind: int) -> Color:
	match kind:
		Tile.PU_SLOW:
			return Color("4ab8ff")
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
