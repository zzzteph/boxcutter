## ============================================================================
##  STATION LOGO - the "UPSTREAM" nameplate on the main menu.
## ============================================================================
## A riveted steel plate like the ones bolted to pump-station machinery: a
## pressure gauge, the name in stencil letters (the bridges cut across them),
## and a hazard-striped strip along the bottom.
class_name StationLogo
extends Control

const NAME := "UPSTREAM"
const SUBTITLE := "PUMP STATION  -  KEEP THE WATER RISING"
const BASE_FONT := 104
const STEEL := Color("2a3640")
const STEEL_LIGHT := Color("4a5a66")
const STEEL_DARK := Color("11181d")
const LETTER := Color("e2eef4")
const WATER := Color("3ab4ff")
const HAZARD := Color("ffc928")

var scale_k := 1.0
var time := 0.0
var _sb := StyleBoxFlat.new()


func _ready() -> void:
	mouse_filter = Control.MOUSE_FILTER_IGNORE
	_sb.anti_aliasing = PipeArt.aa
	_update_size()


func _process(dt: float) -> void:
	if is_visible_in_tree():
		time += dt
		queue_redraw()


## Fit the plate into `width` pixels (never larger than its design size).
func fit_width(width: float) -> void:
	var k := 1.0
	var full := _plate_size(1.0).x + 12.0
	if full > width:
		k = maxf(0.4, width / full)
	if not is_equal_approx(k, scale_k):
		scale_k = k
		_update_size()


func _font_size(k: float) -> int:
	return int(BASE_FONT * k)


func _plate_size(k: float) -> Vector2:
	var f := PipeArt.font()
	var text := f.get_string_size(NAME, HORIZONTAL_ALIGNMENT_LEFT, -1, _font_size(k))
	var gauge := 76.0 * k
	return Vector2(40.0 * k + gauge + 24.0 * k + text.x + 44.0 * k, text.y * 0.9 + 44.0 * k + 18.0 * k)


func _update_size() -> void:
	var p := _plate_size(scale_k)
	custom_minimum_size = Vector2(p.x + 12.0, p.y + 46.0 * scale_k)
	update_minimum_size()


func _draw() -> void:
	var k := scale_k
	var plate := Rect2(Vector2((size.x - _plate_size(k).x) * 0.5, 0), _plate_size(k))
	var f := PipeArt.font()
	var fs := _font_size(k)
	# Hard drop shadow, then the plate.
	draw_rect(Rect2(plate.position + Vector2(7, 7) * k, plate.size), Color(0, 0, 0, 0.6))
	_sb.bg_color = STEEL
	_sb.border_color = STEEL_DARK
	_sb.set_border_width_all(int(maxf(2.0, 4.0 * k)))
	_sb.set_corner_radius_all(int(4.0 * k))
	draw_style_box(_sb, plate)
	draw_line(plate.position + Vector2(6, 6) * k, Vector2(plate.end.x - 6.0 * k, plate.position.y + 6.0 * k), STEEL_LIGHT, maxf(2.0, 3.0 * k))
	# Hazard strip along the bottom.
	var band := Rect2(plate.position.x + 5.0 * k, plate.end.y - 22.0 * k, plate.size.x - 10.0 * k, 16.0 * k)
	_hazard(band, k)
	# Rivets.
	for c in [Vector2(14, 16), Vector2(plate.size.x / k - 14, 16), Vector2(14, plate.size.y / k - 34), Vector2(plate.size.x / k - 14, plate.size.y / k - 34)]:
		var p: Vector2 = plate.position + c * k
		draw_circle(p, 5.0 * k, STEEL_DARK)
		draw_circle(p - Vector2(1, 1) * k, 3.0 * k, STEEL_LIGHT.lightened(0.3))
	# Pressure gauge.
	var top := plate.position.y + 12.0 * k
	var inner_h := band.position.y - top
	var gc := Vector2(plate.position.x + 40.0 * k + 38.0 * k, top + inner_h * 0.5)
	_gauge(gc, 36.0 * k, k)
	# Name in stencil letters.
	var tx := gc.x + 38.0 * k + 24.0 * k
	var baseline := top + inner_h * 0.5 + fs * 0.36
	draw_string_outline(f, Vector2(tx, baseline), NAME, HORIZONTAL_ALIGNMENT_LEFT, -1, fs, int(maxf(4.0, 10.0 * k)), STEEL_DARK)
	draw_string(f, Vector2(tx, baseline), NAME, HORIZONTAL_ALIGNMENT_LEFT, -1, fs, LETTER)
	var tw := f.get_string_size(NAME, HORIZONTAL_ALIGNMENT_LEFT, -1, fs).x
	# Stencil bridges: a cut through every letter, in the plate colour.
	draw_rect(Rect2(tx - 4.0 * k, baseline - fs * 0.40, tw + 8.0 * k, maxf(3.0, fs * 0.065)), STEEL)
	# A water-blue rule under the name, then the subtitle beneath the plate.
	draw_rect(Rect2(tx, baseline + fs * 0.1, tw, maxf(2.0, 4.0 * k)), WATER)
	var sfs := int(maxf(11.0, 19.0 * k))
	var sub_w := f.get_string_size(SUBTITLE, HORIZONTAL_ALIGNMENT_LEFT, -1, sfs).x
	var sp := Vector2((size.x - sub_w) * 0.5, plate.end.y + 30.0 * k)
	draw_string_outline(f, sp, SUBTITLE, HORIZONTAL_ALIGNMENT_LEFT, -1, sfs, 4, Color(0, 0, 0, 0.85))
	draw_string(f, sp, SUBTITLE, HORIZONTAL_ALIGNMENT_LEFT, -1, sfs, Color("8fb8cc"))


func _hazard(band: Rect2, k: float) -> void:
	draw_rect(band, HAZARD)
	var w := 14.0 * k
	var x := band.position.x - band.size.y
	while x < band.end.x:
		var pts := PackedVector2Array()
		for v in [Vector2(x, band.end.y), Vector2(x + w * 0.5, band.end.y), Vector2(x + w * 0.5 + band.size.y, band.position.y), Vector2(x + band.size.y, band.position.y)]:
			pts.append(Vector2(clampf(v.x, band.position.x, band.end.x), v.y))
		if pts[1].x - pts[0].x > 0.5 or pts[2].x - pts[3].x > 0.5:
			draw_colored_polygon(pts, Color("1a1a1a"))
		x += w
	draw_rect(band, STEEL_DARK, false, maxf(1.0, 2.0 * k))


func _gauge(c: Vector2, r: float, k: float) -> void:
	draw_circle(c + Vector2(3, 3) * k, r, Color(0, 0, 0, 0.5))
	draw_circle(c, r, STEEL_DARK)
	draw_circle(c, r * 0.86, Color("dfe6e8"))
	# Red zone and ticks on a 270-degree dial.
	var a0 := PI * 0.75
	var a1 := PI * 2.25
	draw_arc(c, r * 0.68, lerpf(a0, a1, 0.78), a1, 12, Color("e0402a"), maxf(2.0, r * 0.12), PipeArt.aa)
	for i in 11:
		var a := lerpf(a0, a1, i / 10.0)
		var inner := 0.56 if i % 5 == 0 else 0.64
		draw_line(c + Vector2.from_angle(a) * r * inner, c + Vector2.from_angle(a) * r * 0.76, STEEL_DARK, maxf(1.0, r * (0.06 if i % 5 == 0 else 0.035)))
	# The needle hovers near the red, twitching with the pump.
	var v := 0.66 + 0.06 * sin(time * 2.3) + 0.02 * sin(time * 17.0)
	var na := lerpf(a0, a1, v)
	draw_line(c, c + Vector2.from_angle(na) * r * 0.7, Color("c0201a"), maxf(2.0, r * 0.08), PipeArt.aa)
	draw_circle(c, r * 0.12, STEEL_DARK)
	draw_circle(c - Vector2(r, r) * 0.03, r * 0.05, STEEL_LIGHT)
