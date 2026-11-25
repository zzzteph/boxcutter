## ============================================================================
##  TITLE BACKDROP - the main screen's own background.
## ============================================================================
## A pump-station wall (steel plates, seams, rivets, a hazard strip on the
## floor) and two pipe runs climbing the screen edges with water surging
## through them on a loop. The pipes are drawn once per screen size; only the
## water is redrawn each frame.
class_name TitleBackdrop
extends Control


class DrawLayer:
	extends Control
	var draw_cb: Callable

	func _draw() -> void:
		draw_cb.call(self)


const FLOW_SPEED := 3.0        ## Cells per second the goo advances.
const PAUSE_CELLS := 5.0       ## Pause at the top before the run drains and refills.

var time := 0.0
var _cell := 64.0
var _paths: Array = []         ## Each path: Array of {c: Vector2i, en: int, ex: int}
var _pipes: DrawLayer
var _goo: DrawLayer
var _last_size := Vector2.ZERO
var _x0 := 0.0                 ## Left offset that centres the pipe grid.
var _glow: GradientTexture2D


func _ready() -> void:
	mouse_filter = Control.MOUSE_FILTER_IGNORE
	var g := Gradient.new()
	g.set_color(0, Color(1, 1, 1, 1))
	g.set_color(1, Color(1, 1, 1, 0))
	_glow = GradientTexture2D.new()
	_glow.gradient = g
	_glow.fill = GradientTexture2D.FILL_RADIAL
	_glow.fill_from = Vector2(0.5, 0.5)
	_glow.fill_to = Vector2(1.0, 0.5)
	_glow.width = 128
	_glow.height = 128
	_pipes = _make_layer(_draw_pipes)
	_goo = _make_layer(_draw_goo)


func _make_layer(cb: Callable) -> DrawLayer:
	var l := DrawLayer.new()
	l.draw_cb = cb
	l.mouse_filter = Control.MOUSE_FILTER_IGNORE
	l.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(l)
	return l


func _process(dt: float) -> void:
	if not is_visible_in_tree():
		return
	time += dt
	if size != _last_size:
		_last_size = size
		_build_paths()
		queue_redraw()
		_pipes.queue_redraw()
	_goo.queue_redraw()
	queue_redraw()


## Two pipe runs from below the screen to above it, hugging the left and right
## edges so they frame the title without crossing the text.
func _build_paths() -> void:
	_paths.clear()
	_cell = clampf(minf(size.x, size.y) * 0.12, 44.0, 104.0)
	var cols := maxi(4, int(floor(size.x / _cell)))
	_x0 = (size.x - cols * _cell) * 0.5
	var rows := int(ceil(size.y / _cell)) + 1
	var lanes := 2 if size.x >= 900.0 else 1
	var rng := RandomNumberGenerator.new()
	rng.seed = 7
	for side in 2:
		var lo := 0 if side == 0 else cols - lanes
		var hi := lanes - 1 if side == 0 else cols - 1
		var c := lo if side == 0 else hi
		var r := -1
		var entry := Pieces.S
		var path := []
		var since_turn := 3
		while r <= rows:
			var exit := Pieces.N
			if lanes > 1 and since_turn >= 2 and r >= 0 and rng.randf() < 0.45:
				var dir := Pieces.E if c == lo else Pieces.W
				if (dir == Pieces.E and c < hi) or (dir == Pieces.W and c > lo):
					exit = dir
			if exit == entry:
				exit = Pieces.N
			path.append({"c": Vector2i(c, r), "en": entry, "ex": exit})
			var v: Vector2i = Pieces.DIR_VEC[exit]
			c += v.x
			r += v.y
			entry = Pieces.opposite(exit)
			since_turn = 0 if exit != Pieces.N else since_turn + 1
		_paths.append(path)


func _cell_center(cell: Vector2i) -> Vector2:
	return Vector2(_x0 + (cell.x + 0.5) * _cell, size.y - (cell.y + 0.5) * _cell)


func _draw() -> void:
	# Pump-station wall: dark steel plates with seams and rivets.
	var top := Color("1f2c35")
	var bottom := Color("0a1015")
	draw_polygon(PackedVector2Array([Vector2.ZERO, Vector2(size.x, 0), size, Vector2(0, size.y)]),
			PackedColorArray([top, top, bottom, bottom]))
	var pw := maxf(160.0, _cell * 3.0)
	var ph := maxf(120.0, _cell * 2.2)
	var seam := Color(0, 0, 0, 0.35)
	var lit := Color(1, 1, 1, 0.05)
	var x := fposmod(size.x * 0.5, pw) - pw
	while x < size.x:
		draw_rect(Rect2(x, 0, 2, size.y), seam)
		draw_rect(Rect2(x + 2, 0, 1, size.y), lit)
		x += pw
	var y := ph * 0.5
	while y < size.y:
		draw_rect(Rect2(0, y, size.x, 2), seam)
		draw_rect(Rect2(0, y + 2, size.x, 1), lit)
		var rx := fposmod(size.x * 0.5, pw) - pw
		while rx < size.x + pw:
			for d in [-10.0, 10.0]:
				draw_circle(Vector2(rx + d + 2.0, y + d * 0.0 + 9.0), 2.5, Color(0, 0, 0, 0.45))
				draw_circle(Vector2(rx + d + 1.5, y + 8.5), 1.2, Color(1, 1, 1, 0.12))
			rx += pw
		y += ph
	# Cold blue light behind the nameplate.
	var c := Vector2(size.x * 0.5, size.y * 0.36)
	var gr := minf(size.x, size.y) * 0.6
	draw_texture_rect(_glow, Rect2(c - Vector2(gr, gr), Vector2(gr, gr) * 2.0), false, Color(0.23, 0.7, 1.0, 0.13))
	# Hazard strip along the floor.
	var band := Rect2(0, size.y - maxf(14.0, _cell * 0.3), size.x, maxf(14.0, _cell * 0.3))
	draw_rect(band, Color("ffc928"))
	var w := band.size.y * 1.6
	var sx := -band.size.y
	while sx < size.x:
		draw_colored_polygon(PackedVector2Array([Vector2(sx, band.end.y), Vector2(sx + w * 0.5, band.end.y),
				Vector2(sx + w * 0.5 + band.size.y, band.position.y), Vector2(sx + band.size.y, band.position.y)]), Color("1a1a1a"))
		sx += w
	draw_rect(Rect2(0, band.position.y - 3, size.x, 3), Color("11181d"))


func _draw_pipes(ci: CanvasItem) -> void:
	var pal := Zones.theme(0)
	for path in _paths:
		for p in path:
			PipeArt.draw_pipe(ci, _cell_center(p["c"]), _cell, Pieces.piece_for(p["en"], p["ex"]), pal, null, 0.6)


func _draw_goo(ci: CanvasItem) -> void:
	var pal := Zones.theme(0)
	var goo: Color = pal["goo"]
	for k in _paths.size():
		var path: Array = _paths[k]
		var n := float(path.size())
		var cycle := n + PAUSE_CELLS
		var p := fposmod(time * FLOW_SPEED + k * cycle * 0.5, cycle)
		var alpha := 1.0 if p <= n else clampf(1.0 - (p - n) / PAUSE_CELLS, 0.0, 1.0)
		for i in path.size():
			var f := clampf(p - i, 0.0, 1.0)
			if f <= 0.0:
				break
			var cell: Dictionary = path[i]
			var center := _cell_center(cell["c"])
			PipeArt.stroke(ci, center, _cell, cell["en"], cell["ex"], PipeArt.W_GOO * _cell * 2.4, PipeArt.fade(goo, 0.12 * alpha), 0.0, f)
			PipeArt.goo(ci, center, _cell, cell["en"], cell["ex"], f, goo, 0.85 * alpha, time, i * 13, false)
