## ============================================================================
##  SPRITE ATLAS - the vector art, rasterised once per zone into textures.
## ============================================================================
## Drawing a pipe with vector calls costs ~15 GPU draw calls. Instead every
## static look (tile, dry/full/narrow pipe, rock, wall, power-up, locked plate) is painted once into
## an off-screen SubViewport at the exact on-screen pixel size, and the board
## draws textured quads that the renderer batches together. Atlas textures hold
## premultiplied alpha, so whatever draws them uses `premult_material`.
class_name SpriteAtlas
extends Node

# Cell indices in a zone's tile atlas.
const BASE_A := 0
const BASE_B := 1
const EMPTY := 2          ## + piece (7)
const FULL := 9           ## + piece (6, no cross)
const CROSS_H := 15
const CROSS_V := 16
const CROSS_HV := 17
const ONEWAY := 18        ## + piece * 2 + entry index (12)
const ONEWAY_FULL := 30   ## + piece (6)
const RES := 36           ## + 0 vertical / 1 horizontal
const RES_FULL := 38      ## + 0 vertical / 1 horizontal
const ROCK := 40          ## + variant (8)
const ROCK_VARIANTS := 8
const WALL := 48
const PU := 49            ## + power-up kind - 1 (2)
const LOCKED := 51        ## Unlock mode: a face-down tile.
const NARROW := 52        ## + piece (6): narrow pipes, dry.
const NARROW_FULL := 58   ## + piece (6): narrow pipes, full of goo.
const COUNT := 64
const GRID := 8
const GUTTER := 2

const PU_R := 0.36        ## Power-up radius in its cell.


## Paints every cell of one atlas.
class Painter:
	extends Node2D
	var zone := 0
	var cell := 64
	var icons := false

	func _draw() -> void:
		var pal := Zones.theme(zone)
		var n := Pieces.ICON_COUNT if icons else SpriteAtlas.COUNT
		for i in n:
			var rect := Rect2(SpriteAtlas.cell_origin(i, cell), Vector2(cell, cell))
			if icons:
				# Icons 0-6: the pieces; 7-12: narrow versions of pieces 0-5.
				PipeArt.draw_pipe(self, rect.get_center(), cell, i % Pieces.COUNT, pal, null, 1.0, 0.0, false, i >= Pieces.COUNT)
			else:
				SpriteAtlas.paint_cell(self, i, rect, pal)


var premult_material: CanvasItemMaterial
var tile_px := 0
var icon_px := 0
var disk: Texture2D       ## White anti-aliased disk.
var soft: Texture2D       ## White soft radial glow.
var ring: Texture2D       ## White ring.
var gear: Texture2D       ## White gear silhouette.
var _tile_vps: Array = []
var _icon_vps: Array = []


func _ready() -> void:
	premult_material = CanvasItemMaterial.new()
	premult_material.blend_mode = CanvasItemMaterial.BLEND_MODE_PREMULT_ALPHA
	disk = _make_tex(64, func(d: float, _a: float) -> float: return clampf(31.5 - d, 0.0, 1.0))
	soft = _make_tex(64, func(d: float, _a: float) -> float: return pow(clampf(1.0 - d / 32.0, 0.0, 1.0), 2.0))
	ring = _make_tex(64, func(d: float, _a: float) -> float: return clampf(1.6 - absf(d - 27.5), 0.0, 1.0))
	gear = _make_tex(128, func(d: float, a: float) -> float:
		var teeth := 0.5 + 0.5 * signf(sin(a * 10.0))
		var outer := lerpf(50.0, 62.0, teeth)
		return clampf(outer - d, 0.0, 1.0) * clampf(d - 18.0, 0.0, 1.0))
	for z in Zones.count():
		_tile_vps.append(_make_vp(false, z))
		_icon_vps.append(_make_vp(true, z))


static func cell_origin(i: int, cell: int) -> Vector2:
	var stride := cell + GUTTER * 2
	return Vector2(GUTTER + (i % GRID) * stride, GUTTER + (i / GRID) * stride)


func _make_tex(size: int, alpha_fn: Callable) -> ImageTexture:
	var img := Image.create_empty(size, size, false, Image.FORMAT_RGBA8)
	var c := Vector2(size, size) * 0.5
	for y in size:
		for x in size:
			var v := Vector2(x + 0.5, y + 0.5) - c
			var a: float = alpha_fn.call(v.length(), v.angle())
			img.set_pixel(x, y, Color(1, 1, 1, a))
	return ImageTexture.create_from_image(img)


func _make_vp(icons: bool, z: int) -> SubViewport:
	var vp := SubViewport.new()
	vp.transparent_bg = true
	vp.disable_3d = true
	vp.render_target_update_mode = SubViewport.UPDATE_DISABLED
	vp.size = Vector2i(8, 8)
	var p := Painter.new()
	p.zone = z
	p.icons = icons
	vp.add_child(p)
	add_child(vp)
	return vp


## Re-render the atlases when the on-screen tile or icon size (in pixels) changes.
func ensure(tile_pixels: int, icon_pixels: int) -> bool:
	tile_pixels = maxi(8, tile_pixels)
	icon_pixels = maxi(8, icon_pixels)
	if tile_pixels == tile_px and icon_pixels == icon_px:
		return false
	tile_px = tile_pixels
	icon_px = icon_pixels
	for vps in [_tile_vps, _icon_vps]:
		var icons: bool = vps == _icon_vps
		var cell := icon_px if icons else tile_px
		var n := Pieces.ICON_COUNT if icons else COUNT
		var stride := cell + GUTTER * 2
		var cols := mini(n, GRID)
		var rows := int(ceil(n / float(GRID)))
		for vp in vps:
			vp.size = Vector2i(cols * stride, rows * stride)
			var p: Painter = vp.get_child(0)
			p.cell = cell
			p.queue_redraw()
			vp.render_target_update_mode = SubViewport.UPDATE_ONCE
	return true


func tile_tex(zone: int) -> Texture2D:
	return (_tile_vps[posmod(zone, _tile_vps.size())] as SubViewport).get_texture()


func icon_tex(zone: int) -> Texture2D:
	return (_icon_vps[posmod(zone, _icon_vps.size())] as SubViewport).get_texture()


func region(i: int) -> Rect2:
	return Rect2(cell_origin(i, tile_px), Vector2(tile_px, tile_px))


## Icon for a pipe item (piece, or narrow piece).
func icon_region(it: int) -> Rect2:
	return Rect2(cell_origin(Pieces.icon_index(it), icon_px), Vector2(icon_px, icon_px))


## Tile-atlas cell showing a dry pipe item (for hover ghosts).
static func item_cell(it: int) -> int:
	return (NARROW if Pieces.item_narrow(it) else EMPTY) + Pieces.item_piece(it)


## The atlas cell that shows tile `t` as it is now, or -1 if it must be drawn live
## (goo part-way through it, or the animated source).
static func sprite_for(t: Tile) -> int:
	if t.hidden:
		return LOCKED
	if t.kind == Tile.ROCK:
		return ROCK + (t.rnd & 0x7fffffff) % ROCK_VARIANTS
	if t.kind != Tile.EMPTY or t.piece < 0:
		return -1
	var p := t.piece
	var full := [t.fill_entry[0] >= 0, t.fill_entry[1] >= 0]
	for ch in 2:
		if full[ch] and t.fill[ch] < 1.0:
			return -1
	if t.narrow:
		return (NARROW_FULL if full[0] else NARROW) + p
	match t.special:
		Tile.SP_RESERVOIR:
			return (RES_FULL if full[0] else RES) + (0 if p == Pieces.V else 1)
		Tile.SP_ONEWAY:
			if full[0]:
				return ONEWAY_FULL + p
			return ONEWAY + p * 2 + maxi(0, (Pieces.OPENINGS[p] as Array).find(t.oneway_entry))
	if p == Pieces.CROSS:
		if full[0] and full[1]:
			return CROSS_HV
		if full[0]:
			return CROSS_H
		if full[1]:
			return CROSS_V
		return EMPTY + p
	return (FULL if full[0] else EMPTY) + p


static var _shapes: Array = []


static func rock_shape(k: int) -> PackedVector2Array:
	if _shapes.is_empty():
		var rng := RandomNumberGenerator.new()
		rng.seed = 4242
		for v in ROCK_VARIANTS:
			var pts := PackedVector2Array()
			var n := rng.randi_range(7, 9)
			var off := rng.randf() * TAU
			for i in n:
				var ang := off + TAU * float(i) / n + rng.randf_range(-0.2, 0.2)
				var rad := rng.randf_range(0.34, 0.43)
				pts.append(Vector2(cos(ang) * rad, sin(ang) * rad * 0.92 + 0.02))
			_shapes.append(pts)
	return _shapes[k]


## Paint atlas cell `i` into `rect` with palette `pal`.
static func paint_cell(ci: CanvasItem, i: int, rect: Rect2, pal: Dictionary) -> void:
	var T := rect.size.x
	var c := rect.get_center()
	var goo: Color = pal["goo"]
	if i == BASE_A or i == BASE_B:
		PipeArt.draw_tile_base(ci, rect, pal, i == BASE_B)
	elif i >= EMPTY and i < EMPTY + Pieces.COUNT:
		PipeArt.draw_pipe(ci, c, T, i - EMPTY, pal)
	elif i >= FULL and i < FULL + 6:
		_paint_full(ci, c, T, i - FULL, pal, [true, false], Tile.SP_NONE, -1)
	elif i == CROSS_H or i == CROSS_V or i == CROSS_HV:
		_paint_full(ci, c, T, Pieces.CROSS, pal, [i != CROSS_V, i != CROSS_H], Tile.SP_NONE, -1)
	elif i >= ONEWAY and i < ONEWAY + 12:
		var p := (i - ONEWAY) / 2
		var t := Tile.new()
		t.piece = p
		t.special = Tile.SP_ONEWAY
		t.oneway_entry = Pieces.OPENINGS[p][(i - ONEWAY) % 2]
		PipeArt.draw_pipe(ci, c, T, p, pal, t, 1.0, 0.0, false)
	elif i >= ONEWAY_FULL and i < ONEWAY_FULL + 6:
		var p := i - ONEWAY_FULL
		_paint_full(ci, c, T, p, pal, [true, false], Tile.SP_ONEWAY, Pieces.OPENINGS[p][0])
	elif i >= RES and i < RES + 4:
		var t := Tile.new()
		t.piece = Pieces.V if (i - RES) % 2 == 0 else Pieces.H
		t.special = Tile.SP_RESERVOIR
		if i >= RES_FULL:
			t.fill_entry[0] = Pieces.S if t.piece == Pieces.V else Pieces.W
			t.fill[0] = 1.0
			t.fill_color[0] = goo
		PipeArt.draw_pipe(ci, c, T, t.piece, pal, t, 1.0, 0.0, false)
	elif i >= ROCK and i < ROCK + ROCK_VARIANTS:
		var t := Tile.new()
		t.kind = Tile.ROCK
		t.shape = rock_shape(i - ROCK)
		t.rnd = (i - ROCK) * 7919 + 13
		PipeArt.draw_rock(ci, c, T, t, pal)
	elif i == WALL:
		var wall: Color = pal["wall"]
		var ww := T * 0.2
		var x := rect.position.x
		ci.draw_rect(Rect2(x, rect.position.y, ww, T), wall.darkened(0.3))
		ci.draw_rect(Rect2(x + ww * 0.15, rect.position.y, ww * 0.7, T), wall)
		ci.draw_rect(Rect2(x + ww * 0.2, rect.position.y, ww * 0.15, T), wall.lightened(0.3))
		ci.draw_circle(Vector2(x + ww * 0.5, c.y), ww * 0.16, wall.darkened(0.5))
		ci.draw_circle(Vector2(x + ww * 0.45, c.y - ww * 0.04), ww * 0.08, wall.lightened(0.4))
	elif i >= PU and i < PU + 2:
		PipeArt.draw_powerup(ci, c, T * PU_R, i - PU + 1, 0.0, false)
	elif i == LOCKED:
		PipeArt.draw_locked(ci, rect, pal)
	elif i >= NARROW and i < NARROW + 6:
		PipeArt.draw_pipe(ci, c, T, i - NARROW, pal, null, 1.0, 0.0, false, true)
	elif i >= NARROW_FULL and i < NARROW_FULL + 6:
		_paint_full(ci, c, T, i - NARROW_FULL, pal, [true, false], Tile.SP_NONE, -1, true)


static func _paint_full(ci: CanvasItem, c: Vector2, T: float, piece: int, pal: Dictionary, full: Array, special: int, entry: int,
		narrow := false) -> void:
	var goo: Color = pal["goo"]
	var t := Tile.new()
	t.piece = piece
	t.narrow = narrow
	t.special = special
	t.oneway_entry = entry
	var chans := Pieces.channels(piece)
	for ch in chans.size():
		if full[ch]:
			var a: int = chans[ch][0]
			var b: int = chans[ch][1]
			t.fill_entry[ch] = a
			t.fill[ch] = 1.0
			t.fill_color[ch] = goo
			# Baked glow halo under the pipe.
			PipeArt.stroke(ci, c, T, a, b, PipeArt.W_GOO * T * (1.6 if narrow else 2.5), PipeArt.fade(goo, 0.16))
	PipeArt.draw_pipe(ci, c, T, piece, pal, t, 1.0, 0.0, false)
