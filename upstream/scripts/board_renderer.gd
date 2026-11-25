## ============================================================================
##  RENDERER - backdrop, board, goo, particles and the queue panel.
## ============================================================================
## Draw-call budget matters (WebGL, phones), so:
##  * every board row is its own cached canvas item made of textured quads from
##    the SpriteAtlas, redrawn only when that row changes;
##  * only the tile the goo is flowing through (and the source pump) is drawn
##    with live vector calls;
##  * particles, glows and backdrop decorations are textured quads too.
## Layers, back to front: backdrop (this node) > rows > live tiles > glow (add)
##   > pickup sprites > fx > queue panel (bg, icons, overlay).
class_name BoardRenderer
extends Node2D


## A child layer whose drawing is delegated back to the renderer.
class Layer:
	extends Node2D
	var draw_cb: Callable
	var row := -999999
	var stamp := -1

	func _draw() -> void:
		draw_cb.call(self)


var game  ## The Game node (main.gd).
var atlas: SpriteAtlas
## Where layers that must stay sharp go (text, queue panel). In PS1 mode the
## board renders at low resolution, so these live on the full-res screen.
var overlay_parent: Node
var rows_root: Node2D
var live: Layer
var glow: Layer
var fx_sprites: Layer
var frost: Layer
var fx: Layer
var queue_bg: Layer
var queue_icons: Layer
var queue_fg: Layer
var text_layer: Layer
var row_views := {}       ## row -> Layer
var _pool: Array = []
var _animate_until := {}  ## row -> game time until which it redraws every frame
var _layout_key := ""
var _queue_sig := ""
var parts: Array = []   ## {p, v, life, max, col, size, grav, glow}
var texts: Array = []   ## {p, text, col, life, max, size}
var _sb := StyleBoxFlat.new()


func _ready() -> void:
	_sb.anti_aliasing = true
	var add_mat := CanvasItemMaterial.new()
	add_mat.blend_mode = CanvasItemMaterial.BLEND_MODE_ADD
	rows_root = Node2D.new()
	rows_root.material = atlas.premult_material
	add_child(rows_root)
	live = _layer(_draw_live, 140)
	glow = _layer(_draw_glow, 150)
	glow.material = add_mat
	fx_sprites = _layer(_draw_fx_sprites, 160)
	fx_sprites.material = atlas.premult_material
	frost = _layer(_draw_frost, 165)
	fx = _layer(_draw_fx, 170)
	var top: Node = overlay_parent if overlay_parent != null else self
	text_layer = _layer(_draw_text, 175, top)
	queue_bg = _layer(_draw_queue_bg, 180, top)
	queue_icons = _layer(_draw_queue_icons, 181, top)
	queue_icons.material = atlas.premult_material
	queue_icons.texture_filter = CanvasItem.TEXTURE_FILTER_NEAREST
	queue_fg = _layer(_draw_queue_fg, 182, top)


func _layer(cb: Callable, z: int, parent: Node = null) -> Layer:
	var l := Layer.new()
	l.draw_cb = cb
	l.z_index = z
	(parent if parent != null else self).add_child(l)
	return l


func redraw() -> void:
	_sync_rows()
	queue_redraw()
	live.queue_redraw()
	glow.queue_redraw()
	fx_sprites.queue_redraw()
	frost.queue_redraw()
	fx.queue_redraw()
	text_layer.queue_redraw()
	var sig := _queue_signature()
	if sig != _queue_sig or game.queue_shift > 0.0 or game.lock_timer > 0.0 or game.wildcards > 0:
		_queue_sig = sig
		queue_bg.queue_redraw()
		queue_icons.queue_redraw()
		queue_fg.queue_redraw()


func invalidate_rows() -> void:
	for v in row_views.values():
		v.stamp = -1
	_animate_until.clear()
	_queue_sig = ""


func animate_row(r: int, until: float) -> void:
	_animate_until[r] = until


func clear_fx() -> void:
	parts.clear()
	texts.clear()


# --- coordinates ---------------------------------------------------------------

## Snap to whole physical pixels so atlas sprites map 1:1 and never blur or seam.
func snap(v: float) -> float:
	var s: float = game.px_scale
	return roundf(v * s) / s


func row_y(r: int) -> float:
	return snap(game.board_rect.end.y - (r + 1 - game.cam.y) * game.T)


func shake_offset() -> Vector2:
	var o: Vector2 = game.cam.offset
	return Vector2(snap(o.x), snap(o.y))


func tile_rect(c: int, r: int) -> Rect2:
	var T: float = game.T
	return Rect2(Vector2(game.board_rect.position.x + c * T, row_y(r)) + shake_offset(), Vector2(T, T))


func w2s(w: Vector2) -> Vector2:
	var T: float = game.T
	var b: Rect2 = game.board_rect
	return Vector2(b.position.x + w.x * T, b.end.y - (w.y - game.cam.y) * T) + shake_offset()


static func h01(n: float) -> float:
	return fposmod(sin(n * 12.9898) * 43758.5453, 1.0)


func _is_live(t: Tile, c: int, r: int) -> bool:
	return t.kind == Tile.SOURCE or (game.flow.active and c == game.flow.col and r == game.flow.row)


# --- cached rows ---------------------------------------------------------------

func _sync_rows() -> void:
	var T: float = game.T
	var b: Rect2 = game.board_rect
	var key := "%.4f|%.3f|%.3f|%d" % [T, b.position.x, b.size.x, atlas.tile_px]
	if key != _layout_key:
		_layout_key = key
		invalidate_rows()
	var cam: GameCamera = game.cam
	var grid: Grid = game.grid
	var rr := cam.row_range()
	rows_root.position = shake_offset()
	for r in row_views.keys():
		if r < rr.x or r > rr.y:
			var v: Layer = row_views[r]
			v.visible = false
			_pool.append(v)
			row_views.erase(r)
	for r in _animate_until.keys():
		if _animate_until[r] < game.time:
			_animate_until.erase(r)
			grid.touch(r)
	for r in range(rr.x, rr.y + 1):
		var v: Layer = row_views.get(r)
		if v == null:
			if _pool.is_empty():
				v = Layer.new()
				v.draw_cb = _draw_row
				v.use_parent_material = true
				rows_root.add_child(v)
			else:
				v = _pool.pop_back()
			v.row = r
			v.stamp = -1
			v.visible = true
			row_views[r] = v
		v.position = Vector2(0, row_y(r))
		v.z_index = 1 + r - rr.x
		var stamp := grid.version(r) * 4 + (1 if r < grid.floor_row else 0) + (2 if grid.rows.has(r) else 0)
		if _animate_until.has(r) or v.stamp != stamp:
			v.queue_redraw()
			v.stamp = stamp


## One row in local space: x as on screen, y from 0 (row top) to T.
func _draw_row(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0 or atlas.tile_px <= 0:
		return
	var r: int = (ci as Layer).row
	var T: float = game.T
	var b: Rect2 = game.board_rect
	var grid: Grid = game.grid
	var zone := Zones.index_for_row(r)
	var pal := Zones.theme(zone)
	var tex := atlas.tile_tex(zone)
	var x0 := b.position.x
	ci.draw_rect(Rect2(x0 - T * 0.04, 0, b.size.x + T * 0.08, T), pal["board"])
	var wr := atlas.region(SpriteAtlas.WALL)
	wr.size.x *= 0.2
	var ww := T * 0.2
	ci.draw_texture_rect_region(tex, Rect2(x0 - ww, 0, ww, T), wr)
	ci.draw_texture_rect_region(tex, Rect2(b.end.x, 0, ww, T), wr)
	if r < grid.floor_row:
		_draw_bedrock(ci, r, x0, b.size.x, T)
		return
	var time: float = game.time
	for c in Tuning.COLS:
		var t := grid.get_tile(c, r)
		if t != null and (t.hidden or time - t.flip_at < Tuning.FLIP_TIME):
			continue  # Locked and flipping tiles bring their own face.
		ci.draw_texture_rect_region(tex, Rect2(x0 + c * T, 0, T, T), atlas.region(SpriteAtlas.BASE_B if (c + r) % 2 == 0 else SpriteAtlas.BASE_A))
	for c in Tuning.COLS:
		var t := grid.get_tile(c, r)
		if t == null or _is_live(t, c, r):
			continue
		var rect := Rect2(x0 + c * T, 0, T, T)
		var fk := (time - t.flip_at) / Tuning.FLIP_TIME
		if not t.hidden and fk < 0.0:
			ci.draw_texture_rect_region(tex, rect, atlas.region(SpriteAtlas.LOCKED))
			continue
		if not t.hidden and fk >= 0.0 and fk < 1.0:
			# Unlock flip: the plate turns edge-on, then the tile underneath turns face-up.
			ci.draw_set_transform(rect.get_center(), 0.0, Vector2(maxf(0.04, absf(cos(fk * PI))), 1.0 + 0.12 * sin(fk * PI)))
			var local := Rect2(-T * 0.5, -T * 0.5, T, T)
			if fk < 0.5:
				ci.draw_texture_rect_region(tex, local, atlas.region(SpriteAtlas.LOCKED))
			else:
				ci.draw_texture_rect_region(tex, local, atlas.region(SpriteAtlas.BASE_B if (c + r) % 2 == 0 else SpriteAtlas.BASE_A))
				var fs := SpriteAtlas.sprite_for(t)
				if fs >= 0:
					ci.draw_texture_rect_region(tex, local, atlas.region(fs))
			ci.draw_set_transform(Vector2.ZERO)
			continue
		var s := SpriteAtlas.sprite_for(t)
		if s < 0:
			if t.piece >= 0:
				PipeArt.draw_pipe(ci, rect.get_center(), T, t.piece, pal, t, 1.0, game.time, false)
			continue
		var k := _pop_scale(t)
		if k != 1.0:
			ci.draw_set_transform(rect.get_center(), 0.0, Vector2(k, k))
			ci.draw_texture_rect_region(tex, Rect2(-T * 0.5, -T * 0.5, T, T), atlas.region(s))
			ci.draw_set_transform(Vector2.ZERO)
		else:
			ci.draw_texture_rect_region(tex, rect, atlas.region(s))
	if r > 0 and r % Tuning.ZONE_ROWS == 0:
		var x := x0
		var dash := T * 0.25
		var k := 0
		var th := maxf(3.0, T * 0.06)
		while x < b.end.x - 0.5:
			ci.draw_rect(Rect2(x, T - th * 0.5, minf(dash, b.end.x - x), th), pal["accent"] if k % 2 == 0 else Color(0.1, 0.1, 0.1))
			x += dash
			k += 1


func _draw_bedrock(ci: CanvasItem, r: int, x0: float, w: float, T: float) -> void:
	ci.draw_rect(Rect2(x0, 0, w, T), Color("141010"))
	for i in 6:
		var x := x0 + h01(r * 13.0 + i) * w
		var y := h01(r * 7.0 + i * 3.0) * T
		var rad := T * (0.04 + h01(i + r) * 0.06)
		ci.draw_rect(Rect2(x - rad, y - rad, rad * 2.0, rad * 2.0), Color("221a18"))
	if r == game.grid.floor_row - 1:
		var x := x0
		var k := 0
		while x < x0 + w - 0.5:
			ci.draw_rect(Rect2(x, 0, minf(T * 0.25, x0 + w - x), T * 0.08), Color("ffd23a") if k % 2 == 0 else Color("1a1a1a"))
			x += T * 0.25
			k += 1


func _pop_scale(t: Tile) -> float:
	var dt: float = game.time - t.placed_at
	if dt < 0.0 or dt > 0.4:
		return 1.0
	var k := dt / 0.4
	return 1.0 - cos(k * 3.0 * PI) * exp(-5.0 * k) * 0.5


# --- live tiles: the goo's current tile and the source pump ----------------------

func _draw_live(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0:
		return
	var T: float = game.T
	var grid: Grid = game.grid
	var rr: Vector2i = game.cam.row_range()
	var src := grid.get_tile(Tuning.SOURCE_COL, 0)
	if src != null and rr.x <= 0:
		var pal := Zones.theme(0)
		var frac: float = 1.0 - clampf(game.countdown / Tuning.COUNTDOWN_TIME, 0.0, 1.0)
		PipeArt.draw_source(ci, tile_rect(Tuning.SOURCE_COL, 0).get_center(), T, src, pal, pal["goo"], game.time, frac)
	if game.flow.active:
		var t := grid.get_tile(game.flow.col, game.flow.row)
		if t != null and t.kind == Tile.EMPTY and t.piece >= 0:
			var pal := Zones.theme_for_row(game.flow.row)
			PipeArt.draw_pipe(ci, tile_rect(game.flow.col, game.flow.row).get_center(), T, t.piece, pal, t, 1.0, game.time, false)


# --- glow (additive) ---------------------------------------------------------------

func _draw_glow(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0:
		return
	var T: float = game.T
	var pulse := 0.8 + 0.2 * sin(game.time * 6.0)
	if game.flow.active or game.state == game.State.SPILL:
		var hp := w2s(game.flow.head_world())
		var gc: Color = Zones.theme_for_row(game.flow.row)["goo"]
		var r := T * 0.9 * pulse
		ci.draw_texture_rect(atlas.soft, Rect2(hp - Vector2(r, r), Vector2(r, r) * 2.0), false, PipeArt.fade(gc, 0.45))
	for p in parts:
		if p["glow"]:
			var a: float = clampf(p["life"] / p["max"], 0.0, 1.0)
			var r: float = p["size"] * T * 3.0
			ci.draw_texture_rect(atlas.soft, Rect2(w2s(p["p"]) - Vector2(r, r), Vector2(r, r) * 2.0), false, PipeArt.fade(p["col"], 0.4 * a))


# --- particles ---------------------------------------------------------------------

func burst(world_pos: Vector2, col: Color, count: int, speed := 3.0, size := 0.07, life := 0.7, grav := 6.0, glowing := true) -> void:
	for i in count:
		var a := randf() * TAU
		var s := speed * (0.35 + randf() * 0.65)
		parts.append({"p": world_pos, "v": Vector2(cos(a), sin(a)) * s + Vector2(0, speed * 0.3), "life": life * (0.6 + randf() * 0.4),
				"max": life, "col": col, "size": size * (0.6 + randf() * 0.8), "grav": grav, "glow": glowing})
	if parts.size() > 400:
		parts = parts.slice(parts.size() - 400)


func float_text(world_pos: Vector2, text: String, col: Color, size := 0.34, life := 1.1) -> void:
	texts.append({"p": world_pos, "text": text, "col": col, "life": life, "max": life, "size": size})


## Snowflakes drifting down over the board (Flow-freeze).
func snow(count: int) -> void:
	var cam: GameCamera = game.cam
	for i in count:
		var life := 1.6 + randf() * 1.2
		parts.append({"p": Vector2(randf() * Tuning.COLS, cam.y + cam.visible_rows * randf()),
				"v": Vector2(randf_range(-0.25, 0.25), -0.5 - randf() * 0.4), "life": life, "max": life,
				"col": Color(0.92, 0.98, 1.0, 0.95), "size": 0.03 + randf() * 0.03, "grav": 0.0, "glow": false})


## Water dripping off the pipes as the freeze ends.
func thaw_drips() -> void:
	var grid: Grid = game.grid
	var rr: Vector2i = game.cam.row_range()
	for r in range(maxi(rr.x, grid.floor_row), rr.y + 1):
		for c in Tuning.COLS:
			var t := grid.get_tile(c, r)
			if t != null and t.has_goo() and randf() < 0.5:
				burst(Vector2(c + 0.5, r + 0.5), Zones.theme_for_row(r)["goo"], 3, 1.2, 0.05, 0.9, 7.0, false)


func update_fx(dt: float) -> void:
	for p in parts:
		p["v"].y -= p["grav"] * dt
		p["p"] += p["v"] * dt
		p["life"] -= dt
	parts = parts.filter(func(p): return p["life"] > 0.0)
	for t in texts:
		t["p"].y += dt * 0.7
		t["life"] -= dt
	texts = texts.filter(func(t): return t["life"] > 0.0)


# --- pickups and hover ghost (atlas sprites) -------------------------------------------

func _draw_fx_sprites(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0 or atlas.tile_px <= 0:
		return
	var T: float = game.T
	var grid: Grid = game.grid
	var rr: Vector2i = game.cam.row_range()
	var time: float = game.time
	for r in range(maxi(rr.x, grid.floor_row), rr.y + 1):
		var tex := atlas.tile_tex(Zones.index_for_row(r))
		for c in Tuning.COLS:
			var t := grid.get_tile(c, r)
			if t == null or t.hidden or t.powerup == Tile.PU_NONE:
				continue
			var rect := tile_rect(c, r)
			var bob := Vector2(0, snap(sin(time * 3.0 + c * 1.3 + r) * T * 0.02))
			if t.powerup != Tile.PU_NONE:
				var cell := SpriteAtlas.PU + t.powerup - 1
				if t.piece < 0:
					_icon(ci, tex, cell, rect.get_center() + bob, T * 0.27 / SpriteAtlas.PU_R)
				else:
					_icon(ci, tex, cell, rect.position + Vector2(T * 0.2, T * 0.21) + bob, T * 0.14 / SpriteAtlas.PU_R)
	# Ghost of the next piece under the cursor.
	for cell in _hover_cells():
		var action: String = game.placement_mode(cell.x, cell.y)
		var ghost := -1
		if action == "place" or action == "replace":
			ghost = game.queue[0]
		elif action == "drop":
			ghost = game.held_piece
		if ghost >= 0:
			var tex := atlas.tile_tex(Zones.index_for_row(cell.y))
			ci.draw_texture_rect_region(tex, tile_rect(cell.x, cell.y), atlas.region(SpriteAtlas.item_cell(ghost)), Color(0.5, 0.5, 0.5, 0.5))


## Draw an atlas cell centred on `center`, `size` pixels across.
func _icon(ci: CanvasItem, tex: Texture2D, cell: int, center: Vector2, size: float) -> void:
	ci.draw_texture_rect_region(tex, Rect2(center - Vector2(size, size) * 0.5, Vector2(size, size)), atlas.region(cell))


func _hover_cells() -> Array:
	var cells := []
	if not (game.state == game.State.COUNTDOWN or game.state == game.State.RUNNING) or game.paused:
		return cells
	if game.hover_active and game.is_tile_visible(game.hover.x, game.hover.y):
		cells.append(game.hover)
	if game.kb_active and game.kb_cursor != game.hover and game.is_tile_visible(game.kb_cursor.x, game.kb_cursor.y):
		cells.append(game.kb_cursor)
	return cells


# --- Flow-freeze frost -----------------------------------------------------------------------

func _draw_frost(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0:
		return
	var a: float = game.freeze_amount()
	if a <= 0.0:
		return
	var T: float = game.T
	var b: Rect2 = game.board_rect
	var grid: Grid = game.grid
	var rr: Vector2i = game.cam.row_range()
	var off := shake_offset()
	# A cold tint over the whole board, and frost creeping in from the walls.
	ci.draw_rect(Rect2(b.position.x - T * 0.2 + off.x, b.position.y, b.size.x + T * 0.4, b.size.y), Color(0.72, 0.9, 1.0, 0.24 * a))
	for r in range(rr.x, rr.y + 1):
		var y := row_y(r) + off.y
		for x in [b.position.x + off.x, b.end.x + off.x]:
			var fr := T * (0.7 + 0.25 * h01(r * 3.7 + x))
			ci.draw_texture_rect(atlas.soft, Rect2(x - fr, y + T * 0.5 - fr, fr * 2.0, fr * 2.0), false, Color(0.88, 0.97, 1.0, 0.4 * a))
	var ice := Color(0.9, 0.98, 1.0, 0.95 * a)
	var sheen := Color(1, 1, 1, 0.8 * a)
	for r in range(maxi(rr.x, grid.floor_row), rr.y + 1):
		for c in Tuning.COLS:
			var t := grid.get_tile(c, r)
			if t == null or t.hidden or t.kind != Tile.EMPTY or t.piece < 0:
				continue
			var center := tile_rect(c, r).get_center()
			# The water in the pipe turns to ice.
			var w := PipeArt.W_GOO * T * (PipeArt.NARROW_SCALE if t.narrow else 1.0)
			for ch in 2:
				if t.fill_entry[ch] < 0:
					continue
				var en: int = t.fill_entry[ch]
				var ex := Pieces.exit_dir(t.piece, en)
				var p: float = t.fill[ch]
				PipeArt.stroke(ci, center, T, en, ex, w * 1.05, ice, 0.0, p)
				if t.special == Tile.SP_RESERVOIR and p > PipeArt.BULGE_T0:
					PipeArt.stroke(ci, center, T, en, ex, PipeArt.W_BULGE_GOO * T, ice, PipeArt.BULGE_T0, minf(p, 1.0 - PipeArt.BULGE_T0))
				PipeArt.stroke(ci, center, T, en, ex, w * 0.3, sheen, 0.0, p, w * 0.25)
			# Frost crystals on every pipe.
			for k in 2:
				var hx := float((t.rnd >> (k * 7)) & 63) / 63.0 - 0.5
				var hy := float((t.rnd >> (k * 7 + 13)) & 63) / 63.0 - 0.5
				var fsz := T * (0.3 + 0.12 * k)
				var fp := center + Vector2(hx, hy) * T * 0.62
				ci.draw_texture_rect(atlas.flake, Rect2(fp - Vector2(fsz, fsz) * 0.5, Vector2(fsz, fsz)), false, Color(1, 1, 1, 0.85 * a))
	# The freeze rings out from the water's leading edge.
	var since: float = game.time - game.freeze_started
	if since < 0.8:
		var hp := w2s(game.flow.head_world())
		ci.draw_arc(hp, since / 0.8 * T * 7.0, 0.0, TAU, 48, Color(0.92, 0.99, 1.0, (1.0 - since / 0.8) * 0.9), maxf(3.0, T * 0.09), PipeArt.aa)


# --- fx (bubbles, outlines, particles, text) -------------------------------------------

func _draw_fx(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0:
		return
	var T: float = game.T
	var grid: Grid = game.grid
	var rr: Vector2i = game.cam.row_range()
	var time: float = game.time
	var pulse := 0.55 + 0.45 * sin(time * 4.0)
	# Bubbles drifting along full pipes, and pulsing frames around pickups.
	for r in range(maxi(rr.x, grid.floor_row), rr.y + 1):
		for c in Tuning.COLS:
			var t := grid.get_tile(c, r)
			if t == null:
				continue
			if t.has_goo() and t.special != Tile.SP_RESERVOIR and t.kind == Tile.EMPTY:
				var center := tile_rect(c, r).get_center()
				var br := PipeArt.W_GOO * T * 0.17
				for ch in 2:
					if t.fill_entry[ch] >= 0 and t.fill[ch] >= 1.0:
						var en: int = t.fill_entry[ch]
						var tt := fposmod(time * 0.55 + float((t.rnd + ch * 37) & 0xffff) / 997.0, 1.0)
						var bp := center + Pieces.path_point(en, Pieces.exit_dir(t.piece, en), tt) * T
						ci.draw_texture_rect(atlas.disk, Rect2(bp - Vector2(br, br), Vector2(br, br) * 2.0), false, PipeArt.fade(t.fill_color[ch].lightened(0.75), 0.75))
			if not t.hidden and t.powerup != Tile.PU_NONE:
				var col := PipeArt.powerup_color(t.powerup)
				ci.draw_rect(tile_rect(c, r).grow(-T * 0.075), PipeArt.fade(col, 0.25 + 0.35 * pulse), false, maxf(2.0, T * 0.045))
	# Unlock mode: the picked-up pipe gets a bright pulsing frame.
	if game.held_piece >= 0 and game.held_from.x >= 0:
		var hr := tile_rect(game.held_from.x, game.held_from.y)
		var hp := 0.6 + 0.4 * sin(time * 10.0)
		ci.draw_rect(hr.grow(-T * 0.02), Color(1.0, 0.85, 0.2, hp), false, maxf(3.0, T * 0.07))
	_draw_hover(ci, T)
	if game.state == game.State.SPILL or game.state == game.State.GAMEOVER:
		_draw_spill(ci, T)
	for p in parts:
		var a: float = clampf(p["life"] / p["max"], 0.0, 1.0)
		var r: float = p["size"] * T * (0.5 + 0.5 * a)
		ci.draw_texture_rect(atlas.disk, Rect2(w2s(p["p"]) - Vector2(r, r), Vector2(r, r) * 2.0), false, PipeArt.fade(p["col"], a))



## Floating score text (on the sharp layer in PS1 mode).
func _draw_text(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0:
		return
	var T: float = game.T
	var f := PipeArt.font()
	for t in texts:
		var a: float = clampf(t["life"] / t["max"] * 1.6, 0.0, 1.0)
		var fs := int(t["size"] * T)
		var pos := w2s(t["p"]) + Vector2(-T * 2.0, fs * 0.35)
		ci.draw_string_outline(f, pos, t["text"], HORIZONTAL_ALIGNMENT_CENTER, T * 4.0, fs, maxi(3, fs / 4), Color(0, 0, 0, a))
		ci.draw_string(f, pos, t["text"], HORIZONTAL_ALIGNMENT_CENTER, T * 4.0, fs, PipeArt.fade(t["col"], a))


func _draw_hover(ci: CanvasItem, T: float) -> void:
	for cell in _hover_cells():
		var mode: String = game.placement_mode(cell.x, cell.y)
		var rect := tile_rect(cell.x, cell.y)
		var col := Color(1, 1, 1, 0.85)
		match mode:
			"replace":
				col = Color("ffb030")
			"flip":
				col = Color("6ad8ff")
			"drop":
				col = Color("7dff3a")
			"deselect":
				col = Color("ffd23a")
			"locked", "no":
				col = Color(1, 0.3, 0.3, 0.6)
		ci.draw_rect(rect.grow(-T * 0.03), col, false, maxf(2.0, T * 0.05))
		var f := PipeArt.font()
		var fs := int(T * 0.3)
		if mode == "replace":
			var txt := "-%d" % Tuning.REPLACE_PENALTY
			ci.draw_string_outline(f, rect.position + Vector2(0, T * 0.95), txt, HORIZONTAL_ALIGNMENT_CENTER, T, fs, 4, Color.BLACK)
			ci.draw_string(f, rect.position + Vector2(0, T * 0.95), txt, HORIZONTAL_ALIGNMENT_CENTER, T, fs, col)


func _draw_spill(ci: CanvasItem, T: float) -> void:
	var sp: Dictionary = game.spill
	if sp.is_empty():
		return
	var k := clampf((game.time - float(sp["t"])) / 1.2, 0.0, 1.0)
	var pos := w2s(sp["p"])
	var col: Color = sp["col"]
	var rad := T * (0.15 + 0.35 * sqrt(k))
	for i in 7:
		var a := i * TAU / 7.0 + float(sp["seed"])
		var r2 := rad * (0.45 + 0.2 * h01(i + float(sp["seed"])))
		var p := pos + Vector2.from_angle(a) * rad * 0.7
		ci.draw_texture_rect(atlas.disk, Rect2(p - Vector2(r2, r2), Vector2(r2, r2) * 2.0), false, col)
	ci.draw_texture_rect(atlas.disk, Rect2(pos - Vector2(rad, rad), Vector2(rad, rad) * 2.0), false, col)
	var hr := rad * 0.3
	ci.draw_texture_rect(atlas.disk, Rect2(pos - Vector2(rad, rad) * 0.3 - Vector2(hr, hr), Vector2(hr, hr) * 2.0), false, col.lightened(0.5))


# --- backdrop (textured quads, redrawn every frame) -----------------------------------

func _view_palette() -> Array:
	var cr: float = game.cam.y + game.cam.visible_rows * 0.5
	var zi := Zones.index_for_row(int(floor(cr)))
	var local := cr - zi * Tuning.ZONE_ROWS
	var to := Zones.theme(zi)
	if zi > 0 and local < 6.0:
		return [Zones.theme(zi - 1), to, smoothstep(0.0, 6.0, local)]
	return [to, to, 1.0]


func _mix(a: Dictionary, b: Dictionary, key: String, t: float) -> Color:
	return (a[key] as Color).lerp(b[key], t)


func _draw() -> void:
	if game == null or game.T <= 0.0:
		return
	var vp := _view_palette()
	var vs: Vector2 = game.view_size
	var top := _mix(vp[0], vp[1], "bg_top", vp[2])
	var bottom := _mix(vp[0], vp[1], "bg_bottom", vp[2])
	draw_polygon(PackedVector2Array([Vector2.ZERO, Vector2(vs.x, 0), vs, Vector2(0, vs.y)]),
			PackedColorArray([top, top, bottom, bottom]))
	if vp[2] < 1.0:
		_deco(vp[0], 1.0 - vp[2])
	_deco(vp[1], vp[2])


func _dot(tex: Texture2D, p: Vector2, r: float, col: Color) -> void:
	draw_texture_rect(tex, Rect2(p - Vector2(r, r), Vector2(r, r) * 2.0), false, col)


func _deco(pal: Dictionary, alpha: float) -> void:
	if alpha <= 0.01:
		return
	var vs: Vector2 = game.view_size
	var T: float = game.T
	var t: float = game.time
	var scroll: float = game.cam.y * T
	var acc: Color = pal["accent"]
	match pal["deco"]:
		"bubbles":
			for i in 24:
				var x := h01(i * 3.1) * vs.x + sin(t + i) * 6.0
				var sp := 18.0 + h01(i * 1.7) * 40.0
				var y := vs.y - fposmod(h01(i * 7.7) * vs.y + t * sp + scroll * 0.3, vs.y + 60.0) + 30.0
				var r := 4.0 + h01(i * 5.3) * 10.0
				_dot(atlas.ring, Vector2(x, y), r, PipeArt.fade(acc, 0.3 * alpha))
				_dot(atlas.disk, Vector2(x - r * 0.35, y - r * 0.35), r * 0.25, PipeArt.fade(Color.WHITE, 0.18 * alpha))
		"gears":
			for i in 8:
				var left := i % 2 == 0
				var gx := (h01(i * 2.3) * 0.12 + 0.02) * vs.x
				var x := gx if left else vs.x - gx
				var y := fposmod(h01(i * 4.1) * (vs.y + 300.0) + scroll * 0.4, vs.y + 300.0) - 150.0
				var r := 40.0 + h01(i * 9.1) * 60.0
				draw_set_transform(Vector2(x, y), t * (0.4 if left else -0.4) * (1.5 - h01(i)), Vector2.ONE)
				draw_texture_rect(atlas.gear, Rect2(-r, -r, r * 2.0, r * 2.0), false, PipeArt.fade(pal["wall"].darkened(0.2), 0.55 * alpha))
			draw_set_transform(Vector2.ZERO)
		"grid":
			var col := PipeArt.fade(acc, 0.16 * alpha)
			var gap := 48.0
			var y := vs.y + fposmod(scroll * 0.5, gap)
			while y > -gap:
				draw_rect(Rect2(0, y - 1.0, vs.x, 2.0), col)
				y -= gap
			var x := fposmod(vs.x * 0.5, gap)
			while x < vs.x:
				draw_rect(Rect2(x - 1.0, 0, 2.0, vs.y), col)
				x += gap
			for i in 6:
				var sx := h01(i * 6.6) * vs.x
				var sy := fposmod(h01(i * 3.3) * vs.y + scroll * 0.5 + t * 30.0, vs.y)
				draw_rect(Rect2(sx, vs.y - sy, 3, 18), PipeArt.fade(pal["goo"], 0.4 * alpha))
		"embers":
			for i in 36:
				var x := h01(i * 3.7) * vs.x + sin(t * 1.3 + i) * 10.0
				var sp := 30.0 + h01(i * 1.9) * 60.0
				var y := vs.y - fposmod(h01(i * 8.3) * vs.y + t * sp + scroll * 0.35, vs.y + 20.0)
				var fl := 0.5 + 0.5 * sin(t * 8.0 + i * 2.0)
				_dot(atlas.soft, Vector2(x, y), 3.0 + h01(i * 2.9) * 5.0, PipeArt.fade(acc.lerp(Color("ff4a1a"), h01(i)), (0.45 + 0.5 * fl) * alpha))
		"stars":
			for i in 90:
				var layer := 0.08 + h01(i * 1.3) * 0.25
				var x := h01(i * 4.9) * vs.x
				var y := fposmod(h01(i * 2.1) * vs.y + scroll * layer, vs.y)
				var tw := 0.5 + 0.5 * sin(t * (1.0 + h01(i) * 3.0) + i)
				_dot(atlas.disk, Vector2(x, y), 0.8 + layer * 5.0, PipeArt.fade(Color.WHITE.lerp(acc, h01(i * 7.0)), (0.3 + 0.6 * tw) * alpha))


# --- queue panel ---------------------------------------------------------------------------

func _queue_signature() -> String:
	# Includes whether each animation is running, so the frame after it ends is redrawn too.
	return "%s|%d|%s|%d|%d|%s|%d|%d|%s|%s|%d|%s|%d|%s" % [str(game.queue), game.zone_index, game.portrait,
			ceili(game.slow_timer), game.state, game.queue_rect, atlas.icon_px, atlas.tile_px,
			game.queue_shift > 0.0, game.lock_timer > 0.0, game.wildcards, game.mode, game.held_piece, game.is_touch]


func _draw_queue_bg(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0 or game.state == game.State.TITLE:
		return
	var q: Rect2 = game.queue_rect
	var pal := Zones.theme(game.zone_index)
	var f := PipeArt.font()
	_sb.bg_color = Color(0.05, 0.06, 0.08, 0.88)
	_sb.set_corner_radius_all(18)
	_sb.set_border_width_all(3)
	_sb.border_color = Color(0.23, 0.7, 1.0, 0.55)
	ci.draw_style_box(_sb, q)
	var slots: Array = game.queue_slot_rects()
	var unlock: bool = game.mode == "unlock"
	for i in slots.size():
		if unlock and i > 0:
			break
		var sr: Rect2 = slots[i]
		_sb.bg_color = Color(1, 1, 1, 0.07) if i > 0 else PipeArt.fade(pal["tile"], 0.95)
		_sb.set_corner_radius_all(int(sr.size.x * 0.16))
		_sb.set_border_width_all(3 if i == 0 else 0)
		_sb.border_color = Color("3ab4ff")
		ci.draw_style_box(_sb, sr)
	_sb.set_border_width_all(0)
	if slots.is_empty():
		return
	var s0: Rect2 = slots[0]
	if game.wildcards > 0:
		ci.draw_rect(s0.grow(4), Color.from_hsv(fposmod(game.time * 0.5, 1.0), 0.8, 1.0), false, 4)
	var title := "HAND" if unlock else "NEXT"
	if not game.portrait:
		_text(ci, f, Vector2(s0.get_center().x, s0.position.y - 10), title, 20, Color(1, 1, 1, 0.8))
	else:
		_text(ci, f, Vector2(s0.get_center().x, s0.position.y - 4), title, 15, Color(1, 1, 1, 0.8))
	if unlock and slots.size() > 1 and not (game.portrait and game.powers_shown()):
		var hint := _hint_rect(slots)
		var verb := "Tap" if game.is_touch else "Click"
		var msg := ""
		if game.held_piece >= 0:
			msg = "%s an open spot or another pipe to swap them. %s it again to put it back." % [verb, verb]
		else:
			msg = "%s a block to open it. %s a pipe, then a spot, to move it." % [verb, verb]
		var fsz := int(clampf(hint.size.y * 0.2, 13.0, 17.0)) if game.portrait else 16
		ci.draw_multiline_string_outline(f, hint.position + Vector2(0, fsz), msg, HORIZONTAL_ALIGNMENT_LEFT, hint.size.x, fsz, -1, 4, Color(0, 0, 0, 0.8))
		ci.draw_multiline_string(f, hint.position + Vector2(0, fsz), msg, HORIZONTAL_ALIGNMENT_LEFT, hint.size.x, fsz, -1, Color(0.85, 0.95, 1.0, 0.9))
	for chip in _chips():
		_text(ci, f, chip["text_pos"], chip["text"], chip["size"], Color.WHITE, HORIZONTAL_ALIGNMENT_LEFT)


## Unlock mode: where the how-to text goes (the space of the queue's small slots).
func _hint_rect(slots: Array) -> Rect2:
	var q: Rect2 = game.queue_rect
	var box := (slots[1] as Rect2).merge(slots[slots.size() - 1])
	if game.portrait:
		return Rect2(box.position.x, q.position.y + 8.0, box.size.x, q.size.y - 16.0)
	return Rect2(q.position.x + 12.0, box.position.y, q.size.x - 24.0, box.size.y)


func _chips() -> Array:
	var st: Rect2 = game.status_rect
	var icon := minf(st.size.y * 0.42, 22.0)
	var x := st.position.x
	var y := st.get_center().y
	var out := []
	var items := []
	if game.slow_timer > 0.0:
		items.append([Tile.PU_SLOW, "%ds" % ceili(game.slow_timer)])
	if game.wildcards > 0:
		items.append([Tile.PU_WILD, "PICK"])
	for it in items:
		out.append({"kind": it[0], "center": Vector2(x + icon, y), "radius": icon * 0.8,
				"text": it[1], "text_pos": Vector2(x + icon * 2.0 + 18, y + icon * 0.35), "size": int(icon * 0.9)})
		x += icon * 4.0
	return out


func _draw_queue_icons(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0 or game.state == game.State.TITLE or atlas.icon_px <= 0:
		return
	var slots: Array = game.queue_slot_rects()
	var shift: float = game.queue_shift
	var itex := atlas.icon_tex(game.zone_index)
	if game.mode == "unlock":
		if not slots.is_empty() and game.held_piece >= 0:
			var s0: Rect2 = slots[0]
			var sz := s0.size.x * 0.86
			ci.draw_texture_rect_region(itex, Rect2(s0.get_center() - Vector2(sz, sz) * 0.5, Vector2(sz, sz)), atlas.icon_region(game.held_piece))
		slots = []
	for i in slots.size():
		var sr: Rect2 = slots[i]
		var pr := sr
		var a := 1.0 if i == 0 else 0.85
		# Pieces slide one slot forward after each placement.
		if shift > 0.0:
			var nxt := sr
			if i + 1 < slots.size():
				nxt = slots[i + 1]
			elif i > 0:
				nxt = Rect2(sr.position + (sr.position - (slots[i - 1] as Rect2).position), sr.size)
			pr = Rect2(sr.position.lerp(nxt.position, shift), sr.size.lerp(nxt.size, shift))
			if i == slots.size() - 1:
				a *= 1.0 - shift
		var size := pr.size.x * 0.86
		ci.draw_texture_rect_region(itex, Rect2(pr.get_center() - Vector2(size, size) * 0.5, Vector2(size, size)),
				atlas.icon_region(game.queue[i]), Color(a, a, a, a))
	var tex := atlas.tile_tex(game.zone_index)
	for chip in _chips():
		_icon(ci, tex, SpriteAtlas.PU + chip["kind"] - 1, chip["center"], chip["radius"] / SpriteAtlas.PU_R)


func _draw_queue_fg(ci: CanvasItem) -> void:
	if game == null or game.T <= 0.0 or game.state == game.State.TITLE or game.lock_timer <= 0.0:
		return
	var slots: Array = game.queue_slot_rects()
	if slots.is_empty():
		return
	var s0: Rect2 = slots[0]
	_sb.bg_color = Color(0.6, 0.05, 0.05, 0.6)
	_sb.set_corner_radius_all(int(s0.size.x * 0.16))
	_sb.set_border_width_all(0)
	ci.draw_style_box(_sb, s0)
	var frac: float = game.lock_timer / Tuning.REPLACE_LOCK_TIME
	ci.draw_arc(s0.get_center(), s0.size.x * 0.3, -PI / 2, -PI / 2 + TAU * frac, 32, Color.WHITE, maxf(3.0, s0.size.x * 0.06), true)
	_text(ci, PipeArt.font(), s0.get_center() + Vector2(0, s0.size.y * 0.08), "LOCK", int(s0.size.x * 0.17), Color.WHITE)


func _text(ci: CanvasItem, f: Font, pos: Vector2, s: String, size: int, col: Color, align := HORIZONTAL_ALIGNMENT_CENTER) -> void:
	var w := 400.0
	var p := pos + Vector2(-w * 0.5, 0) if align == HORIZONTAL_ALIGNMENT_CENTER else pos - Vector2(18, 0)
	ci.draw_string_outline(f, p, s, align, w, size, maxi(3, size / 4), Color(0, 0, 0, 0.85 * col.a))
	ci.draw_string(f, p, s, align, w, size, col)
