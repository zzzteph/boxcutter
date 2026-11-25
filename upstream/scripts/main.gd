## ============================================================================
##  UPSTREAM - game controller: state machine, rules, scoring and layout.
## ============================================================================
## Owns the Grid, Generator, Flow and Camera, and wires the Renderer, Input,
## UI and Sfx nodes together. See tuning.gd for every difficulty knob.
extends Node2D

enum State { TITLE, COUNTDOWN, RUNNING, SPILL, GAMEOVER }

const REASONS := {
	"rock": "The water smashed into a rock.",
	"empty": "The water poured out onto an empty tile.",
	"leak": "The water leaked out of an open pipe end.",
	"wall": "The water hit the wall.",
	"oneway": "The water hit a one-way pipe from the wrong side.",
	"clogged": "The water ran into a pipe that was already full.",
	"locked": "The water hit a closed block. Open the blocks ahead of it.",
}

var state := State.TITLE
var paused := false
var mode: String = Tuning.DEFAULT_MODE  ## "unlock" (BioShock-style) or "classic" (piece queue).
var grid := Grid.new()
var gen := LevelGenerator.new()
var flow := Flow.new()
var cam := GameCamera.new()
var queue: Array[int] = []        ## Classic mode: upcoming pipe items (see Pieces.item).
var rng := RandomNumberGenerator.new()

var renderer: BoardRenderer
var atlas: SpriteAtlas
var world_view: TextureRect          ## PS1 mode: shows the world viewport, scaled to the screen.
var world_vp: SubViewport            ## PS1 mode: the world renders in here, at PS1_SHORT_SIDE lines.
var is_touch := false
var input_handler: InputHandler
var ui: GameUI
var sfx: Sfx

# Run state
var score := 0
var best := 0
var height := 0            ## Highest row the goo has reached.
var countdown := 0.0
var fast_forward := false
var slow_timer := 0.0
var wildcards := 0
var lock_timer := 0.0
var queue_shift := 0.0     ## 1 -> 0 slide animation after a placement.
var time := 0.0
var zone_index := 0
var spill := {}
var spill_timer := 0.0
var new_best := false
var crosses := 0
var last_reason := ""
var _beeped := 0
# Unlock mode
var held_from := Vector2i(-1, -1)  ## Tile whose pipe is picked up ((-1,-1) = from a wildcard).
var held_piece := -1               ## Pipe item in hand (see Pieces.item), -1 = empty hand.
var surge_timer := 0.0             ## Alarm surge time left.
# Milestone powers (earned every POWER_AWARD_ROWS rows)
var freezes := 0                   ## Flow-freeze charges.
var reveals := 0                   ## Reveal charges.
var freeze_timer := 0.0            ## Time left on a running freeze.
var freeze_started := -100.0       ## Game time the current freeze began.
var _next_award_row := Tuning.POWER_AWARD_ROWS
var flips := 0
var alarms := 0

# Layout, in virtual pixels (720 on the short side).
var view_size := Vector2(720, 720)
var portrait := false
var hud_h := 66.0
var T := 64.0
var px_scale := 1.0        ## Physical pixels per virtual pixel (window stretch).
var board_rect := Rect2()
var queue_rect := Rect2()
var status_rect := Rect2()
var ff_rect := Rect2()
var freeze_rect := Rect2()   ## Milestone power buttons (shown when you have charges).
var reveal_rect := Rect2()
var _slots: Array = []

# Pointer / keyboard cursor
var hover := Vector2i(-1, -1)
var hover_active := false
var kb_cursor := Vector2i(Tuning.SOURCE_COL, 1)
var kb_active := false

# Debug flags: add ?fps / ?autoplay to the web URL (or --fps / --autoplay after "--" on the command line).
var debug_fps := false
var debug_autoplay := false
var debug_powers := false   ## ?powers: start each run with 3 Flow-freezes and 3 Reveals.
var _fps_timer := 0.0


func _ready() -> void:
	rng.randomize()
	sfx = Sfx.new()
	add_child(sfx)
	atlas = SpriteAtlas.new()
	add_child(atlas)
	renderer = BoardRenderer.new()
	renderer.game = self
	renderer.atlas = atlas
	if Tuning.PS1_MODE:
		_build_world_viewport()
		renderer.overlay_parent = self
		world_vp.add_child(renderer)
	else:
		add_child(renderer)
	input_handler = InputHandler.new()
	input_handler.game = self
	add_child(input_handler)
	ui = GameUI.new()
	ui.game = self
	add_child(ui)
	best = SaveData.load_best()
	_read_debug_flags()
	_compute_layout()
	new_board(rng.randi())
	state = State.TITLE
	ui.show_title(best)


## PS1 mode: the board renders into a low-resolution viewport that is scaled up
## with nearest-neighbour sampling and run through the 15-bit dither shader.
## The HUD and menus stay on the full-resolution screen so text stays readable.
func _build_world_viewport() -> void:
	world_vp = SubViewport.new()
	world_vp.disable_3d = true
	world_vp.gui_disable_input = true
	world_vp.render_target_update_mode = SubViewport.UPDATE_ALWAYS
	world_vp.size_2d_override_stretch = true
	add_child(world_vp)
	world_view = TextureRect.new()
	world_view.texture = world_vp.get_texture()
	world_view.expand_mode = TextureRect.EXPAND_IGNORE_SIZE
	world_view.stretch_mode = TextureRect.STRETCH_SCALE
	world_view.mouse_filter = Control.MOUSE_FILTER_IGNORE
	world_view.texture_filter = CanvasItem.TEXTURE_FILTER_LINEAR if Tuning.SMOOTH_EDGES else CanvasItem.TEXTURE_FILTER_NEAREST
	var mat := ShaderMaterial.new()
	mat.shader = load("res://scripts/ps1_screen.gdshader")
	mat.set_shader_parameter("levels", Tuning.PS1_COLOR_LEVELS)
	mat.set_shader_parameter("dither", Tuning.PS1_DITHER)
	world_view.material = mat
	add_child(world_view)


func _notification(what: int) -> void:
	if what == NOTIFICATION_APPLICATION_FOCUS_OUT and (state == State.COUNTDOWN or state == State.RUNNING) and not paused:
		toggle_pause()


# --- run lifecycle ------------------------------------------------------------------

func new_board(seed_value: int) -> void:
	grid.clear()
	gen.reset(seed_value)
	gen.unlock_mode = mode == "unlock"
	_clear_hand()
	surge_timer = 0.0
	freezes = 0
	reveals = 0
	freeze_timer = 0.0
	freeze_started = -100.0
	_next_award_row = Tuning.POWER_AWARD_ROWS
	flips = 0
	alarms = 0
	flow.reset()
	if renderer:
		renderer.clear_fx()
		renderer.invalidate_rows()
	score = 0
	height = 0
	fast_forward = false
	slow_timer = 0.0
	wildcards = 0
	lock_timer = 0.0
	queue_shift = 0.0
	zone_index = 0
	spill = {}
	spill_timer = 0.0
	new_best = false
	crosses = 0
	last_reason = ""
	countdown = Tuning.COUNTDOWN_TIME
	_beeped = 0
	queue.clear()
	for i in Tuning.QUEUE_SIZE:
		queue.append(_random_piece())
	cam.visible_rows = board_rect.size.y / T if T > 0.0 else Tuning.MIN_VISIBLE_ROWS
	cam.snap(0.5, 0)
	_ensure_rows()
	kb_cursor = Vector2i(Tuning.SOURCE_COL, 1)
	kb_active = false


func start_run() -> void:
	new_board(rng.randi())
	if debug_powers:
		freezes = 3
		reveals = 3
	paused = false
	state = State.COUNTDOWN
	ui.show_play()
	sfx.play("click")


func go_to_title() -> void:
	paused = false
	new_board(rng.randi())
	state = State.TITLE
	ui.show_title(best)


func _start_flow() -> void:
	countdown = 0.0
	flow.begin(grid, Tuning.SOURCE_COL, 0, Pieces.S, _goo_color())
	state = State.RUNNING
	sfx.play("go")
	ui.show_toast("PUMP ON!", Color("8fd8ff"))


func _random_piece() -> int:
	var total := 0
	for w in Tuning.PIECE_WEIGHTS:
		total += w
	var p := 0
	for attempt in 2:
		var x := rng.randi_range(0, total - 1)
		for i in Tuning.PIECE_WEIGHTS.size():
			x -= Tuning.PIECE_WEIGHTS[i]
			if x < 0:
				p = i
				break
		# Avoid three of the same piece in a row.
		var n := queue.size()
		if not (n >= 2 and Pieces.item_piece(queue[n - 1]) == p and Pieces.item_piece(queue[n - 2]) == p):
			break
	return Pieces.item(p, rng.randf() < Tuning.NARROW_CHANCE)


# --- frame update --------------------------------------------------------------------

func _process(dt: float) -> void:
	dt = minf(dt, 0.05)
	time += dt
	_compute_layout()
	if not paused:
		match state:
			State.COUNTDOWN, State.RUNNING:
				_update_play(dt)
			State.SPILL:
				_update_spill(dt)
		renderer.update_fx(dt)
		queue_shift = maxf(0.0, queue_shift - dt * 7.0)
		var head := flow.head_world() if (flow.active or state == State.SPILL or state == State.GAMEOVER) \
				else Vector2(Tuning.SOURCE_COL + 0.5, 0.5)
		cam.update(dt, head.y, grid.floor_row)
	_ensure_rows()
	if debug_autoplay:
		_autoplay_step()
	if debug_fps:
		_fps_timer += dt
		if _fps_timer >= 2.0:
			_fps_timer = 0.0
			print("FPS %d | process %.2f ms | draw calls %d | primitives %d | height %d | score %d | state %s | rows in memory %d" % [
					Engine.get_frames_per_second(), Performance.get_monitor(Performance.TIME_PROCESS) * 1000.0,
					Performance.get_monitor(Performance.RENDER_TOTAL_DRAW_CALLS_IN_FRAME),
					Performance.get_monitor(Performance.RENDER_TOTAL_PRIMITIVES_IN_FRAME),
					height, score, State.keys()[state], grid.row_count()])
	renderer.redraw()
	ui.refresh()


func _update_play(dt: float) -> void:
	lock_timer = maxf(0.0, lock_timer - dt)
	_check_hand()
	if state == State.COUNTDOWN:
		countdown -= dt
		var n := int(ceil(countdown))
		if n <= 3 and n >= 1 and n != _beeped:
			_beeped = n
			sfx.play("beep")
		if countdown <= 0.0:
			_start_flow()
		return
	slow_timer = maxf(0.0, slow_timer - dt)
	surge_timer = maxf(0.0, surge_timer - dt)
	if freeze_timer > 0.0:
		freeze_timer -= dt
		if randf() < 0.6:
			renderer.snow(1)
		if freeze_timer <= 0.0:
			freeze_timer = 0.0
			sfx.play("thaw")
			renderer.thaw_drips()
	var amount := dt * effective_speed() / Tuning.BASE_SEGMENT_TIME
	for e in flow.advance(grid, amount, _goo_color()):
		grid.touch(e["row"])
		_handle_event(e)
		if state != State.RUNNING:
			break


func _update_spill(dt: float) -> void:
	spill_timer -= dt
	if randf() < 0.5:
		renderer.burst(spill["p"], spill["col"], 2, 2.2, 0.06, 0.8, 9.0)
	if spill_timer <= 0.0:
		state = State.GAMEOVER
		ui.show_game_over(REASONS.get(last_reason, "The water spilled."), score, height, best, new_best)


func _ensure_rows() -> void:
	var floor_r := maxi(0, height - Tuning.KEEP_ROWS_BELOW)
	if floor_r > grid.floor_row:
		grid.discard_below(floor_r)
		gen.forget_below(floor_r)
	var top := int(ceil(cam.y + cam.visible_rows)) + Tuning.GENERATE_AHEAD
	top = maxi(top, height + Tuning.GENERATE_AHEAD)
	gen.generate_until(grid, top)


# --- rules & scoring ---------------------------------------------------------------------

func multiplier() -> float:
	return 1.0 + Tuning.MULT_STEP * floorf(height / float(Tuning.MULT_ROWS_STEP))


func height_speed() -> float:
	return minf(Tuning.MAX_SPEED, 1.0 + height * Tuning.SPEEDUP_PER_ROW)


func effective_speed() -> float:
	var s := height_speed()
	if fast_forward:
		s *= Tuning.FAST_FORWARD_MULT
	if slow_timer > 0.0:
		s *= Tuning.SLOWMO_MULT
	if surge_timer > 0.0:
		s *= Tuning.ALARM_SURGE_MULT
	if freeze_timer > 0.0:
		return 0.0
	return s


func add_points(base: float) -> int:
	var pts := int(round(base * multiplier() * (Tuning.FAST_FORWARD_SCORE_MULT if fast_forward else 1.0)))
	score += pts
	return pts


func _goo_color() -> Color:
	return Zones.theme_for_row(flow.row if flow.active else 0)["goo"]


func _handle_event(e: Dictionary) -> void:
	match e["type"]:
		"enter":
			var r: int = e["row"]
			if r > height:
				_set_height(r)
				var zi := Zones.index_for_row(height)
				if zi > zone_index:
					zone_index = zi
					ui.show_banner(Zones.title(zi))
					sfx.play("zone")
			var t: Tile = e["tile"]
			var wp := Vector2(e["col"] + 0.5, e["row"] + 0.5)
			if t.narrow:
				renderer.float_text(wp, "SLOW", Color("e8c020"), 0.28, 0.8)
			if t.powerup != Tile.PU_NONE:
				_apply_powerup(t.powerup, wp)
				t.powerup = Tile.PU_NONE
		"filled":
			var t: Tile = e["tile"]
			if t.kind == Tile.SOURCE:
				return
			add_points(Tuning.SCORE_SEGMENT)
			sfx.play("tick", 0.92 + randf() * 0.16 + minf(0.5, height * 0.004), -5.0)
			if t.piece == Pieces.CROSS and t.fill[0] >= 1.0 and t.fill[1] >= 1.0:
				var pts := add_points(Tuning.SCORE_CROSS_DOUBLE)
				crosses += 1
				var wp := Vector2(e["col"] + 0.5, e["row"] + 0.5)
				renderer.burst(wp, Color("ffffff"), 30, 4.5, 0.08, 1.0)
				renderer.float_text(wp, "CROSS! +%d" % pts, Color("8af0ff"), 0.4, 1.3)
				sfx.play("cross")
		"blocked":
			_game_over(e)


## New best height: zone banners, and the milestone powers every 100 rows.
func _set_height(r: int) -> void:
	height = r
	while height >= _next_award_row:
		freezes += 1
		reveals += 1
		ui.show_toast("ROW %d!  +1 FLOW-FREEZE  +1 REVEAL" % _next_award_row, Color("8fe8ff"))
		sfx.play("powerup", 0.8)
		renderer.float_text(flow.head_world(), "+FREEZE  +REVEAL", Color("bff0ff"), 0.36, 1.6)
		_next_award_row += Tuning.POWER_AWARD_ROWS


## Flow-freeze: every pipe frosts over and the water stops for FREEZE_TIME.
func use_freeze() -> bool:
	if freezes <= 0 or state != State.RUNNING or paused or freeze_timer > 0.0:
		sfx.play("deny")
		return false
	freezes -= 1
	freeze_timer = Tuning.FREEZE_TIME
	freeze_started = time
	sfx.play("freeze")
	cam.add_shake(0.2)
	renderer.snow(40)
	ui.show_toast("FLOW FROZEN", Color("bff0ff"))
	ui.flash(Color(0.85, 0.97, 1.0, 0.45))
	buzz(60)
	return true


## Reveal: unlock every tile on the current map, in a wave from the bottom.
## Alarms are disarmed rather than set off.
func use_reveal() -> bool:
	if reveals <= 0 or (state != State.COUNTDOWN and state != State.RUNNING) or paused:
		sfx.play("deny")
		return false
	var base := floori(cam.y)
	var count := 0
	for r in range(grid.floor_row, grid.top_row + 1):
		var any := false
		for c in Tuning.COLS:
			var t := grid.get_tile(c, r)
			if t == null or not t.hidden:
				continue
			t.hidden = false
			t.alarm = false
			t.flip_at = time + maxf(0.0, r - base) * 0.045 + c * 0.012
			any = true
			count += 1
		if any:
			grid.touch(r)
			renderer.animate_row(r, time + maxf(0.0, r - base) * 0.045 + 0.1 + Tuning.FLIP_TIME + 0.05)
	if count == 0:
		ui.show_toast("Nothing left to reveal", Color("8fa3ab"))
		sfx.play("deny")
		return false
	reveals -= 1
	sfx.play("reveal")
	ui.show_toast("MAP REVEALED", Color("8fe8ff"))
	return true


func _apply_powerup(kind: int, wp: Vector2) -> void:
	var col := PipeArt.powerup_color(kind)
	match kind:
		Tile.PU_SLOW:
			slow_timer += Tuning.SLOWMO_DURATION
			ui.show_toast("SLOW-MO!  Half speed for %ds" % int(Tuning.SLOWMO_DURATION), col)
			renderer.float_text(wp, "SLOW-MO", col)
		Tile.PU_WILD:
			wildcards += 1
			ui.show_toast("WILDCARD!  Choose any piece", col)
			renderer.float_text(wp, "WILDCARD", col)
	renderer.burst(wp, col, 32, 4.5, 0.08, 1.0)
	sfx.play("powerup")


func _game_over(e: Dictionary) -> void:
	state = State.SPILL
	spill_timer = 1.5
	last_reason = e["reason"]
	var v: Vector2i = Pieces.DIR_VEC[e["exit"]]
	var p := Vector2(e["col"] + 0.5, e["row"] + 0.5) + Vector2(v.x, v.y) * 0.5
	var col := _goo_color()
	spill = {"p": p, "t": time, "col": col, "seed": randf() * TAU}
	cam.add_shake(0.85)
	sfx.play("gameover")
	buzz(250)
	renderer.burst(p, col, 44, 5.0, 0.09, 1.2, 8.0)
	fast_forward = false
	slow_timer = 0.0
	surge_timer = 0.0
	freeze_timer = 0.0
	_clear_hand()
	if score > best:
		best = score
		new_best = true
		SaveData.save_best(best)


# --- placement ------------------------------------------------------------------------------

func screen_to_tile(pos: Vector2) -> Vector2i:
	return Vector2i(floori((pos.x - board_rect.position.x) / T), floori(cam.y + (board_rect.end.y - pos.y) / T))


func is_tile_visible(c: int, r: int) -> bool:
	if c < 0 or c >= Tuning.COLS or r < grid.floor_row or r > grid.top_row:
		return false
	var cy := board_rect.end.y - (r + 0.5 - cam.y) * T
	return cy >= board_rect.position.y and cy <= board_rect.end.y


## What clicking tile (c, r) would do. Classic: place, replace, locked or no.
## Unlock: flip, pick, drop, deselect or no.
func placement_mode(c: int, r: int) -> String:
	var t := grid.get_tile(c, r)
	if t == null or not is_tile_visible(c, r):
		return "no"
	if mode == "unlock":
		return _unlock_action(t, c, r)
	if t.kind != Tile.EMPTY or t.has_goo() or t.fixed:
		return "no"
	if lock_timer > 0.0:
		return "locked"
	return "replace" if t.piece >= 0 else "place"


func try_place(c: int, r: int) -> String:
	if (state != State.COUNTDOWN and state != State.RUNNING) or paused:
		return "inactive"
	if mode == "unlock":
		return _unlock_click(c, r)
	var action := placement_mode(c, r)
	var t := grid.get_tile(c, r)
	var wp := Vector2(c + 0.5, r + 0.5)
	if action == "place" or action == "replace":
		grid.touch(r)
		renderer.animate_row(r, time + 0.45)
	match action:
		"place", "replace":
			t.set_item(queue.pop_front())
			queue.append(_random_piece())
			queue_shift = 1.0
			t.placed_at = time
			if action == "replace":
				score = maxi(0, score - Tuning.REPLACE_PENALTY)
				lock_timer = Tuning.REPLACE_LOCK_TIME
				sfx.play("replace")
				renderer.float_text(wp, "-%d" % Tuning.REPLACE_PENALTY, Color("ff8a5a"), 0.3, 0.9)
				renderer.burst(wp, Color(0.8, 0.8, 0.8), 10, 2.5, 0.06, 0.5, 3.0, false)
			else:
				sfx.play("place", 0.95 + randf() * 0.1)
				renderer.burst(wp, Color(1, 1, 1, 0.7), 6, 1.5, 0.05, 0.35, 0.0, false)
		"locked":
			sfx.play("deny")
			ui.show_toast("LOCKED!", Color("ff6a5a"))
		_:
			sfx.play("deny")
	return action


# --- unlock mode (BioShock-style) -------------------------------------------------------------

func _unlock_action(t: Tile, c: int, r: int) -> String:
	if t.hidden:
		return "flip"
	if held_piece >= 0:
		if Vector2i(c, r) == held_from:
			return "deselect"
		if t.is_slot() or t.is_loose():
			return "drop"
		return "no"
	if t.is_loose():
		return "pick"
	return "no"


## Unlock a tile, pick a pipe up, or drop the pipe in hand (swapping with
## whatever is there).
func _unlock_click(c: int, r: int) -> String:
	var t := grid.get_tile(c, r)
	if t == null or not is_tile_visible(c, r):
		sfx.play("deny")
		return "no"
	var action := _unlock_action(t, c, r)
	var wp := Vector2(c + 0.5, r + 0.5)
	match action:
		"flip":
			t.hidden = false
			t.flip_at = time
			flips += 1
			grid.touch(r)
			renderer.animate_row(r, time + Tuning.FLIP_TIME + 0.05)
			sfx.play("flip", 0.9 + randf() * 0.2)
			renderer.burst(wp, Color(0.8, 0.85, 0.9), 8, 2.0, 0.05, 0.4, 2.0, false)
			if t.alarm:
				t.alarm = false
				_trigger_alarm(wp)
		"pick":
			held_from = Vector2i(c, r)
			held_piece = t.get_item()
			sfx.play("pick")
		"deselect":
			_clear_hand()
			sfx.play("click")
		"drop":
			var src: Tile = grid.get_tile(held_from.x, held_from.y) if held_from.x >= 0 else null
			var old := t.get_item()
			t.set_item(held_piece)
			t.placed_at = time
			grid.touch(r)
			renderer.animate_row(r, time + 0.45)
			if src != null:
				src.set_item(old)
				if old >= 0:
					src.placed_at = time
				grid.touch(held_from.y)
				renderer.animate_row(held_from.y, time + 0.45)
			_clear_hand()
			sfx.play("place", 0.95 + randf() * 0.1)
			renderer.burst(wp, Color(1, 1, 1, 0.7), 6, 1.5, 0.05, 0.35, 0.0, false)
		_:
			sfx.play("deny")
	return action


func _trigger_alarm(wp: Vector2) -> void:
	alarms += 1
	surge_timer = Tuning.ALARM_SURGE_TIME
	score = maxi(0, score - Tuning.ALARM_PENALTY)
	cam.add_shake(0.45)
	sfx.play("alarm")
	renderer.burst(wp, Color("ff3a2a"), 30, 4.0, 0.08, 0.9)
	renderer.float_text(wp, "ALARM! -%d" % Tuning.ALARM_PENALTY, Color("ff5a4a"), 0.36, 1.3)
	ui.show_toast("ALARM!  The water surges", Color("ff5a4a"))
	buzz(120)
	ui.flash(Color(1.0, 0.1, 0.05, 0.35))


func _clear_hand() -> void:
	held_from = Vector2i(-1, -1)
	held_piece = -1


## Drop the hand if the picked-up pipe scrolled away, got goo, or changed.
func _check_hand() -> void:
	if held_piece < 0 or held_from.x < 0:
		return
	var t := grid.get_tile(held_from.x, held_from.y)
	if t == null or not t.is_loose() or t.get_item() != held_piece or not is_tile_visible(held_from.x, held_from.y):
		_clear_hand()


# --- input entry points ---------------------------------------------------------------------

func on_pointer_move(pos: Vector2, touch := false) -> void:
	hover = screen_to_tile(pos)
	hover_active = not touch and board_rect.has_point(pos) and is_tile_visible(hover.x, hover.y)
	if not touch:
		kb_active = false


func on_pointer_press(pos: Vector2, touch := false) -> void:
	if state != State.COUNTDOWN and state != State.RUNNING or paused:
		return
	if not board_rect.has_point(pos):
		return
	var cell := screen_to_tile(pos)
	hover = cell
	hover_active = not touch and is_tile_visible(cell.x, cell.y)
	try_place(cell.x, cell.y)


func move_cursor(dx: int, dy: int) -> void:
	if (state != State.COUNTDOWN and state != State.RUNNING) or paused:
		return
	if not kb_active:
		kb_active = true
		if hover_active:
			kb_cursor = hover
		elif flow.active:
			kb_cursor = Vector2i(flow.col, flow.row + 1)
		else:
			kb_cursor = Vector2i(Tuning.SOURCE_COL, 1)
	else:
		kb_cursor += Vector2i(dx, dy)
	hover_active = false
	var lo := maxi(grid.floor_row, ceili(cam.y + 0.01))
	var hi := floori(cam.y + cam.visible_rows - 0.51)
	kb_cursor.x = clampi(kb_cursor.x, 0, Tuning.COLS - 1)
	kb_cursor.y = clampi(kb_cursor.y, lo, maxi(lo, hi))


func on_confirm() -> void:
	match state:
		State.TITLE, State.GAMEOVER:
			start_run()
		State.COUNTDOWN, State.RUNNING:
			if paused:
				toggle_pause()
			elif kb_active:
				try_place(kb_cursor.x, kb_cursor.y)
			else:
				move_cursor(0, 0)


func restart_key() -> void:
	if state == State.TITLE or state == State.GAMEOVER or paused:
		start_run()


func toggle_pause() -> void:
	if state != State.COUNTDOWN and state != State.RUNNING:
		return
	paused = not paused
	ui.show_pause(paused)
	sfx.play("click")


func toggle_mute() -> void:
	sfx.set_muted(not sfx.muted)
	sfx.play("click")


func activate_fast_forward() -> void:
	if (state != State.COUNTDOWN and state != State.RUNNING) or paused or fast_forward:
		return
	fast_forward = true
	if state == State.COUNTDOWN:
		_start_flow()
	sfx.play("ff")
	ui.show_toast("FAST-FORWARD!  x2 POINTS", Color("ffd23a"))


func choose_wildcard(piece: int) -> void:
	if wildcards <= 0 or piece < 0 or piece >= Pieces.COUNT:
		return
	if (state != State.COUNTDOWN and state != State.RUNNING) or paused:
		return
	wildcards -= 1
	sfx.play("powerup", 1.4)
	if mode == "unlock":
		held_from = Vector2i(-1, -1)
		held_piece = piece
		ui.show_toast("%s a spot to place your %s" % ["Tap" if is_touch else "Click", Pieces.NAMES[piece]], Color("e8b0ff"))
		return
	queue[0] = piece
	queue_shift = 0.0
	ui.show_toast("Next piece: %s" % Pieces.NAMES[piece], Color("e8b0ff"))


# --- layout -----------------------------------------------------------------------------------

func powers_shown() -> bool:
	return (state == State.COUNTDOWN or state == State.RUNNING) and (freezes > 0 or reveals > 0 or freeze_timer > 0.0)


## 0..1 strength of the freeze effect: frosts in fast, thaws over the last second.
func freeze_amount() -> float:
	if freeze_timer <= 0.0:
		return 0.0
	return clampf((time - freeze_started) / 0.35, 0.0, 1.0) * clampf(freeze_timer / 1.0, 0.0, 1.0)


func buzz(ms: int) -> void:
	if is_touch:
		Input.vibrate_handheld(ms)


func queue_slot_rects() -> Array:
	return _slots


## Snap to whole physical pixels.
func _px(v: float) -> float:
	return roundf(v * px_scale) / px_scale


func _compute_layout() -> void:
	var win := get_window()
	if win != null and win.size.x > 0:
		# Pick the virtual resolution from the screen's real (logical) size, so
		# phones get a smaller base and therefore bigger text and buttons.
		var ds := DisplayServer.screen_get_scale()
		var logical := minf(win.size.x, win.size.y) / (ds if ds > 0.0 else 1.0)
		var base := clampi(int(logical), Tuning.UI_BASE_MIN, Tuning.UI_BASE_MAX)
		if win.content_scale_size != Vector2i(base, base):
			win.content_scale_size = Vector2i(base, base)
	view_size = get_viewport_rect().size
	if world_vp != null:
		# Render the board at PS1_SHORT_SIDE lines (never above the screen's own pixels).
		var phys := Vector2(win.size) if win != null and win.size.x > 0 else view_size
		if phys.x < view_size.x * 0.5:
			phys = view_size  # Headless / not-yet-sized window: use the virtual size.
		var k := minf(1.0, Tuning.PS1_SHORT_SIDE / minf(phys.x, phys.y))
		var target := Vector2i(maxi(16, roundi(phys.x * k)), maxi(16, roundi(phys.y * k)))
		if world_vp.size != target:
			world_vp.size = target
		if world_vp.size_2d_override != Vector2i(view_size):
			world_vp.size_2d_override = Vector2i(view_size)
		if world_view.size != view_size:
			world_view.position = Vector2.ZERO
			world_view.size = view_size
		px_scale = float(world_vp.size.x) / view_size.x
	else:
		px_scale = float(win.size.x) / view_size.x if win != null and win.size.x > 0 and view_size.x > 0.0 else 1.0
	is_touch = DisplayServer.is_touchscreen_available()
	var min_rows := Tuning.MIN_VISIBLE_ROWS if view_size.y >= 600.0 else Tuning.MIN_VISIBLE_ROWS_COMPACT
	portrait = view_size.x < view_size.y * 0.9
	hud_h = _px(56.0)
	_slots = []
	var n := Tuning.QUEUE_SIZE
	if portrait:
		var bottom_h := clampf(view_size.y * 0.12, 110.0, 150.0)
		var avail_w := view_size.x - 40.0
		var avail_h := view_size.y - hud_h - bottom_h
		T = _tile_size(minf(avail_w / Tuning.COLS, avail_h / min_rows))
		var bw := T * Tuning.COLS
		board_rect = Rect2(_px((view_size.x - bw) * 0.5), hud_h, bw, _px(view_size.y - bottom_h) - hud_h)
		queue_rect = Rect2(8.0, board_rect.end.y + 6.0, view_size.x - 16.0, bottom_h - 14.0)
		var s0 := queue_rect.size.y - 34.0
		var s1 := s0 * 0.72
		var ffw := clampf(view_size.x * 0.17, 100.0, 140.0)
		ff_rect = Rect2(queue_rect.end.x - 14.0 - ffw, queue_rect.position.y + 12.0, ffw, queue_rect.size.y - 24.0)
		var x := queue_rect.position.x + 14.0
		var y := queue_rect.position.y + 24.0
		_slots.append(Rect2(x, y, s0, s0))
		x += s0 + 12.0
		for i in n - 1:
			_slots.append(Rect2(x, y + s0 - s1, s1, s1))
			x += s1 + 8.0
		status_rect = Rect2(x + 4.0, queue_rect.position.y + 8.0, maxf(0.0, ff_rect.position.x - x - 12.0), queue_rect.size.y - 16.0)
		# Power buttons: big thumb targets just left of FAST.
		var pw := ff_rect.size.y * 0.95
		reveal_rect = Rect2(ff_rect.position.x - 10.0 - pw, ff_rect.position.y, pw, ff_rect.size.y)
		freeze_rect = Rect2(reveal_rect.position.x - 8.0 - pw, ff_rect.position.y, pw, ff_rect.size.y)
		if powers_shown():
			var s0r: Rect2 = _slots[0]
			status_rect = Rect2(s0r.end.x + 10.0, queue_rect.position.y + 8.0, maxf(0.0, freeze_rect.position.x - s0r.end.x - 20.0), queue_rect.size.y - 16.0)
	else:
		var panel_w := clampf(view_size.x * 0.17, 150.0, 220.0)
		var avail_w := view_size.x - panel_w - 80.0
		var avail_h := view_size.y - hud_h
		T = _tile_size(minf(avail_w / Tuning.COLS, avail_h / min_rows))
		var bw := T * Tuning.COLS
		var total := bw + 30.0 + panel_w
		var x0 := _px((view_size.x - total) * 0.5)
		board_rect = Rect2(x0, hud_h, bw, _px(view_size.y) - hud_h)
		queue_rect = Rect2(board_rect.end.x + 30.0, hud_h + 12.0, panel_w, view_size.y - hud_h - 24.0)
		var cx := queue_rect.get_center().x
		var y := queue_rect.position.y + 40.0
		if view_size.y >= 600.0:
			# Tall screen: the next piece on top, the rest stacked below it.
			ff_rect = Rect2(queue_rect.position.x + 12.0, queue_rect.end.y - 92.0, panel_w - 24.0, 80.0)
			var avail := ff_rect.position.y - queue_rect.position.y - 40.0 - 70.0 - (n - 1) * 10.0 - 14.0
			var s0 := minf(panel_w - 40.0, avail / (1.0 + (n - 1) * 0.58))
			var s1 := s0 * 0.58
			_slots.append(Rect2(cx - s0 * 0.5, y, s0, s0))
			y += s0 + 14.0
			for i in n - 1:
				_slots.append(Rect2(cx - s1 * 0.5, y, s1, s1))
				y += s1 + 10.0
		else:
			# Short screen (phone held sideways): the next piece, then one row of the rest.
			ff_rect = Rect2(queue_rect.position.x + 12.0, queue_rect.end.y - 70.0, panel_w - 24.0, 58.0)
			var gap := 6.0
			var s1 := (panel_w - 24.0 - gap * (n - 2)) / (n - 1)
			var s0 := minf(panel_w - 40.0, ff_rect.position.y - y - s1 - 14.0 - 44.0)
			_slots.append(Rect2(cx - s0 * 0.5, y, s0, s0))
			y += s0 + 10.0
			var x := queue_rect.position.x + 12.0
			for i in n - 1:
				_slots.append(Rect2(x, y, s1, s1))
				x += s1 + gap
			y += s1 + 4.0
		# Power buttons: a row just above FAST.
		var ph := 64.0 if view_size.y >= 600.0 else 50.0
		var half := (panel_w - 24.0 - 8.0) * 0.5
		freeze_rect = Rect2(queue_rect.position.x + 12.0, ff_rect.position.y - 10.0 - ph, half, ph)
		reveal_rect = Rect2(freeze_rect.end.x + 8.0, freeze_rect.position.y, half, ph)
		var status_end := freeze_rect.position.y if powers_shown() else ff_rect.position.y
		status_rect = Rect2(queue_rect.position.x + 10.0, y, panel_w - 20.0, maxf(30.0, status_end - y - 8.0))
	cam.visible_rows = board_rect.size.y / T
	if atlas != null:
		atlas.ensure(roundi(T * px_scale), roundi((_slots[0] as Rect2).size.x * 0.86 * px_scale))


## A tile size that is a whole number of physical pixels, so atlas sprites stay crisp.
func _tile_size(t: float) -> float:
	return maxf(8.0, floorf(t * px_scale)) / px_scale


# --- test hooks -------------------------------------------------------------------------------

func _read_debug_flags() -> void:
	var qs := ""
	if OS.has_feature("web"):
		var q = JavaScriptBridge.eval("window.location.search", true)
		qs = str(q) if q != null else ""
	for arg in OS.get_cmdline_user_args():
		qs += " " + arg
	debug_fps = qs.contains("fps")
	debug_autoplay = qs.contains("autoplay")
	debug_powers = qs.contains("powers")


## Autoplay: a perfect player that lays the guaranteed path just ahead of the goo.
func _autoplay_step() -> void:
	match state:
		State.TITLE, State.GAMEOVER:
			start_run()
			activate_fast_forward()
		State.COUNTDOWN, State.RUNNING:
			if mode == "unlock":
				_autoplay_unlock()
				return
			var r0 := flow.row if flow.active else 0
			for r in range(maxi(1, r0 - 1), r0 + 6):
				var need: Dictionary = gen.spine_needs.get(r, {})
				for c in need:
					var t := grid.get_tile(c, r)
					if t != null and t.is_free():
						debug_set_piece(c, r, Pieces.piece_for(need[c][0], need[c][1]))


func debug_set_piece(c: int, r: int, piece: int) -> void:
	var t := grid.get_tile(c, r)
	if t != null and t.kind == Tile.EMPTY and not t.has_goo():
		t.set_item(piece)
		t.placed_at = time
		grid.touch(r)
		renderer.animate_row(r, time + 0.45)


## Autoplay in unlock mode: unlock the rows ahead, then swap the needed pipes
## onto the guaranteed path, through the same clicks a player makes.
func _autoplay_unlock() -> void:
	_clear_hand()
	var r0 := flow.row if flow.active else 0
	for r in range(maxi(1, r0 - 1), r0 + 5):
		if not is_tile_visible(0, r):
			continue
		for c in Tuning.COLS:
			var t := grid.get_tile(c, r)
			if t != null and t.hidden:
				_unlock_click(c, r)
		var need: Dictionary = gen.spine_needs.get(r, {})
		for c in need:
			var t := grid.get_tile(c, r)
			var want := Pieces.piece_for(need[c][0], need[c][1])
			if t == null or t.fixed or t.has_goo() or t.piece == want:
				continue
			for c2 in Tuning.COLS:
				var s2 := grid.get_tile(c2, r)
				if c2 == c or s2 == null or not s2.is_loose() or s2.piece != want:
					continue
				if need.has(c2) and Pieces.piece_for(need[c2][0], need[c2][1]) == want:
					continue
				_unlock_click(c2, r)
				_unlock_click(c, r)
				break
