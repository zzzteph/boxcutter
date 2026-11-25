## Integration test: drives the real main scene through input events.
## Run from the project folder (fixed fps makes it deterministic and fast):
##   godot --headless --fixed-fps 60 --script res://tests/game_test.gd
extends SceneTree

const P := preload("res://scripts/pieces.gd")

var game
var failures := 0
var checks := 0
var proc_times: Array = []


func _initialize() -> void:
	game = load("res://main.tscn").instantiate()
	root.add_child(game)
	_run.call_deferred()


func check(cond: bool, msg: String) -> void:
	checks += 1
	if not cond:
		failures += 1
		push_error("FAIL: " + msg)
		print("FAIL: ", msg)


func frames(n: int) -> void:
	for i in n:
		await process_frame
		proc_times.append(Performance.get_monitor(Performance.TIME_PROCESS))


func click(pos: Vector2) -> void:
	var ev := InputEventMouseButton.new()
	ev.button_index = MOUSE_BUTTON_LEFT
	ev.pressed = true
	ev.position = pos
	ev.global_position = pos
	root.push_input(ev, true)
	var up := ev.duplicate()
	up.pressed = false
	root.push_input(up, true)


func key(k: int) -> void:
	var ev := InputEventKey.new()
	ev.keycode = k
	ev.pressed = true
	root.push_input(ev, true)
	var up := ev.duplicate()
	up.pressed = false
	root.push_input(up, true)


func tile_center(c: int, r: int) -> Vector2:
	return game.renderer.tile_rect(c, r).get_center() - game.cam.offset


## Keep the spine laid just ahead of the goo (the "perfect player").
func lay_spine_ahead(rows_ahead := 6) -> void:
	var r0: int = game.flow.row
	for r in range(maxi(1, r0 - 1), r0 + rows_ahead):
		if not game.gen.spine_needs.has(r):
			continue
		var need: Dictionary = game.gen.spine_needs[r]
		for c in need:
			var t: Tile = game.grid.get_tile(c, r)
			if t != null and t.is_free():
				game.debug_set_piece(c, r, P.piece_for(need[c][0], need[c][1]))


func _run() -> void:
	await frames(3)
	var S = game.State
	# The classic (piece queue) mode is tested first; unlock mode further down.
	game.mode = "classic"
	game.go_to_title()
	await frames(1)
	check(game.state == S.TITLE, "starts on the title screen")
	check(game.ui.title_screen.visible, "title overlay visible")

	# --- the menu: one NEW GAME button; clicking elsewhere does nothing ---
	check(game.ui.title_screen.visible and game.ui.new_game_button.is_visible_in_tree(), "the menu shows a NEW GAME button")
	click(Vector2(game.view_size.x * 0.5, game.view_size.y * 0.92))
	await frames(1)
	check(game.state == S.TITLE, "clicking beside the button does not start a game")
	click(game.ui.new_game_button.get_global_rect().get_center())
	await frames(2)
	check(game.state == S.COUNTDOWN, "NEW GAME starts the countdown")
	check(not game.ui.title_screen.visible, "title hidden")
	check(game.countdown > 9.0, "10 second countdown")

	# --- place a piece by clicking a tile ---
	var next: int = game.queue[0]
	var second: int = game.queue[1]
	click(tile_center(3, 1))
	await frames(1)
	var t31: Tile = game.grid.get_tile(3, 1)
	check(t31.get_item() == next, "click places the next queued piece")
	check(game.queue[0] == second and game.queue.size() == Tuning.QUEUE_SIZE, "queue advances and refills")

	# --- replacing costs a lock and points ---
	game.score = 500
	click(tile_center(3, 1))
	await frames(1)
	check(game.score == 500 - Tuning.REPLACE_PENALTY, "replace costs %d points" % Tuning.REPLACE_PENALTY)
	check(game.lock_timer > 0.9, "replace locks the queue")
	var before: int = game.grid.get_tile(4, 1).piece
	click(tile_center(4, 1))
	await frames(1)
	check(game.grid.get_tile(4, 1).piece == before, "placing is blocked while locked")
	await frames(65)
	check(game.lock_timer == 0.0, "lock wears off after 1s")
	click(tile_center(4, 1))
	await frames(1)
	check(game.grid.get_tile(4, 1).piece >= 0, "placing works again after the lock")

	# --- off-screen tiles can't be used ---
	var top_row := int(game.cam.y + game.cam.visible_rows) + 2
	check(game.try_place(2, top_row) == "no", "tiles above the screen are not placeable")

	# --- wildcard, pause, mute ---
	game.wildcards = 1
	await frames(1)
	check(game.ui.picker.visible, "wildcard picker appears")
	key(KEY_7)
	await frames(1)
	check(game.queue[0] == P.CROSS and game.wildcards == 0, "wildcard sets the next piece")
	check(not game.ui.picker.visible or game.wildcards == 0, "picker closes")
	key(KEY_P)
	await frames(1)
	check(game.paused and game.ui.pause_screen.visible, "P pauses")
	var cd: float = game.countdown
	await frames(30)
	check(game.countdown == cd, "countdown frozen while paused")
	key(KEY_ESCAPE)
	await frames(1)
	check(not game.paused, "Esc resumes")
	key(KEY_M)
	await frames(1)
	check(game.sfx.muted, "M mutes")
	key(KEY_M)
	await frames(1)
	check(not game.sfx.muted, "M unmutes")

	# --- keyboard placement ---
	key(KEY_LEFT)
	key(KEY_SPACE)
	await frames(1)
	check(game.kb_active, "arrow keys show the keyboard cursor")

	# --- countdown runs out, goo starts ---
	game.go_to_title()
	await frames(1)
	key(KEY_ENTER)
	await frames(1)
	check(game.state == S.COUNTDOWN, "Enter starts from the title")
	await frames(int(Tuning.COUNTDOWN_TIME * 60) + 5)
	check(game.state == S.RUNNING and game.flow.active, "goo starts after the countdown")

	# --- the cross loop in the safe rows: both passes score ---
	game.start_run()
	await frames(1)
	for spec in [[3, 1, P.V], [3, 2, P.CROSS], [3, 3, P.SE], [4, 3, P.SW], [4, 2, P.NW], [2, 2, P.NE], [2, 3, P.V], [2, 4, P.V]]:
		game.debug_set_piece(spec[0], spec[1], spec[2])
	var above: Tile = game.grid.get_tile(2, 5)  # Make sure the loop ends on an empty tile.
	above.kind = Tile.EMPTY
	above.clear_pipe()
	above.powerup = Tile.PU_NONE
	key(KEY_F)
	await frames(1)
	check(game.state == S.RUNNING and game.fast_forward, "F during countdown starts the flow in fast-forward")
	var waited := 0
	while game.state == S.RUNNING and waited < 2000:
		await frames(1)
		waited += 1
	var cross: Tile = game.grid.get_tile(3, 2)
	check(cross.fill[0] == 1.0 and cross.fill[1] == 1.0, "cross filled both ways in game")
	check(game.crosses == 1, "cross double-pass counted once")
	var want := int((9 * Tuning.SCORE_SEGMENT + Tuning.SCORE_CROSS_DOUBLE) * Tuning.FAST_FORWARD_SCORE_MULT)
	check(game.score == want, "loop score %d (got %d)" % [want, game.score])
	check(game.last_reason == "empty", "spills on the empty tile (got %s)" % game.last_reason)
	await frames(100)
	check(game.state == S.GAMEOVER and game.ui.over_screen.visible, "game over screen shows")
	check(not game.fast_forward, "fast-forward ends at game over")
	key(KEY_R)
	await frames(1)
	check(game.state == S.COUNTDOWN, "R plays again")

	# --- a long perfect run: zones, speed-up, memory ---
	game.start_run()
	await frames(1)
	key(KEY_F)
	var peak_rows := 0
	var zones_seen := {}
	var guard := 0
	var target := 165
	while game.state == S.RUNNING and game.height < target and guard < 60000:
		lay_spine_ahead()
		await frames(1)
		guard += 1
		peak_rows = maxi(peak_rows, game.grid.row_count())
		zones_seen[game.zone_index] = true
	check(game.height >= target, "perfect play climbs to row %d (reached %d, %s)" % [target, game.height, game.last_reason])
	check(zones_seen.size() >= 4, "passed through 4 zones (%d)" % zones_seen.size())
	check(game.multiplier() >= 1.0 + Tuning.MULT_STEP * 6, "multiplier grows with height (x%.1f)" % game.multiplier())
	check(game.height_speed() > 2.5, "flow speeds up with height (%.2fx)" % game.height_speed())
	check(peak_rows <= Tuning.KEEP_ROWS_BELOW + 40, "rows in memory stay bounded (peak %d)" % peak_rows)
	check(game.grid.floor_row > 100, "old rows discarded (floor at %d)" % game.grid.floor_row)
	print("long run: height %d, score %d, crosses %d, wildcards %d" % [game.height, game.score, game.crosses, game.wildcards])

	# Stop laying pipe: the run must end on its own.
	guard = 0
	while game.state == S.RUNNING and guard < 3000:
		await frames(1)
		guard += 1
	check(game.state == S.SPILL or game.state == S.GAMEOVER, "run ends once pipes run out")
	await frames(120)
	check(game.state == S.GAMEOVER, "game over after the spill")
	check(game.best >= game.score, "best score kept")
	check(SaveData.load_best() == game.best, "best score saved")

	# --- unlock mode (BioShock-style) ---
	game.mode = "unlock"
	game.start_run()
	await frames(1)
	check(game.state == S.COUNTDOWN, "unlock mode starts")
	var hidden_ok := true
	for r in range(1, 5):
		for c in Tuning.COLS:
			if not game.grid.get_tile(c, r).hidden:
				hidden_ok = false
	check(hidden_ok, "unlock mode: tiles start locked")
	click(tile_center(3, 1))
	await frames(1)
	check(not game.grid.get_tile(3, 1).hidden and game.flips == 1, "clicking a locked tile unlocks it")
	for r in range(1, 4):
		for c in Tuning.COLS:
			if game.grid.get_tile(c, r).hidden:
				click(tile_center(c, r))
	await frames(1)
	var src := Vector2i(-1, -1)
	var dst := Vector2i(-1, -1)
	for r in range(1, 4):
		for c in Tuning.COLS:
			var t: Tile = game.grid.get_tile(c, r)
			if src.x < 0 and t.is_loose():
				src = Vector2i(c, r)
			elif dst.x < 0 and t.is_slot():
				dst = Vector2i(c, r)
	check(src.x >= 0 and dst.x >= 0, "unlocked rows hold pipes and open spots")
	if src.x >= 0 and dst.x >= 0:
		var piece: int = game.grid.get_tile(src.x, src.y).get_item()
		click(tile_center(src.x, src.y))
		await frames(1)
		check(game.held_piece == piece and game.held_from == src, "clicking a pipe picks it up")
		click(tile_center(src.x, src.y))
		await frames(1)
		check(game.held_piece == -1, "clicking it again puts it back")
		click(tile_center(src.x, src.y))
		click(tile_center(dst.x, dst.y))
		await frames(1)
		check(game.grid.get_tile(dst.x, dst.y).get_item() == piece and game.grid.get_tile(src.x, src.y).piece == -1 and game.held_piece == -1,
				"clicking an open spot moves the pipe there")
	# A narrow pipe stays narrow when it is moved.
	var nsrc: Tile = game.grid.get_tile(1, 1)
	var ndst: Tile = game.grid.get_tile(5, 1)
	for t in [nsrc, ndst]:
		t.hidden = false
		t.kind = Tile.EMPTY
		t.fixed = false
		t.special = Tile.SP_NONE
	nsrc.set_item(P.item(P.V, true))
	ndst.set_item(-1)
	game.grid.touch(1)
	click(tile_center(1, 1))
	click(tile_center(5, 1))
	await frames(1)
	check(ndst.piece == P.V and ndst.narrow and not nsrc.narrow and nsrc.piece == -1, "a narrow pipe stays narrow when moved")
	# An alarm trap.
	var trap: Tile = null
	for c in Tuning.COLS:
		var t: Tile = game.grid.get_tile(c, 5)
		if t.hidden and t.kind == Tile.EMPTY:
			trap = t
			t.alarm = true
			t.piece = -1
			click(tile_center(c, 5))
			break
	await frames(1)
	check(trap != null and game.alarms == 1 and game.surge_timer > 0.0, "unlocking an alarm trap starts a surge")
	check(game.effective_speed() > game.height_speed(), "the surge speeds the goo up")
	# Goo meets a locked tile.
	game.start_run()
	await frames(1)
	game.grid.get_tile(3, 1).hidden = true
	key(KEY_F)
	guard = 0
	while game.state == S.RUNNING and guard < 2000:
		await frames(1)
		guard += 1
	check(game.last_reason == "locked", "goo reaching a locked tile spills (got %s)" % game.last_reason)
	# A long unlock-mode run, played by the autoplay bot through the same clicks.
	game.start_run()
	game.debug_autoplay = true
	guard = 0
	while game.height < 120 and guard < 40000:
		await frames(1)
		guard += 1
		if game.state == S.GAMEOVER:
			break
	game.debug_autoplay = false
	check(game.height >= 120, "unlock mode: autoplay climbs to row 120 (reached %d, %s)" % [game.height, game.last_reason])
	print("unlock run: height %d, score %d, flips %d, alarms %d" % [game.height, game.score, game.flips, game.alarms])

	# --- frame cost ---
	var total := 0.0
	var worst := 0.0
	for t in proc_times:
		total += t
		worst = maxf(worst, t)
	print("process time per frame: avg %.2f ms, worst %.2f ms over %d frames" % [total / proc_times.size() * 1000.0, worst * 1000.0, proc_times.size()])
	print("\n%d checks, %d failures" % [checks, failures])
	quit(1 if failures > 0 else 0)
