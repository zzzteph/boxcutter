## Headless logic tests. Run from the project folder:
##   godot --headless --script res://tests/run_tests.gd
extends SceneTree

var failures := 0
var checks := 0
const P := preload("res://scripts/pieces.gd")


func _initialize() -> void:
	test_exit_table()
	test_path_geometry()
	test_flow_every_piece_every_entry()
	test_cross_both_ways()
	test_block_reasons()
	test_reservoir_is_slow()
	test_generator_solvable()
	test_memory_discard()
	print("\n%d checks, %d failures" % [checks, failures])
	quit(1 if failures > 0 else 0)


func check(cond: bool, msg: String) -> void:
	checks += 1
	if not cond:
		failures += 1
		push_error("FAIL: " + msg)
		print("FAIL: ", msg)


# --- helpers -------------------------------------------------------------------

func empty_grid(rows: int) -> Grid:
	var g := Grid.new()
	for r in rows:
		var row := []
		for c in Tuning.COLS:
			row.append(Tile.new())
		g.add_row(r, row)
	return g


func put(g: Grid, c: int, r: int, piece: int) -> Tile:
	var t := g.get_tile(c, r)
	t.piece = piece
	return t


func run_until_block(g: Grid, f: Flow, max_steps := 400) -> Array:
	var all := []
	for i in max_steps:
		var ev := f.advance(g, 0.37, Color.GREEN)
		all.append_array(ev)
		if not f.active:
			break
	return all


func events_of(evs: Array, type: String) -> Array:
	return evs.filter(func(e): return e["type"] == type)


# --- tests ---------------------------------------------------------------------

func test_exit_table() -> void:
	var expected := {
		P.H: {P.E: P.W, P.W: P.E, P.N: -1, P.S: -1},
		P.V: {P.N: P.S, P.S: P.N, P.E: -1, P.W: -1},
		P.SE: {P.S: P.E, P.E: P.S, P.N: -1, P.W: -1},
		P.SW: {P.S: P.W, P.W: P.S, P.N: -1, P.E: -1},
		P.NE: {P.N: P.E, P.E: P.N, P.S: -1, P.W: -1},
		P.NW: {P.N: P.W, P.W: P.N, P.S: -1, P.E: -1},
		P.CROSS: {P.N: P.S, P.S: P.N, P.E: P.W, P.W: P.E},
	}
	for piece in expected:
		for entry in expected[piece]:
			var got := P.exit_dir(piece, entry)
			check(got == expected[piece][entry], "exit_dir(%s, %d) = %d, want %d" % [P.NAMES[piece], entry, got, expected[piece][entry]])
	check(P.channel_for(P.CROSS, P.N) == 1 and P.channel_for(P.CROSS, P.S) == 1, "cross vertical channel")
	check(P.channel_for(P.CROSS, P.E) == 0 and P.channel_for(P.CROSS, P.W) == 0, "cross horizontal channel")
	for a in 4:
		for b in 4:
			if a != b:
				var p := P.piece_for(a, b)
				check(P.has_opening(p, a) and P.has_opening(p, b), "piece_for(%d,%d)" % [a, b])


func test_path_geometry() -> void:
	for piece in P.COUNT:
		for entry in 4:
			var ex := P.exit_dir(piece, entry)
			if ex < 0:
				continue
			var p0 := P.path_point(entry, ex, 0.0)
			var p1 := P.path_point(entry, ex, 1.0)
			check(p0.distance_to(P.SIDE_MID[entry]) < 1e-4, "%s from %d starts at entry side" % [P.NAMES[piece], entry])
			check(p1.distance_to(P.SIDE_MID[ex]) < 1e-4, "%s from %d ends at exit side" % [P.NAMES[piece], entry])
			var prev := p0
			var prev_dist := p0.distance_to(P.SIDE_MID[ex])
			var ok := true
			for i in range(1, 41):
				var q := P.path_point(entry, ex, i / 40.0)
				if absf(q.x) > 0.5001 or absf(q.y) > 0.5001:
					ok = false
				if q.distance_to(prev) > 0.05:
					ok = false
				var dist := q.distance_to(P.SIDE_MID[ex])
				if dist > prev_dist + 1e-4:
					ok = false
				prev = q
				prev_dist = dist
			check(ok, "%s from %d: path stays inside, is continuous and heads to the exit" % [P.NAMES[piece], entry])
			if ex != P.opposite(entry):
				var corner: Vector2 = P.SIDE_MID[entry] + P.SIDE_MID[ex]
				var mid := P.path_point(entry, ex, 0.5)
				check(absf(mid.distance_to(corner) - 0.5) < 1e-4, "%s from %d follows the curve" % [P.NAMES[piece], entry])


## Every piece, entered from every valid side, must hand the goo to the right neighbour.
func test_flow_every_piece_every_entry() -> void:
	for piece in P.COUNT:
		for entry in 4:
			var ex := P.exit_dir(piece, entry)
			if ex < 0:
				continue
			var g := empty_grid(6)
			var tc := 3
			var tr := 2
			put(g, tc, tr, piece)
			# Feeder on the entry side, flowing toward the test tile.
			var fv: Vector2i = P.DIR_VEC[entry]
			var feeder := put(g, tc + fv.x, tr + fv.y, P.CROSS)
			# Receiver on the exit side.
			var xv: Vector2i = P.DIR_VEC[ex]
			put(g, tc + xv.x, tr + xv.y, P.CROSS)
			var f := Flow.new()
			check(f.begin(g, tc + fv.x, tr + fv.y, entry, Color.GREEN), "feeder begins")
			var evs := []
			for i in 40:
				evs.append_array(f.advance(g, 0.25, Color.GREEN))
				if events_of(evs, "enter").size() >= 2 or not f.active:
					break
			var enters := events_of(evs, "enter")
			var name := "%s entered from %d" % [P.NAMES[piece], entry]
			check(enters.size() >= 2, name + ": goo passes through")
			if enters.size() >= 2:
				check(enters[0]["col"] == tc and enters[0]["row"] == tr and enters[0]["entry"] == entry, name + ": enters test tile")
				check(enters[1]["col"] == tc + xv.x and enters[1]["row"] == tr + xv.y, name + ": leaves to the exit neighbour")
				check(enters[1]["entry"] == P.opposite(ex), name + ": arrives through the facing side")
				var t := g.get_tile(tc, tr)
				var ch := P.channel_for(piece, entry)
				check(t.fill[ch] == 1.0 and t.fill_entry[ch] == entry, name + ": tile is full")
			check(feeder.has_goo(), name + ": feeder has goo")


## A loop that runs through a cross vertically, then horizontally.
func test_cross_both_ways() -> void:
	var g := empty_grid(7)
	var src := g.get_tile(3, 0)
	src.kind = Tile.SOURCE
	src.piece = P.V
	put(g, 3, 1, P.V)
	var cross := put(g, 3, 2, P.CROSS)
	put(g, 3, 3, P.SE)   # enter S -> exit E
	put(g, 4, 3, P.SW)   # enter W -> exit S
	put(g, 4, 2, P.NW)   # enter N -> exit W
	put(g, 2, 2, P.NE)   # enter E -> exit N
	put(g, 2, 3, P.V)
	var f := Flow.new()
	check(f.begin(g, 3, 0, P.S, Color.GREEN), "source begins")
	var evs := run_until_block(g, f)
	var enters := events_of(evs, "enter")
	var visits := []
	for e in enters:
		visits.append(Vector2i(e["col"], e["row"]))
	var want := [Vector2i(3, 1), Vector2i(3, 2), Vector2i(3, 3), Vector2i(4, 3), Vector2i(4, 2), Vector2i(3, 2), Vector2i(2, 2), Vector2i(2, 3)]
	check(visits == want, "loop order %s" % [visits])
	check(cross.fill[0] == 1.0 and cross.fill[1] == 1.0, "cross filled both ways")
	check(cross.fill_entry[1] == P.S and cross.fill_entry[0] == P.E, "cross entries recorded")
	var blocked := events_of(evs, "blocked")
	check(blocked.size() == 1 and blocked[0]["reason"] == "empty", "loop ends at the empty tile above")
	check(f.segments == 9, "9 segments filled (got %d)" % f.segments)

	# A third pass through the same cross is clogged.
	var g2 := empty_grid(5)
	var c2 := put(g2, 3, 2, P.CROSS)
	c2.fill_entry = [P.E, P.S]
	c2.fill = [1.0, 1.0]
	put(g2, 3, 1, P.V)
	var f2 := Flow.new()
	f2.begin(g2, 3, 1, P.S, Color.GREEN)
	var b2 := events_of(run_until_block(g2, f2), "blocked")
	check(b2.size() == 1 and b2[0]["reason"] == "clogged", "full cross is clogged")


func expect_block(g: Grid, c: int, r: int, entry: int, reason: String, label: String) -> void:
	var f := Flow.new()
	check(f.begin(g, c, r, entry, Color.GREEN), label + ": begins")
	var b := events_of(run_until_block(g, f), "blocked")
	check(b.size() == 1 and b[0]["reason"] == reason, "%s: blocked by %s (got %s)" % [label, reason, b])


func test_block_reasons() -> void:
	var g := empty_grid(5)
	put(g, 0, 2, P.H)
	expect_block(g, 0, 2, P.E, "wall", "left wall")
	g = empty_grid(5)
	put(g, 6, 2, P.H)
	expect_block(g, 6, 2, P.W, "wall", "right wall")
	g = empty_grid(5)
	put(g, 3, 1, P.V)
	g.get_tile(3, 2).kind = Tile.ROCK
	expect_block(g, 3, 1, P.S, "rock", "rock")
	g = empty_grid(5)
	put(g, 3, 1, P.V)
	expect_block(g, 3, 1, P.S, "empty", "empty tile")
	g = empty_grid(5)
	put(g, 3, 1, P.V)
	put(g, 3, 2, P.H)
	expect_block(g, 3, 1, P.S, "leak", "open pipe end")
	g = empty_grid(5)
	put(g, 3, 1, P.V)
	var ow := put(g, 3, 2, P.V)
	ow.fixed = true
	ow.special = Tile.SP_ONEWAY
	ow.oneway_entry = P.N
	expect_block(g, 3, 1, P.S, "oneway", "one-way against the arrow")
	ow.oneway_entry = P.S
	expect_block(g, 3, 1, P.S, "empty", "one-way with the arrow passes")
	g = empty_grid(5)
	put(g, 3, 1, P.V)
	var cl := put(g, 3, 2, P.V)
	cl.fill_entry[0] = P.N
	expect_block(g, 3, 1, P.S, "clogged", "already filled pipe")
	g = empty_grid(5)
	g.discard_below(2)
	put(g, 3, 2, P.V)
	expect_block(g, 3, 2, P.N, "wall", "bedrock floor")


func test_reservoir_is_slow() -> void:
	var g := empty_grid(5)
	var t := put(g, 3, 2, P.V)
	t.special = Tile.SP_RESERVOIR
	var f := Flow.new()
	f.begin(g, 3, 2, P.S, Color.GREEN)
	f.advance(g, 1.0, Color.GREEN)
	check(absf(f.progress - 1.0 / Tuning.RESERVOIR_FILL_FACTOR) < 1e-4, "reservoir fills %sx slower" % Tuning.RESERVOIR_FILL_FACTOR)


func test_generator_solvable() -> void:
	var rows := 420
	var seeds := 250
	var bad_spine := 0
	var bad_rows := 0
	var bad_bfs := 0
	var bad_run := 0
	var seen_oneway := 0
	var seen_res := 0
	var seen_bonus := 0
	var seen_pu := 0
	for s in seeds:
		var g := Grid.new()
		var gen := LevelGenerator.new()
		gen.reset(1000 + s * 7919)
		gen.generate_until(g, rows)
		# Spine continuity and compatibility.
		var prev_exit := Tuning.SOURCE_COL
		for r in range(1, rows + 1):
			var sp: Vector2i = gen.spine[r]
			if sp.x != prev_exit:
				bad_spine += 1
			prev_exit = sp.y
			var need: Dictionary = gen.spine_needs[r]
			for c in need:
				var t := g.get_tile(c, r)
				var ok := t.is_free()
				if t.fixed and t.kind == Tile.EMPTY:
					ok = t.piece == P.piece_for(need[c][0], need[c][1])
					if t.special == Tile.SP_ONEWAY:
						ok = ok and t.oneway_entry == need[c][0]
				if not ok:
					bad_spine += 1
			var open := 0
			for c in Tuning.COLS:
				var t := g.get_tile(c, r)
				if t.kind != Tile.ROCK:
					open += 1
				if t.special == Tile.SP_ONEWAY:
					seen_oneway += 1
				if t.special == Tile.SP_RESERVOIR:
					seen_res += 1
				if t.bonus > 0:
					seen_bonus += 1
				if t.powerup != Tile.PU_NONE:
					seen_pu += 1
			if open < Tuning.COLS - Tuning.MAX_ROCKS_PER_ROW:
				bad_rows += 1
		if not bfs_reaches_top(g, rows):
			bad_bfs += 1
		# Lay the needed pieces along the spine and let the goo run the whole way.
		for r in range(1, rows + 1):
			var need: Dictionary = gen.spine_needs[r]
			for c in need:
				var t := g.get_tile(c, r)
				if t.is_free():
					t.piece = P.piece_for(need[c][0], need[c][1])
		var f := Flow.new()
		f.begin(g, Tuning.SOURCE_COL, 0, P.S, Color.GREEN)
		var top := 0
		for i in 20000:
			var ev := f.advance(g, 0.9, Color.GREEN)
			top = maxi(top, f.row)
			if not f.active:
				break
		if top < rows:
			bad_run += 1
	check(bad_spine == 0, "spine is continuous and always passable (%d bad cells)" % bad_spine)
	check(bad_rows == 0, "no row is sealed by rocks (%d bad rows)" % bad_rows)
	check(bad_bfs == 0, "BFS finds a way to the top on every seed (%d failed)" % bad_bfs)
	check(bad_run == 0, "goo laid along the spine reaches row %d on every seed (%d failed)" % [rows, bad_run])
	check(seen_oneway > 0 and seen_res > 0 and seen_bonus > 0 and seen_pu > 0, "all obstacle kinds appear")
	print("generator: %d seeds x %d rows, one-way %d, reservoirs %d, bonus %d, power-ups %d" % [seeds, rows, seen_oneway, seen_res, seen_bonus, seen_pu])


## Can goo get from the source to `top_row` if the player fills free tiles freely?
func bfs_reaches_top(g: Grid, top_row: int) -> bool:
	var start := Vector3i(Tuning.SOURCE_COL, 1, P.S)
	var seen := {start: true}
	var q := [start]
	while not q.is_empty():
		var s: Vector3i = q.pop_front()
		if s.y >= top_row:
			return true
		var t := g.get_tile(s.x, s.y)
		if t == null or t.kind != Tile.EMPTY:
			continue
		var exits := []
		if t.piece < 0:
			for d in 4:
				if d != s.z:
					exits.append(d)
		else:
			if Flow.check_enter(t, s.z) != "":
				continue
			exits.append(P.exit_dir(t.piece, s.z))
		for d in exits:
			var v: Vector2i = P.DIR_VEC[d]
			var ns := Vector3i(s.x + v.x, s.y + v.y, P.opposite(d))
			if not seen.has(ns):
				seen[ns] = true
				q.append(ns)
	return false


func test_memory_discard() -> void:
	var g := Grid.new()
	var gen := LevelGenerator.new()
	gen.reset(42)
	var peak := 0
	for h in range(0, 2000, 3):
		gen.generate_until(g, h + 30)
		var floor_r := maxi(0, h - Tuning.KEEP_ROWS_BELOW)
		g.discard_below(floor_r)
		gen.forget_below(floor_r)
		peak = maxi(peak, g.row_count())
	check(peak <= Tuning.KEEP_ROWS_BELOW + 40, "rows in memory stay bounded (peak %d)" % peak)
	check(gen.spine.size() <= Tuning.KEEP_ROWS_BELOW + 40, "spine memory bounded")
	check(g.get_tile(3, 10) == null, "discarded rows read as bedrock")
