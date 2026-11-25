## ============================================================================
##  GENERATOR - procedural rows with a guaranteed path upward.
## ============================================================================
## Every row carries a "spine": the goo enters it from below at column a,
## travels sideways to column b and leaves upward. Spine cells are always either
## free (the player can lay the needed piece) or a fixed pipe whose openings and
## direction match the spine exactly. Obstacles only go on the other cells, and
## at most MAX_ROCKS_PER_ROW rocks per row, so no row is ever sealed and there
## is always a way up.
class_name LevelGenerator
extends RefCounted

const P := preload("res://scripts/pieces.gd")

var rng := RandomNumberGenerator.new()
var next_entry_col := Tuning.SOURCE_COL
var spine := {}            ## row -> Vector2i(entry_col, exit_col)
var spine_needs := {}      ## row -> {col: [entry_side, exit_side]}
var last_powerup_row := 0
var next_row := 0
var unlock_mode := false   ## Fill rows with face-down tiles hiding loose pipes.


func reset(seed_value: int) -> void:
	rng.seed = seed_value
	next_entry_col = Tuning.SOURCE_COL
	spine.clear()
	spine_needs.clear()
	last_powerup_row = 0
	next_row = 0


func generate_until(grid: Grid, target_row: int) -> void:
	while next_row <= target_row:
		grid.add_row(next_row, _make_row(next_row))
		next_row += 1


func forget_below(r: int) -> void:
	for k in spine.keys():
		if k < r:
			spine.erase(k)
			spine_needs.erase(k)


# --- helpers -----------------------------------------------------------------

func _weighted(weights: Array) -> int:
	var total := 0.0
	for w in weights:
		total += float(w)
	var x := rng.randf() * total
	for i in weights.size():
		x -= float(weights[i])
		if x < 0.0:
			return i
	return weights.size() - 1


func _shuffle(arr: Array) -> void:
	for i in range(arr.size() - 1, 0, -1):
		var j := rng.randi_range(0, i)
		var tmp = arr[i]
		arr[i] = arr[j]
		arr[j] = tmp


func _choose_exit_col(a: int, r: int) -> int:
	var shift := _weighted(Tuning.SPINE_SHIFT_WEIGHTS)
	if r < Tuning.SAFE_ROWS:
		shift = mini(shift, 1)
	var sgn := 1 if rng.randf() < 0.5 else -1
	if a <= 1:
		sgn = 1 if rng.randf() < 0.8 else -1
	elif a >= Tuning.COLS - 2:
		sgn = -1 if rng.randf() < 0.8 else 1
	var b := a + sgn * shift
	if b < 0 or b >= Tuning.COLS:
		b = a - sgn * shift
	return clampi(b, 0, Tuning.COLS - 1)


func _rock_shape() -> PackedVector2Array:
	var pts := PackedVector2Array()
	var n := rng.randi_range(7, 9)
	var off := rng.randf() * TAU
	var cx := rng.randf_range(-0.03, 0.03)
	var cy := rng.randf_range(-0.02, 0.04)
	for i in n:
		var ang := off + TAU * float(i) / n + rng.randf_range(-0.2, 0.2)
		var rad := rng.randf_range(0.34, 0.44)
		pts.append(Vector2(cx + cos(ang) * rad, cy + sin(ang) * rad * 0.92))
	return pts


func _make_oneway(t: Tile, entry: int, exit: int) -> void:
	t.piece = P.piece_for(entry, exit)
	t.fixed = true
	t.special = Tile.SP_ONEWAY
	t.oneway_entry = entry


func _make_reservoir(t: Tile, piece: int) -> void:
	t.piece = piece
	t.fixed = true
	t.special = Tile.SP_RESERVOIR


# --- row construction ----------------------------------------------------------

func _make_row(r: int) -> Array:
	var tiles := []
	for c in Tuning.COLS:
		var t := Tile.new()
		t.rnd = rng.randi()
		tiles.append(t)

	if r == 0:
		var s: Tile = tiles[Tuning.SOURCE_COL]
		s.kind = Tile.SOURCE
		s.piece = P.V
		s.fixed = true
		s.spine = true
		spine[0] = Vector2i(Tuning.SOURCE_COL, Tuning.SOURCE_COL)
		spine_needs[0] = {Tuning.SOURCE_COL: [P.S, P.N]}
		next_entry_col = Tuning.SOURCE_COL
		return tiles

	# 1) The guaranteed path through this row.
	var a := next_entry_col
	var b := _choose_exit_col(a, r)
	spine[r] = Vector2i(a, b)
	next_entry_col = b
	var need := {}
	if a == b:
		need[a] = [P.S, P.N]
	else:
		var dir := P.E if b > a else P.W
		var step := 1 if b > a else -1
		need[a] = [P.S, dir]
		var c := a + step
		while c != b:
			need[c] = [P.opposite(dir), dir]
			c += step
		need[b] = [P.opposite(dir), P.N]
	spine_needs[r] = need
	for c in need:
		(tiles[c] as Tile).spine = true

	if r < Tuning.SAFE_ROWS:
		if unlock_mode:
			_fill_unlock(tiles, need, r)
		return tiles

	var zone := Zones.theme_for_row(r)
	var depth := r - Tuning.SAFE_ROWS
	var off_path := []
	for c in Tuning.COLS:
		if not need.has(c):
			off_path.append(c)
	_shuffle(off_path)

	# 2) Rocks, only off the path and capped per row.
	var rock_p := minf(Tuning.ROCK_MAX, Tuning.ROCK_BASE + Tuning.ROCK_PER_ROW * depth) * float(zone["rock_mult"])
	var rocks := 0
	for c in off_path:
		if rocks < Tuning.MAX_ROCKS_PER_ROW and rng.randf() < rock_p:
			var t: Tile = tiles[c]
			t.kind = Tile.ROCK
			t.shape = _rock_shape()
			rocks += 1

	# 3) Fixed pipes on the path, matching it exactly.
	var path_cols := need.keys()
	if r >= Tuning.ONEWAY_START_ROW and rng.randf() < Tuning.ONEWAY_ON_PATH_CHANCE * float(zone["oneway_mult"]):
		var c: int = path_cols[rng.randi_range(0, path_cols.size() - 1)]
		_make_oneway(tiles[c], need[c][0], need[c][1])
	elif r >= Tuning.RESERVOIR_START_ROW and rng.randf() < Tuning.RESERVOIR_ON_PATH_CHANCE * float(zone["reservoir_mult"]):
		var straights := []
		for c in path_cols:
			if need[c][1] == P.opposite(need[c][0]):
				straights.append(c)
		if not straights.is_empty():
			var c: int = straights[rng.randi_range(0, straights.size() - 1)]
			_make_reservoir(tiles[c], P.piece_for(need[c][0], need[c][1]))

	# 4) Fixed pipes off the path (opportunities and traps).
	for c in off_path:
		var t: Tile = tiles[c]
		if t.kind != Tile.EMPTY:
			continue
		if r >= Tuning.ONEWAY_START_ROW and rng.randf() < Tuning.ONEWAY_CHANCE * float(zone["oneway_mult"]):
			var p := rng.randi_range(0, P.CROSS - 1)
			var o: Array = P.OPENINGS[p]
			var entry: int = o[rng.randi_range(0, 1)]
			_make_oneway(t, entry, P.exit_dir(p, entry))
		elif r >= Tuning.RESERVOIR_START_ROW and rng.randf() < Tuning.RESERVOIR_CHANCE * float(zone["reservoir_mult"]):
			_make_reservoir(t, P.V if rng.randf() < 0.6 else P.H)

	# 5) Power-ups, on or right next to the path so they're reachable.
	if r >= Tuning.POWERUP_START_ROW and r - last_powerup_row >= Tuning.POWERUP_MIN_GAP \
			and rng.randf() < Tuning.POWERUP_CHANCE * float(zone["powerup_mult"]):
		var lo := maxi(0, mini(a, b) - 1)
		var hi := mini(Tuning.COLS - 1, maxi(a, b) + 1)
		var cand := []
		for c in range(lo, hi + 1):
			var t: Tile = tiles[c]
			if t.is_free():
				cand.append(c)
		if not cand.is_empty():
			var t: Tile = tiles[cand[rng.randi_range(0, cand.size() - 1)]]
			t.powerup = 1 + _weighted(Tuning.POWERUP_WEIGHTS)
			last_powerup_row = r

	if unlock_mode:
		_fill_unlock(tiles, need, r)
	return tiles


## Unlock mode: every tile is face-down. Each row hides at least the pipes its
## own guaranteed path needs, so the player can always build the path by
## unlocking that row and swapping pipes around. The rest is random pipes,
## empty slots and the odd alarm trap.
func _fill_unlock(tiles: Array, need: Dictionary, r: int) -> void:
	var needed := []
	var spine_free := []
	var others := []
	for c in Tuning.COLS:
		var t: Tile = tiles[c]
		t.hidden = true
		if t.kind != Tile.EMPTY or t.fixed:
			continue
		if need.has(c):
			needed.append(P.piece_for(need[c][0], need[c][1]))
			spine_free.append(c)
		else:
			others.append(c)
	# Some path tiles already hide the right pipe; the rest of the needed pipes
	# land somewhere else in the row.
	var leftover := []
	for i in spine_free.size():
		if rng.randf() < Tuning.UNLOCK_SPINE_PIECE_CHANCE:
			(tiles[spine_free[i]] as Tile).piece = needed[i]
		else:
			leftover.append(needed[i])
	var spots := []
	for c in spine_free + others:
		if (tiles[c] as Tile).piece < 0:
			spots.append(c)
	_shuffle(spots)
	for i in leftover.size():
		(tiles[spots[i]] as Tile).piece = leftover[i]
	for i in range(leftover.size(), spots.size()):
		var t: Tile = tiles[spots[i]]
		if rng.randf() < Tuning.UNLOCK_PIECE_FILL:
			t.piece = _weighted(Tuning.PIECE_WEIGHTS)
			# Some spare pipes are narrow: they work the same but the goo crawls.
			t.narrow = t.piece != P.CROSS and r >= Tuning.NARROW_START_ROW and rng.randf() < Tuning.NARROW_CHANCE
		elif r >= Tuning.ALARM_START_ROW and not t.spine and t.powerup == Tile.PU_NONE \
				and rng.randf() < Tuning.ALARM_CHANCE:
			t.alarm = true
