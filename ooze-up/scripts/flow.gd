## ============================================================================
##  FLOW - moves the goo's leading edge through the pipes.
## ============================================================================
## The leading edge sits in one tile at a time, travelling from its entry side
## to its exit side. When a tile is full the flow steps into the neighbour on
## the exit side, or stops with a reason if that neighbour can't take the goo.
class_name Flow
extends RefCounted

var col := 0
var row := 0
var entry := Pieces.S
var exit := Pieces.N
var channel := 0
var progress := 0.0      ## 0..1 within the current tile.
var active := false
var segments := 0        ## Tiles (channels) completely filled.
var block_reason := ""


func reset() -> void:
	active = false
	segments = 0
	block_reason = ""
	progress = 0.0


## Start the goo in tile (c, r) as if it came in through `entry_side`.
func begin(grid: Grid, c: int, r: int, entry_side: int, goo: Color) -> bool:
	var t := grid.get_tile(c, r)
	if t == null or t.piece < 0:
		return false
	var ex := Pieces.exit_dir(t.piece, entry_side)
	if ex < 0:
		return false
	col = c
	row = r
	entry = entry_side
	exit = ex
	channel = Pieces.channel_for(t.piece, entry_side)
	progress = 0.0
	active = true
	block_reason = ""
	t.fill_entry[channel] = entry
	t.fill_color[channel] = goo
	t.fill[channel] = 0.0
	return true


## Why the goo can't enter tile `t` through `side` ("" = it can).
static func check_enter(t: Tile, side: int) -> String:
	if t == null:
		return "wall"
	if t.kind == Tile.ROCK:
		return "rock"
	if t.kind == Tile.SOURCE:
		return "leak"
	if t.piece < 0:
		return "empty"
	if Pieces.exit_dir(t.piece, side) < 0:
		return "leak"
	if t.special == Tile.SP_ONEWAY and side != t.oneway_entry:
		return "oneway"
	if t.fill_entry[Pieces.channel_for(t.piece, side)] >= 0:
		return "clogged"
	return ""


static func time_factor(t: Tile) -> float:
	if t != null and t.special == Tile.SP_RESERVOIR:
		return Tuning.RESERVOIR_FILL_FACTOR
	return 1.0


## Advance by `amount` tiles' worth of flow (rate * dt). Returns events:
##   {type="filled", col, row, tile, channel}   a tile/channel became full
##   {type="enter",  col, row, tile, entry}     goo entered a new tile
##   {type="blocked", reason, col, row, exit, next_col, next_row}
func advance(grid: Grid, amount: float, goo: Color) -> Array:
	var events := []
	if not active:
		return events
	var t := grid.get_tile(col, row)
	if t == null:
		active = false
		block_reason = "wall"
		events.append({"type": "blocked", "reason": "wall", "col": col, "row": row, "exit": exit,
				"next_col": col, "next_row": row})
		return events
	var remaining := amount
	var guard := 0
	while remaining > 0.0 and active and guard < 32:
		guard += 1
		var factor := time_factor(t)
		var need := (1.0 - progress) * factor
		if remaining < need:
			progress += remaining / factor
			t.fill[channel] = progress
			break
		remaining -= need
		progress = 1.0
		t.fill[channel] = 1.0
		segments += 1
		events.append({"type": "filled", "col": col, "row": row, "tile": t, "channel": channel})

		var v: Vector2i = Pieces.DIR_VEC[exit]
		var nc := col + v.x
		var nr := row + v.y
		var ne := Pieces.opposite(exit)
		var nt := grid.get_tile(nc, nr)
		var reason := check_enter(nt, ne)
		if reason != "":
			active = false
			block_reason = reason
			events.append({"type": "blocked", "reason": reason, "col": col, "row": row, "exit": exit,
					"next_col": nc, "next_row": nr})
			break
		col = nc
		row = nr
		entry = ne
		exit = Pieces.exit_dir(nt.piece, ne)
		channel = Pieces.channel_for(nt.piece, ne)
		progress = 0.0
		nt.fill_entry[channel] = ne
		nt.fill_color[channel] = goo
		nt.fill[channel] = 0.0
		t = nt
		events.append({"type": "enter", "col": col, "row": row, "tile": nt, "entry": ne})
	return events


## Leading edge in world tile units (x right, y up).
func head_world() -> Vector2:
	return Pieces.world_point(col, row, entry, exit, progress)
