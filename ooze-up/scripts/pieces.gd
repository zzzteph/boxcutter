## ============================================================================
##  PIECES - piece types, openings, and the geometry of the goo path.
## ============================================================================
## Directions are tile sides. Rows grow upward, so N means row + 1.
class_name Pieces
extends RefCounted

const N := 0
const E := 1
const S := 2
const W := 3

const NONE := -1
const H := 0      ## ─
const V := 1      ## │
const SE := 2     ## ┌  opens South + East
const SW := 3     ## ┐  opens South + West
const NE := 4     ## └  opens North + East
const NW := 5     ## ┘  opens North + West
const CROSS := 6  ## ┼
const COUNT := 7

const NAMES := ["─", "│", "┌", "┐", "└", "┘", "┼"]
const OPENINGS := [[E, W], [N, S], [S, E], [S, W], [N, E], [N, W], [N, E, S, W]]
## Grid step per direction as (col, row), row up.
const DIR_VEC := [Vector2i(0, 1), Vector2i(1, 0), Vector2i(0, -1), Vector2i(-1, 0)]
## Side midpoints in tile-local screen units (center = 0,0, y down, tile = 1x1).
const SIDE_MID := [Vector2(0, -0.5), Vector2(0.5, 0), Vector2(0, 0.5), Vector2(-0.5, 0)]


static func opposite(d: int) -> int:
	return (d + 2) % 4


static func has_opening(piece: int, side: int) -> bool:
	return piece >= 0 and piece < COUNT and (OPENINGS[piece] as Array).has(side)


## Side the goo leaves through after entering `piece` through side `entry`, or -1.
static func exit_dir(piece: int, entry: int) -> int:
	if piece < 0 or piece >= COUNT or entry < 0 or entry > 3:
		return -1
	if piece == CROSS:
		return opposite(entry)
	var o: Array = OPENINGS[piece]
	if o[0] == entry:
		return o[1]
	if o[1] == entry:
		return o[0]
	return -1


## Crosses have two channels: 0 = horizontal, 1 = vertical. Other pieces use 0.
static func channel_for(piece: int, entry: int) -> int:
	if piece == CROSS and (entry == N or entry == S):
		return 1
	return 0


## The channels (as side pairs) a piece draws, in draw order.
static func channels(piece: int) -> Array:
	if piece == CROSS:
		return [[E, W], [N, S]]
	if piece < 0 or piece >= COUNT:
		return []
	return [OPENINGS[piece]]


## The single non-cross piece that connects sides a and b.
static func piece_for(a: int, b: int) -> int:
	for p in range(CROSS):
		var o: Array = OPENINGS[p]
		if o.has(a) and o.has(b) and a != b:
			return p
	return NONE


static func is_straight(piece: int) -> bool:
	return piece == H or piece == V


## Point on the path from side `entry` to side `exit` at t in [0, 1], in
## tile-local screen units. Straights are lines; corners are quarter circles
## around the tile corner the two sides share.
static func path_point(entry: int, exit: int, t: float) -> Vector2:
	var a: Vector2 = SIDE_MID[entry]
	var b: Vector2 = SIDE_MID[exit]
	if exit == opposite(entry):
		return a.lerp(b, t)
	var c := a + b
	var a0 := (a - c).angle()
	var d := wrapf((b - c).angle() - a0, -PI, PI)
	return c + Vector2.from_angle(a0 + d * t) * 0.5


## World-space (tile units, y up) position of a path point in tile (col, row).
static func world_point(col: int, row: int, entry: int, exit: int, t: float) -> Vector2:
	var p := path_point(entry, exit, t)
	return Vector2(col + 0.5 + p.x, row + 0.5 - p.y)
