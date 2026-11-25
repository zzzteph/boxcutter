## ============================================================================
##  GRID - a 7-wide, endlessly tall board stored as a sparse map of rows.
## ============================================================================
## Rows are generated on demand above and discarded below `floor_row`; anything
## under the floor is solid bedrock (treated as a wall).
class_name Grid
extends RefCounted

var cols := Tuning.COLS
var rows := {}          ## int row -> Array[Tile]
var floor_row := 0      ## Lowest row still in memory.
var top_row := -1       ## Highest generated row.
var versions := {}      ## int row -> change counter (lets the renderer cache rows).


func clear() -> void:
	rows.clear()
	versions.clear()
	floor_row = 0
	top_row = -1


## Mark a row as changed so its cached drawing is refreshed.
func touch(r: int) -> void:
	versions[r] = int(versions.get(r, 0)) + 1


func version(r: int) -> int:
	return int(versions.get(r, 0))


func add_row(r: int, tiles: Array) -> void:
	rows[r] = tiles
	top_row = maxi(top_row, r)


func get_tile(c: int, r: int) -> Tile:
	if c < 0 or c >= cols or r < floor_row:
		return null
	var row = rows.get(r)
	if row == null:
		return null
	return row[c]


func in_bounds(c: int, r: int) -> bool:
	return c >= 0 and c < cols and r >= floor_row and r <= top_row


## Free every row below `r`. Those rows become bedrock.
func discard_below(r: int) -> void:
	if r <= floor_row:
		return
	for k in range(floor_row, r):
		rows.erase(k)
		versions.erase(k)
	floor_row = r


func row_count() -> int:
	return rows.size()
