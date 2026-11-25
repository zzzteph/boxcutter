## One board cell: its terrain, optional pipe, pickups and goo fill state.
class_name Tile
extends RefCounted

# Terrain
const EMPTY := 0
const ROCK := 1
const SOURCE := 2

# Special pre-placed pipes
const SP_NONE := 0
const SP_ONEWAY := 1
const SP_RESERVOIR := 2

# Power-ups
const PU_NONE := 0
const PU_SLOW := 1
const PU_WILD := 2

var kind := EMPTY
var piece := -1                ## Pieces.* or -1.
var narrow := false            ## A narrow pipe: the goo crawls through it.
var fixed := false             ## Pre-placed by the generator; the player can't replace it.
var special := SP_NONE
var oneway_entry := -1         ## For one-way pipes: the only side goo may enter.
var powerup := PU_NONE
var fill := [0.0, 0.0]         ## Fill progress per channel (cross: 0 = horizontal, 1 = vertical).
var fill_entry := [-1, -1]     ## Side the goo entered each channel through (-1 = dry).
var fill_color := [Color.WHITE, Color.WHITE]
var placed_at := -100.0        ## Game time of placement (pop animation).
var rnd := 0                   ## Per-tile random value for visuals.
var spine := false             ## On the generator's guaranteed path (debug/tests).
var hidden := false            ## Unlock mode: still face-down (locked).
var alarm := false             ## Unlock mode: a trap that goes off when unlocked.
var flip_at := -100.0          ## Game time it was unlocked (flip animation).
var shape := PackedVector2Array()  ## Rock outline in tile units.


func is_free() -> bool:
	return kind == EMPTY and piece < 0


## A dry, player-owned pipe that unlock mode lets you pick up and move.
func is_loose() -> bool:
	return kind == EMPTY and piece >= 0 and not fixed and not hidden and not has_goo()


## An open spot a pipe can be dropped on: unlocked, nothing in it, no goo.
func is_slot() -> bool:
	return kind == EMPTY and piece < 0 and not hidden and not has_goo()


func has_goo() -> bool:
	return fill_entry[0] >= 0 or fill_entry[1] >= 0


## The pipe here as an item (piece + narrow flag), or -1.
func get_item() -> int:
	return Pieces.item(piece, narrow) if piece >= 0 else -1


func set_item(it: int) -> void:
	piece = Pieces.item_piece(it) if it >= 0 else -1
	narrow = it >= 0 and Pieces.item_narrow(it)


func clear_pipe() -> void:
	narrow = false
	piece = -1
	fixed = false
	special = SP_NONE
	oneway_entry = -1
