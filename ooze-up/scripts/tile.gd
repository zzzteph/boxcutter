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
const PU_BOMB := 2
const PU_WILD := 3

var kind := EMPTY
var piece := -1                ## Pieces.* or -1.
var fixed := false             ## Pre-placed by the generator; the player can't replace it.
var special := SP_NONE
var oneway_entry := -1         ## For one-way pipes: the only side goo may enter.
var bonus := 0                 ## Bonus points when goo passes (0 = none).
var powerup := PU_NONE
var fill := [0.0, 0.0]         ## Fill progress per channel (cross: 0 = horizontal, 1 = vertical).
var fill_entry := [-1, -1]     ## Side the goo entered each channel through (-1 = dry).
var fill_color := [Color.WHITE, Color.WHITE]
var placed_at := -100.0        ## Game time of placement (pop animation).
var rnd := 0                   ## Per-tile random value for visuals.
var spine := false             ## On the generator's guaranteed path (debug/tests).
var shape := PackedVector2Array()  ## Rock outline in tile units.


func is_free() -> bool:
	return kind == EMPTY and piece < 0


func has_goo() -> bool:
	return fill_entry[0] >= 0 or fill_entry[1] >= 0


func clear_pipe() -> void:
	piece = -1
	fixed = false
	special = SP_NONE
	oneway_entry = -1
