## ============================================================================
##  CAMERA - smooth vertical follow of the goo's leading edge, plus shake.
## ============================================================================
## `y` is the world row coordinate at the bottom edge of the board viewport.
class_name GameCamera
extends RefCounted

var y := -Tuning.CAMERA_FLOOR_MARGIN
var visible_rows := Tuning.MIN_VISIBLE_ROWS
var shake := 0.0
var offset := Vector2.ZERO


func target_for(head_y: float, floor_row: int) -> float:
	return maxf(head_y - visible_rows * Tuning.CAMERA_LEAD_FRACTION, floor_row - Tuning.CAMERA_FLOOR_MARGIN)


func snap(head_y: float, floor_row: int) -> void:
	y = target_for(head_y, floor_row)
	shake = 0.0
	offset = Vector2.ZERO


func update(dt: float, head_y: float, floor_row: int) -> void:
	var target := target_for(head_y, floor_row)
	y = lerpf(y, target, 1.0 - exp(-Tuning.CAMERA_STIFFNESS * dt))
	if shake > 0.0:
		shake = maxf(0.0, shake - dt * 1.4)
		var k := shake * shake * 22.0
		offset = Vector2(randf_range(-1.0, 1.0), randf_range(-1.0, 1.0)) * k
	else:
		offset = Vector2.ZERO


func add_shake(amount: float) -> void:
	shake = minf(1.0, shake + amount)


## Lowest and highest row with any part on screen.
func row_range() -> Vector2i:
	return Vector2i(floori(y) - 1, ceili(y + visible_rows) + 1)
