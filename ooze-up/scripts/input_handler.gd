## ============================================================================
##  INPUT - mouse, touch (emulated as mouse) and keyboard.
## ============================================================================
## UI buttons and overlays eat their own clicks first; whatever reaches
## _unhandled_input is aimed at the board.
class_name InputHandler
extends Node

var game  ## The Game node (main.gd).


func _unhandled_input(event: InputEvent) -> void:
	if event is InputEventMouseMotion:
		game.on_pointer_move(event.position, event.device == InputEvent.DEVICE_ID_EMULATION)
	elif event is InputEventMouseButton:
		if event.pressed and event.button_index == MOUSE_BUTTON_LEFT:
			game.on_pointer_press(event.position, event.device == InputEvent.DEVICE_ID_EMULATION)
			get_viewport().set_input_as_handled()
	elif event is InputEventKey and event.pressed:
		if _on_key(event.keycode, event.echo):
			get_viewport().set_input_as_handled()


func _on_key(key: int, echo: bool) -> bool:
	# Movement keys may repeat; everything else fires once per press.
	match key:
		KEY_LEFT, KEY_A:
			game.move_cursor(-1, 0)
			return true
		KEY_RIGHT, KEY_D:
			game.move_cursor(1, 0)
			return true
		KEY_UP, KEY_W:
			game.move_cursor(0, 1)
			return true
		KEY_DOWN, KEY_S:
			game.move_cursor(0, -1)
			return true
	if echo:
		return false
	match key:
		KEY_F:
			game.activate_fast_forward()
		KEY_P, KEY_ESCAPE:
			game.toggle_pause()
		KEY_M:
			game.toggle_mute()
		KEY_R:
			game.restart_key()
		KEY_SPACE, KEY_ENTER, KEY_KP_ENTER:
			game.on_confirm()
		_:
			if key >= KEY_1 and key <= KEY_7:
				game.choose_wildcard(key - KEY_1)
			else:
				return false
	return true
