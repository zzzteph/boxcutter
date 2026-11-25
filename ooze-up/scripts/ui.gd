## ============================================================================
##  UI - HUD, buttons, banners and the title / pause / game-over screens.
## ============================================================================
class_name GameUI
extends CanvasLayer


## A button that draws its own icon (pause, sound, fast-forward, pipe piece).
class IconButton:
	extends Button
	var kind := ""
	var piece := -1
	var pal: Dictionary = {}
	var lit := false
	var caption := ""

	func _draw() -> void:
		var c := size * 0.5
		var s := minf(size.x, size.y)
		var col := Color.WHITE
		match kind:
			"pause":
				draw_rect(Rect2(c + Vector2(-0.2, -0.22) * s, Vector2(0.13, 0.44) * s), col)
				draw_rect(Rect2(c + Vector2(0.07, -0.22) * s, Vector2(0.13, 0.44) * s), col)
			"sound_on", "sound_off":
				var pts := PackedVector2Array()
				for p in [Vector2(-0.28, -0.09), Vector2(-0.14, -0.09), Vector2(0.0, -0.22), Vector2(0.0, 0.22), Vector2(-0.14, 0.09), Vector2(-0.28, 0.09)]:
					pts.append(c + p * s)
				draw_colored_polygon(pts, col)
				if kind == "sound_on":
					draw_arc(c + Vector2(0.02, 0) * s, 0.12 * s, -0.9, 0.9, 10, col, maxf(2.0, s * 0.05), true)
					draw_arc(c + Vector2(0.02, 0) * s, 0.22 * s, -0.9, 0.9, 12, col, maxf(2.0, s * 0.05), true)
				else:
					draw_line(c + Vector2(0.08, -0.12) * s, c + Vector2(0.3, 0.12) * s, Color("ff5a4a"), maxf(2.0, s * 0.06), true)
					draw_line(c + Vector2(0.08, 0.12) * s, c + Vector2(0.3, -0.12) * s, Color("ff5a4a"), maxf(2.0, s * 0.06), true)
			"ff":
				var fc := Color("ffd23a") if lit else col
				var h := s * 0.2
				var top := c + Vector2(0, -s * 0.1 if caption != "" else 0.0)
				for k in 2:
					var x0 := top.x - h * 1.1 + k * h * 1.1
					draw_colored_polygon(PackedVector2Array([Vector2(x0, top.y - h), Vector2(x0 + h * 1.1, top.y), Vector2(x0, top.y + h)]), fc)
				if caption != "":
					var fs := int(clampf(s * 0.2, 12, 22))
					draw_string(PipeArt.font(), Vector2(0, size.y - fs * 0.6), caption, HORIZONTAL_ALIGNMENT_CENTER, size.x, fs, fc)
			"piece":
				pass  # Drawn by the IconArt child from the sprite atlas.


## A pipe icon from the sprite atlas (premultiplied alpha, hence its own material).
class IconArt:
	extends Control
	var atlas: SpriteAtlas
	var piece := 0
	var zone := 0

	func _draw() -> void:
		if atlas == null or atlas.icon_px <= 0:
			return
		var s := minf(size.x, size.y) * 0.78
		draw_texture_rect_region(atlas.icon_tex(zone), Rect2((size - Vector2(s, s)) * 0.5, Vector2(s, s)), atlas.icon_region(piece))


var game  ## The Game node (main.gd).
var root: Control
var hud: Panel
var stat_values := {}
var btn_pause: IconButton
var btn_mute: IconButton
var btn_ff: IconButton
var countdown_label: Label
var countdown_sub: Label
var banner: Label
var toast: Label
var title_screen: Control
var new_game_button: Button
var pause_screen: Control
var pause_mute: Button
var over_screen: Control
var over_reason: Label
var over_score: Label
var over_height: Label
var over_best: Label
var over_new: Label
var picker: PanelContainer
var picker_buttons: Array = []
var _last_view := Vector2.ZERO
var _last_portrait := false
var _banner_tween: Tween
var _toast_tween: Tween
var _last_count := -1
var _speed_col := Color.WHITE
var _ff_lit := false
var _picker_zone := -1
var _scaled := []          ## [Label, base font size, base outline] scaled to the screen width.
var _key_buttons := []     ## [Button, mouse/keyboard text, touch text]
var _picker_label: Label
var _best_box: Control
var _flash: ColorRect
var _flash_tween: Tween


func _ready() -> void:
	layer = 10
	root = Control.new()
	root.set_anchors_preset(Control.PRESET_FULL_RECT)
	root.mouse_filter = Control.MOUSE_FILTER_IGNORE
	root.theme = _make_theme()
	add_child(root)
	_build_hud()
	_build_center_labels()
	_build_picker()
	_build_title()
	_build_pause()
	_build_over()
	_flash = ColorRect.new()
	_flash.set_anchors_preset(Control.PRESET_FULL_RECT)
	_flash.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_flash.color = Color(1, 0, 0, 0)
	root.add_child(_flash)


# --- theme ------------------------------------------------------------------------------

func _box(bg: Color, border: Color, radius := 14, bw := 3, shadow := 6) -> StyleBoxFlat:
	var sb := StyleBoxFlat.new()
	sb.bg_color = bg
	sb.border_color = border
	sb.set_border_width_all(bw)
	sb.set_corner_radius_all(mini(radius, 3) if Tuning.PS1_MODE else radius)
	sb.shadow_color = Color(0, 0, 0, 0.45)
	sb.shadow_size = shadow
	sb.shadow_offset = Vector2(0, 3)
	if Tuning.PS1_MODE and shadow > 0:
		# Hard, offset drop shadow, like a 32-bit era menu.
		sb.shadow_color = Color(0, 0, 0, 0.7)
		sb.shadow_size = 1
		sb.shadow_offset = Vector2(5, 5)
	sb.content_margin_left = 16
	sb.content_margin_right = 16
	sb.content_margin_top = 8
	sb.content_margin_bottom = 8
	sb.anti_aliasing = PipeArt.aa
	return sb


func _make_theme() -> Theme:
	var th := Theme.new()
	th.default_font = PipeArt.font()
	th.default_font_size = 22
	th.set_color("font_outline_color", "Label", Color(0, 0, 0, 0.9))
	th.set_constant("outline_size", "Label", 8)
	th.set_color("font_color", "Label", Color.WHITE)
	th.set_stylebox("normal", "Button", _box(Color("2b6b3a"), Color("7dff3a")))
	th.set_stylebox("hover", "Button", _box(Color("3a8a4a"), Color("b6ff7a")))
	th.set_stylebox("pressed", "Button", _box(Color("1d4a28"), Color("7dff3a")))
	th.set_stylebox("focus", "Button", StyleBoxEmpty.new())
	th.set_stylebox("disabled", "Button", _box(Color("333333"), Color("555555")))
	th.set_color("font_color", "Button", Color.WHITE)
	th.set_color("font_hover_color", "Button", Color.WHITE)
	th.set_color("font_pressed_color", "Button", Color("d0ffd0"))
	th.set_color("font_outline_color", "Button", Color(0, 0, 0, 0.8))
	th.set_constant("outline_size", "Button", 6)
	th.set_font_size("font_size", "Button", 26)
	th.set_stylebox("panel", "PanelContainer", _box(Color(0.06, 0.08, 0.1, 0.94), Color("7dff3a"), 22, 4, 12))
	th.set_stylebox("panel", "Panel", _box(Color(0.04, 0.05, 0.07, 0.92), Color(1, 1, 1, 0.12), 0, 0, 8))
	return th


func _label(text: String, size: int, col := Color.WHITE, outline := 8) -> Label:
	var l := Label.new()
	l.text = text
	l.add_theme_font_size_override("font_size", size)
	l.add_theme_color_override("font_color", col)
	l.add_theme_constant_override("outline_size", outline)
	l.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	l.vertical_alignment = VERTICAL_ALIGNMENT_CENTER
	l.mouse_filter = Control.MOUSE_FILTER_IGNORE
	return l


## A label whose font size follows the screen width (big screens keep `size`).
func _slabel(text: String, size: int, col := Color.WHITE, outline := 8) -> Label:
	var l := _label(text, size, col, outline)
	_scaled.append([l, size, outline])
	return l


## A button whose caption drops its keyboard hint on touch screens.
func _kbutton(key_text: String, touch_text: String, cb: Callable) -> Button:
	var b := _button(key_text, cb)
	_key_buttons.append([b, key_text, touch_text])
	return b


func _button(text: String, cb: Callable, min_w := 260) -> Button:
	var b := Button.new()
	b.text = text
	b.focus_mode = Control.FOCUS_NONE
	b.custom_minimum_size = Vector2(min_w, 60)
	b.pressed.connect(func():
		game.sfx.play("click")
		cb.call())
	return b


func _icon_button(kind: String, cb: Callable) -> IconButton:
	var b := IconButton.new()
	b.kind = kind
	b.focus_mode = Control.FOCUS_NONE
	b.custom_minimum_size = Vector2(52, 52)
	b.pressed.connect(cb)
	return b


func _overlay() -> Control:
	var o := Control.new()
	o.set_anchors_preset(Control.PRESET_FULL_RECT)
	o.mouse_filter = Control.MOUSE_FILTER_STOP
	var dim := ColorRect.new()
	dim.color = Color(0.02, 0.03, 0.04, 0.62)
	dim.set_anchors_preset(Control.PRESET_FULL_RECT)
	dim.mouse_filter = Control.MOUSE_FILTER_IGNORE
	o.add_child(dim)
	var cc := CenterContainer.new()
	cc.set_anchors_preset(Control.PRESET_FULL_RECT)
	cc.mouse_filter = Control.MOUSE_FILTER_IGNORE
	o.add_child(cc)
	o.visible = false
	root.add_child(o)
	return o


func _center_of(o: Control) -> CenterContainer:
	return o.get_child(1) as CenterContainer


# --- HUD ----------------------------------------------------------------------------------

func _build_hud() -> void:
	hud = Panel.new()
	hud.mouse_filter = Control.MOUSE_FILTER_IGNORE
	root.add_child(hud)
	var hb := HBoxContainer.new()
	hb.name = "Stats"
	hb.add_theme_constant_override("separation", 6)
	hb.mouse_filter = Control.MOUSE_FILTER_IGNORE
	hud.add_child(hb)
	for key in ["SCORE", "BEST", "HEIGHT", "MULT", "SPEED"]:
		var vb := VBoxContainer.new()
		vb.size_flags_horizontal = Control.SIZE_EXPAND_FILL
		vb.add_theme_constant_override("separation", -6)
		vb.mouse_filter = Control.MOUSE_FILTER_IGNORE
		var cap := _label(key, 13, Color(1, 1, 1, 0.55), 0)
		var val := _label("0", 27, Color.WHITE, 6)
		val.clip_text = false
		vb.add_child(cap)
		vb.add_child(val)
		hb.add_child(vb)
		stat_values[key] = val
		stat_values[key + "_cap"] = cap
		if key == "BEST":
			_best_box = vb
	btn_pause = _icon_button("pause", func(): game.toggle_pause())
	btn_mute = _icon_button("sound_on", func(): game.toggle_mute())
	hb.add_child(btn_pause)
	hb.add_child(btn_mute)
	btn_ff = _icon_button("ff", func(): game.activate_fast_forward())
	btn_ff.caption = "FAST x5"
	root.add_child(btn_ff)


func _build_center_labels() -> void:
	countdown_label = _slabel("", 150, Color("ffffff"), 22)
	countdown_label.set_anchors_preset(Control.PRESET_FULL_RECT)
	root.add_child(countdown_label)
	countdown_sub = _slabel("", 30, Color("b6ff7a"), 10)
	countdown_sub.set_anchors_preset(Control.PRESET_FULL_RECT)
	root.add_child(countdown_sub)
	banner = _slabel("", 54, Color("ffd23a"), 16)
	banner.set_anchors_preset(Control.PRESET_FULL_RECT)
	banner.modulate.a = 0.0
	root.add_child(banner)
	toast = _slabel("", 26, Color.WHITE, 8)
	toast.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	toast.modulate.a = 0.0
	root.add_child(toast)


func _build_picker() -> void:
	picker = PanelContainer.new()
	picker.visible = false
	var vb := VBoxContainer.new()
	vb.add_theme_constant_override("separation", 6)
	picker.add_child(vb)
	_picker_label = _slabel("WILDCARD! Pick your next piece (1-7)", 20, Color("e8b0ff"), 6)
	vb.add_child(_picker_label)
	var hb := HBoxContainer.new()
	hb.add_theme_constant_override("separation", 6)
	hb.alignment = BoxContainer.ALIGNMENT_CENTER
	vb.add_child(hb)
	for p in Pieces.COUNT:
		var piece := p
		var b := _icon_button("piece", func(): game.choose_wildcard(piece))
		b.piece = p
		b.custom_minimum_size = Vector2(62, 62)
		var art := IconArt.new()
		art.atlas = game.atlas
		art.piece = p
		art.material = game.atlas.premult_material
		art.mouse_filter = Control.MOUSE_FILTER_IGNORE
		art.set_anchors_preset(Control.PRESET_FULL_RECT)
		b.add_child(art)
		hb.add_child(b)
		picker_buttons.append(art)
	root.add_child(picker)


func _build_title() -> void:
	title_screen = _overlay()
	# The main screen gets its own background instead of the dimmed board.
	var dim := title_screen.get_child(0)
	title_screen.remove_child(dim)
	dim.queue_free()
	var backdrop := TitleBackdrop.new()
	backdrop.set_anchors_preset(Control.PRESET_FULL_RECT)
	title_screen.add_child(backdrop)
	title_screen.move_child(backdrop, 0)
	# A simple menu: the name and one button.
	var vb := VBoxContainer.new()
	vb.add_theme_constant_override("separation", 36)
	vb.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_center_of(title_screen).add_child(vb)
	var logo := _slabel("OOZE UP!", 120, Color("7dff3a"), 30)
	logo.add_theme_color_override("font_outline_color", Color("0b3a12"))
	vb.add_child(logo)
	new_game_button = _button("NEW GAME", func(): game.start_run(), 300)
	new_game_button.custom_minimum_size = Vector2(300, 76)
	new_game_button.add_theme_font_size_override("font_size", 36)
	new_game_button.size_flags_horizontal = Control.SIZE_SHRINK_CENTER
	vb.add_child(new_game_button)


func _build_pause() -> void:
	pause_screen = _overlay()
	var panel := PanelContainer.new()
	_center_of(pause_screen).add_child(panel)
	var vb := VBoxContainer.new()
	vb.add_theme_constant_override("separation", 14)
	panel.add_child(vb)
	vb.add_child(_slabel("PAUSED", 64, Color("7dff3a"), 14))
	vb.add_child(_kbutton("RESUME  (P)", "RESUME", func(): game.toggle_pause()))
	vb.add_child(_kbutton("RESTART  (R)", "RESTART", func(): game.start_run()))
	pause_mute = _button("SOUND: ON  (M)", func(): game.toggle_mute())
	vb.add_child(pause_mute)
	vb.add_child(_button("MAIN MENU", func(): game.go_to_title()))


func _build_over() -> void:
	over_screen = _overlay()
	var panel := PanelContainer.new()
	_center_of(over_screen).add_child(panel)
	var vb := VBoxContainer.new()
	vb.add_theme_constant_override("separation", 8)
	panel.add_child(vb)
	vb.add_child(_slabel("WATER SPILLED!", 64, Color("ff8a3a"), 14))
	over_reason = _slabel("", 22, Color(1, 1, 1, 0.85), 6)
	over_reason.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	vb.add_child(over_reason)
	over_score = _slabel("", 54, Color.WHITE, 12)
	vb.add_child(over_score)
	over_height = _label("", 26, Color("b6ff7a"), 6)
	vb.add_child(over_height)
	over_best = _label("", 26, Color("ffd23a"), 6)
	vb.add_child(over_best)
	over_new = _label("NEW BEST!", 36, Color("ffd23a"), 10)
	vb.add_child(over_new)
	var sp := Control.new()
	sp.mouse_filter = Control.MOUSE_FILTER_IGNORE  # Spacers must not swallow taps.
	sp.custom_minimum_size = Vector2(0, 8)
	vb.add_child(sp)
	vb.add_child(_kbutton("PLAY AGAIN  (R)", "PLAY AGAIN", func(): game.start_run()))
	vb.add_child(_button("MAIN MENU", func(): game.go_to_title()))


# --- screens --------------------------------------------------------------------------------

func show_title(best: int) -> void:
	title_screen.visible = true
	pause_screen.visible = false
	over_screen.visible = false
	hud.visible = false
	btn_ff.visible = false


func show_play() -> void:
	title_screen.visible = false
	pause_screen.visible = false
	over_screen.visible = false
	hud.visible = true
	btn_ff.visible = true
	_last_count = -1


func show_pause(p: bool) -> void:
	pause_screen.visible = p


func show_game_over(reason: String, score: int, height: int, best: int, is_new: bool) -> void:
	over_reason.text = reason
	over_score.text = "%d" % score
	over_height.text = "HEIGHT  %d rows" % height
	over_best.text = "BEST  %d" % best
	over_new.visible = is_new
	over_screen.visible = true
	over_screen.modulate.a = 0.0
	create_tween().tween_property(over_screen, "modulate:a", 1.0, 0.35)


func show_banner(text: String) -> void:
	banner.text = text
	if _banner_tween:
		_banner_tween.kill()
	banner.modulate.a = 0.0
	banner.scale = Vector2.ONE
	_banner_tween = create_tween()
	_banner_tween.tween_property(banner, "modulate:a", 1.0, 0.25)
	_banner_tween.tween_interval(1.8)
	_banner_tween.tween_property(banner, "modulate:a", 0.0, 0.5)


func flash(col: Color) -> void:
	if _flash_tween:
		_flash_tween.kill()
	_flash.color = col
	_flash_tween = create_tween()
	_flash_tween.tween_property(_flash, "color:a", 0.0, 0.5)


func show_toast(text: String, col := Color.WHITE) -> void:
	toast.text = text
	toast.add_theme_color_override("font_color", col)
	if _toast_tween:
		_toast_tween.kill()
	toast.modulate.a = 1.0
	_toast_tween = create_tween()
	_toast_tween.tween_interval(1.2)
	_toast_tween.tween_property(toast, "modulate:a", 0.0, 0.4)


# --- per-frame refresh ------------------------------------------------------------------------

func _set_text(l: Label, s: String) -> void:
	if l.text != s:
		l.text = s


func refresh() -> void:
	var vs: Vector2 = game.view_size
	if vs != _last_view or game.portrait != _last_portrait:
		_last_view = vs
		_last_portrait = game.portrait
		_apply_layout()
	var ff_rect: Rect2 = game.ff_rect
	if btn_ff.position != ff_rect.position or btn_ff.size != ff_rect.size:
		btn_ff.position = ff_rect.position
		btn_ff.size = ff_rect.size

	_set_text(stat_values["SCORE"], "%d" % game.score)
	_set_text(stat_values["BEST"], "%d" % maxi(game.best, game.score))
	_set_text(stat_values["HEIGHT"], "%d" % game.height)
	_set_text(stat_values["MULT"], "x%.1f" % game.multiplier())
	var spd: float = game.effective_speed()
	var tag := ""
	if game.fast_forward:
		tag = " FF"
	elif game.slow_timer > 0.0:
		tag = " SLOW"
	_set_text(stat_values["SPEED"], "%.2fx%s" % [spd, tag])
	var scol := Color("ffd23a") if game.fast_forward else (Color("8ad8ff") if game.slow_timer > 0.0 else Color.WHITE)
	if scol != _speed_col:
		_speed_col = scol
		(stat_values["SPEED"] as Label).add_theme_color_override("font_color", scol)

	if btn_ff.lit != game.fast_forward:
		btn_ff.lit = game.fast_forward
		btn_ff.queue_redraw()
	var mk := "sound_off" if game.sfx.muted else "sound_on"
	if btn_mute.kind != mk:
		btn_mute.kind = mk
		btn_mute.queue_redraw()
	var mt := "SOUND: OFF" if game.sfx.muted else "SOUND: ON"
	if not game.is_touch:
		mt += "  (M)"
	if pause_mute.text != mt:
		pause_mute.text = mt

	# Countdown.
	if game.state == game.State.COUNTDOWN and not game.paused:
		var n := int(ceil(game.countdown))
		_set_text(countdown_sub, "WATER FLOWS IN")
		_set_text(countdown_label, "%d" % n)
		var frac: float = game.countdown - floor(game.countdown)
		var s := 1.0 + 0.25 * pow(frac, 3.0)
		countdown_label.pivot_offset = countdown_label.size * 0.5
		countdown_label.scale = Vector2(s, s)
		countdown_label.modulate.a = 0.35 if n > 3 else 0.95
		countdown_sub.modulate.a = 0.8
		_last_count = n
	elif countdown_label.text != "" and not (game.paused and game.state == game.State.COUNTDOWN):
		countdown_label.text = ""
		countdown_sub.text = ""

	if over_new.visible:
		over_new.modulate = Color.from_hsv(0.13, 0.6 + 0.4 * sin(game.time * 6.0), 1.0)

	# Wildcard picker.
	var want_picker: bool = game.wildcards > 0 and (game.state == game.State.RUNNING or game.state == game.State.COUNTDOWN) and not game.paused
	if picker.visible != want_picker:
		picker.visible = want_picker
		_picker_zone = -1
	if want_picker:
		var pz: int = game.zone_index * 100000 + game.atlas.icon_px
		if _picker_zone != pz:
			_picker_zone = pz
			for art in picker_buttons:
				art.zone = game.zone_index
				art.queue_redraw()
			picker.reset_size()
		var ps := picker.get_combined_minimum_size()
		var b: Rect2 = game.board_rect
		var pp := Vector2(roundf((vs.x - ps.x) * 0.5), roundf(b.end.y - ps.y - 16.0))
		if picker.position != pp:
			picker.position = pp


func _apply_layout() -> void:
	var vs: Vector2 = game.view_size
	var touch: bool = game.is_touch
	# Text scales down on narrow screens so headings never run off the edge.
	var k := clampf(minf(vs.x / 680.0, vs.y / 760.0), 0.6, 1.0)
	for e in _scaled:
		var l: Label = e[0]
		l.add_theme_font_size_override("font_size", maxi(12, int(e[1] * k)))
		l.add_theme_constant_override("outline_size", maxi(2, int(e[2] * k)))
	for e in _key_buttons:
		(e[0] as Button).text = e[2] if touch else e[1]
	var narrow := vs.x < 620.0
	_best_box.visible = not narrow
	for key in ["SCORE", "BEST", "HEIGHT", "MULT", "SPEED"]:
		(stat_values[key] as Label).add_theme_font_size_override("font_size", 24 if narrow else 27)
		(stat_values[key + "_cap"] as Label).add_theme_font_size_override("font_size", 14 if narrow else 13)
	var bs := 56.0 if touch or narrow else 52.0
	btn_pause.custom_minimum_size = Vector2(bs, bs)
	btn_mute.custom_minimum_size = Vector2(bs, bs)
	var unlock: bool = game.mode == "unlock"
	over_reason.custom_minimum_size = Vector2(minf(420.0, vs.x - 96.0), 0)
	var what := "Pick any piece to place" if unlock else "Pick your next piece"
	_picker_label.text = "WILDCARD! " + what + ("" if touch else " (1-7)")
	var pb := clampf((vs.x - 110.0) / 7.0, 40.0, 62.0)
	for art in picker_buttons:
		(art.get_parent() as Control).custom_minimum_size = Vector2(pb, pb)
	picker.reset_size()
	_picker_zone = -1
	hud.position = Vector2.ZERO
	hud.size = Vector2(vs.x, game.hud_h)
	var hb := hud.get_node("Stats") as HBoxContainer
	hb.position = Vector2(10, 4)
	hb.size = Vector2(vs.x - 20, game.hud_h - 8)
	countdown_label.position = Vector2(0, -40)
	countdown_label.size = vs
	countdown_sub.position = Vector2(0, -150)
	countdown_sub.size = vs
	banner.position = Vector2(0, -vs.y * 0.22)
	banner.size = vs
	toast.position = Vector2(20, -vs.y * 0.5 + game.hud_h + 40)
	toast.size = Vector2(vs.x - 40, vs.y)
