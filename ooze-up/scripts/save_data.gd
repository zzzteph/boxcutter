## High score storage: localStorage in the browser, a config file elsewhere.
## Every access is guarded, so a blocked or broken store never crashes the game.
class_name SaveData
extends RefCounted

const KEY := "ooze_up_best"
const PATH := "user://ooze_up.cfg"


static func load_best() -> int:
	var best := 0
	if OS.has_feature("web"):
		var v = JavaScriptBridge.eval(
				"(function(){try{return String(window.localStorage.getItem('%s')||'0');}catch(e){return '0';}})()" % KEY, true)
		if v != null:
			best = maxi(best, int(str(v)))
	var cfg := ConfigFile.new()
	if cfg.load(PATH) == OK:
		var v = cfg.get_value("scores", "best", 0)
		if typeof(v) == TYPE_INT or typeof(v) == TYPE_FLOAT:
			best = maxi(best, int(v))
	return best


static func save_best(score: int) -> void:
	if OS.has_feature("web"):
		JavaScriptBridge.eval(
				"(function(){try{window.localStorage.setItem('%s','%d');}catch(e){}})()" % [KEY, score], true)
	var cfg := ConfigFile.new()
	cfg.load(PATH)  # Missing file is fine.
	cfg.set_value("scores", "best", score)
	var err := cfg.save(PATH)
	if err != OK and not OS.has_feature("web"):
		push_warning("Could not save high score (error %d)" % err)

