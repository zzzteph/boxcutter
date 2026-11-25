## ============================================================================
##  ZONES - every 50 rows the palette, backdrop and obstacle mix change.
## ============================================================================
class_name Zones
extends RefCounted

static var _themes: Array = []


static func _c(hex: String) -> Color:
	return Color.html(hex)


static func _build() -> void:
	_themes = [
		{
			"name": "SEWER", "deco": "bubbles",
			"bg_top": _c("0d2a2a"), "bg_bottom": _c("06110f"),
			"board": _c("0b1a19"), "tile": _c("29433f"), "tile_hi": _c("3d615a"), "tile_lo": _c("172825"),
			"rock": _c("6b5a4a"), "rock_dark": _c("2e241c"), "rock_hi": _c("9a8670"),
			"metal": _c("8fa3ab"), "metal_dark": _c("2f3b40"), "metal_light": _c("dce8ec"),
			"brass": _c("c9973a"), "brass_dark": _c("5a3d12"),
			"channel": _c("101818"), "goo": _c("3ab4ff"), "accent": _c("b6ff7a"), "wall": _c("44575c"),
			"rock_mult": 1.0, "oneway_mult": 0.6, "reservoir_mult": 0.7, "powerup_mult": 1.0,
		},
		{
			"name": "FACTORY", "deco": "gears",
			"bg_top": _c("3a2414"), "bg_bottom": _c("140b06"),
			"board": _c("1b1410"), "tile": _c("4a4038"), "tile_hi": _c("6c5f53"), "tile_lo": _c("2a231e"),
			"rock": _c("5d6166"), "rock_dark": _c("23262a"), "rock_hi": _c("8d949b"),
			"metal": _c("b0a89c"), "metal_dark": _c("3b342d"), "metal_light": _c("f3ece0"),
			"brass": _c("d6a03a"), "brass_dark": _c("5f3f0f"),
			"channel": _c("15110e"), "goo": _c("3ab4ff"), "accent": _c("ff9d3a"), "wall": _c("6a4a2c"),
			"rock_mult": 1.1, "oneway_mult": 1.4, "reservoir_mult": 1.0, "powerup_mult": 1.0,
		},
		{
			"name": "NEON", "deco": "grid",
			"bg_top": _c("2a0f45"), "bg_bottom": _c("0a0418"),
			"board": _c("0d0820"), "tile": _c("261a4a"), "tile_hi": _c("4a35a0"), "tile_lo": _c("140c2c"),
			"rock": _c("5a2b80"), "rock_dark": _c("1d0b30"), "rock_hi": _c("c070ff"),
			"metal": _c("a8b4d8"), "metal_dark": _c("2a2850"), "metal_light": _c("ffffff"),
			"brass": _c("3af0ff"), "brass_dark": _c("0b4a5a"),
			"channel": _c("0c0718"), "goo": _c("3ab4ff"), "accent": _c("3af0ff"), "wall": _c("ff3df2"),
			"rock_mult": 0.9, "oneway_mult": 1.0, "reservoir_mult": 1.0, "powerup_mult": 1.2,
		},
		{
			"name": "MAGMA", "deco": "embers",
			"bg_top": _c("4a0d06"), "bg_bottom": _c("150302"),
			"board": _c("1a0806"), "tile": _c("3a2724"), "tile_hi": _c("5e3d36"), "tile_lo": _c("201412"),
			"rock": _c("2b2426"), "rock_dark": _c("0c0909"), "rock_hi": _c("ff5a1a"),
			"metal": _c("a08070"), "metal_dark": _c("3a2018"), "metal_light": _c("ffd8c0"),
			"brass": _c("e0b050"), "brass_dark": _c("5a3010"),
			"channel": _c("120807"), "goo": _c("3ab4ff"), "accent": _c("ffd23a"), "wall": _c("6a2a18"),
			"rock_mult": 1.35, "oneway_mult": 1.0, "reservoir_mult": 1.5, "powerup_mult": 1.1,
		},
		{
			"name": "SPACE", "deco": "stars",
			"bg_top": _c("0a1030"), "bg_bottom": _c("010208"),
			"board": _c("050816"), "tile": _c("1a2240"), "tile_hi": _c("34437a"), "tile_lo": _c("0c1024"),
			"rock": _c("6a6a78"), "rock_dark": _c("22222c"), "rock_hi": _c("b0b0c4"),
			"metal": _c("c8d4e8"), "metal_dark": _c("343c56"), "metal_light": _c("ffffff"),
			"brass": _c("ffc94a"), "brass_dark": _c("5a4010"),
			"channel": _c("060814"), "goo": _c("3ab4ff"), "accent": _c("a070ff"), "wall": _c("4a5a8a"),
			"rock_mult": 1.05, "oneway_mult": 1.4, "reservoir_mult": 1.2, "powerup_mult": 1.2,
		},
	]


static func count() -> int:
	if _themes.is_empty():
		_build()
	return _themes.size()


static func index_for_row(r: int) -> int:
	return maxi(0, r) / Tuning.ZONE_ROWS


static func theme(zone_index: int) -> Dictionary:
	if _themes.is_empty():
		_build()
	return _themes[posmod(zone_index, _themes.size())]


static func theme_for_row(r: int) -> Dictionary:
	return theme(index_for_row(r))


## "ZONE 2: FACTORY", and "ZONE 7: FACTORY II" on the second lap.
static func title(zone_index: int) -> String:
	var lap := zone_index / count()
	var suffix := ""
	if lap > 0:
		suffix = " " + "I".repeat(lap + 1) if lap < 3 else " +%d" % lap
	return "ZONE %d: %s%s" % [zone_index + 1, theme(zone_index)["name"], suffix]
