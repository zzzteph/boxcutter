# Ooze Up!

An endless, vertical pipe-laying puzzle built with **Godot 4** (GDScript, no
assets: all art and sound are generated in code). Goo flows up from a pump at
the bottom; lay pipes ahead of it and climb as high as you can.

## Run it

- **Editor:** open this folder in Godot 4.7 (tested with 4.7.2) and press F5.
- **Browser:** Project > Export > Web (the preset is included, single-threaded,
  so any static host works). Then serve the folder over HTTP, for example:

  ```bash
  cd build/web && python3 -m http.server 8000
  ```

  and open http://localhost:8000. A Godot web build can't be opened straight
  from disk with `file://`.

## Controls

| Action | Mouse / touch | Keyboard |
| --- | --- | --- |
| Place the next piece | Click / tap an empty tile | Arrows or WASD to move the cursor, Space / Enter to place |
| Replace a dry pipe (-50 points, 1 s lock) | Click / tap it | Same |
| Fast-forward (x5 flow, x2 points, until game over) | FAST button | F |
| Pick a wildcard piece | Picker buttons | 1-7 |
| Pause | Pause button | P / Esc |
| Mute | Speaker button | M |
| Restart | Play again | R |

## Rules

- Goo starts after a 10-second countdown and speeds up as it climbs.
- The run ends when goo reaches an open pipe end, a wall, a rock, an empty tile,
  a pipe that is already full, or a one-way pipe from the wrong side.
- Pieces: straight horizontal and vertical, four corners and a cross. A cross can
  be filled twice, once each way, for +100.
- Scoring: +10 per filled segment, bonus tiles add their value, and every 25 rows
  add +0.5x to the multiplier. Fast-forward doubles all points.
- Obstacles grow with height: rocks, then bonus tiles, one-way pipes (brass, with
  arrows) and reservoirs (tanks that take 4x as long to fill and buy you time).
- Power-ups (picked up when goo passes): **Slow-mo** (half speed for 8 s),
  **Bomb** (your next click on a rock or dry pipe clears it for free; clicking an
  empty tile still places a piece and keeps the bomb), **Wildcard** (choose the
  next piece).
- Every 50 rows the zone changes: Sewer > Factory > Neon > Magma > Space, then
  the cycle repeats.
- The level is always solvable: each row carries a guaranteed path that only
  ever holds free tiles or fixed pipes pointing the right way, and no row can
  be sealed by rocks.

## Tuning

Every difficulty knob is in [`scripts/tuning.gd`](scripts/tuning.gd):

| Constant | Default | What it does |
| --- | --- | --- |
| `COUNTDOWN_TIME` | 10 s | Delay before the goo starts |
| `BASE_SEGMENT_TIME` | 2.6 s | Time to fill one tile at 1.0x |
| `SPEEDUP_PER_ROW` | 0.012 | Speed gained per row climbed |
| `MAX_SPEED` | 3.5x | Cap on height-based speed |
| `FAST_FORWARD_MULT` / `FAST_FORWARD_SCORE_MULT` | 5x / 2x | Fast-forward flow and points |
| `SLOWMO_MULT` / `SLOWMO_DURATION` | 0.5x / 8 s | Slow-mo power-up |
| `RESERVOIR_FILL_FACTOR` | 4 | How much slower reservoirs fill |
| `REPLACE_LOCK_TIME` / `REPLACE_PENALTY` | 1 s / 50 | Cost of replacing a pipe |
| `PIECE_WEIGHTS` | 16,16,14,14,14,14,5 | Queue odds (crosses rarest) |
| `SCORE_SEGMENT` / `SCORE_CROSS_DOUBLE` | 10 / 100 | Points |
| `MULT_ROWS_STEP` / `MULT_STEP` | 25 rows / +0.5x | Height multiplier |
| `SAFE_ROWS` | 5 | Obstacle-free rows at the start |
| `ROCK_BASE` / `ROCK_PER_ROW` / `ROCK_MAX` | 0.10 / 0.0025 / 0.40 | Rock density and growth |
| `MAX_ROCKS_PER_ROW` | 4 | Hard cap per row |
| `BONUS_START_ROW` / `BONUS_CHANCE` / `BONUS_VALUES` | 12 / 0.045 / 50,100,250 | Bonus tiles |
| `ONEWAY_START_ROW` / `ONEWAY_CHANCE` / `ONEWAY_ON_PATH_CHANCE` | 35 / 0.035 / 0.09 | One-way pipes |
| `RESERVOIR_START_ROW` / `RESERVOIR_CHANCE` / `RESERVOIR_ON_PATH_CHANCE` | 55 / 0.012 / 0.06 | Reservoirs |
| `POWERUP_START_ROW` / `POWERUP_CHANCE` / `POWERUP_MIN_GAP` | 8 / 0.12 / 6 | Power-up frequency |
| `POWERUP_WEIGHTS` | 40,35,25 | Slow-mo, bomb, wildcard odds |
| `SPINE_SHIFT_WEIGHTS` | 40,38,16,6 | How far the guaranteed path drifts sideways per row |
| `ZONE_ROWS` | 50 | Rows per zone |
| `CAMERA_LEAD_FRACTION` / `CAMERA_STIFFNESS` | 0.33 / 3.0 | Camera follow |
| `KEEP_ROWS_BELOW` / `GENERATE_AHEAD` | 20 / 8 | Rows kept below / generated above |

Each zone also scales the obstacle mix (`rock_mult`, `bonus_mult`, ...) in
[`scripts/zones.gd`](scripts/zones.gd).

## Code map

| Script | Role |
| --- | --- |
| `main.gd` | Game controller: states, rules, scoring, layout |
| `tuning.gd` | Tunable constants |
| `pieces.gd` | Piece types, openings, goo path geometry |
| `grid.gd`, `tile.gd` | Sparse endless board; rows below the floor are discarded |
| `flow.gd` | Moves the goo and reports fills, entries and spills |
| `game_camera.gd` | Smooth follow (goo in the lower third) and screen shake |
| `generator.gd` | Procedural rows with a guaranteed path upward |
| `zones.gd` | Zone palettes and obstacle mixes |
| `pipe_art.gd` | Vector drawing of pipes, goo, rocks and icons |
| `sprite_atlas.gd` | Rasterises the vector art once per zone into textures |
| `board_renderer.gd` | Backdrop, cached board rows, live goo tile, particles, queue |
| `input_handler.gd` | Mouse, touch and keyboard |
| `ui.gd` | HUD, banners, title / pause / game-over screens |
| `sfx.gd` | Synthesised sound effects |
| `save_data.gd` | High score (localStorage on the web, a config file elsewhere) |

## Tests

```bash
godot --headless --script res://tests/run_tests.gd
```

```bash
godot --headless --fixed-fps 60 --script res://tests/game_test.gd
```

`run_tests.gd` checks every piece from every entry side, the cross both ways,
every way the goo can be stopped, and generates 250 seeds x 420 rows to prove
each one solvable. `game_test.gd` drives the real scene with input events:
placing, replacing, bombs, wildcards, pause, the countdown, a cross scored in
game, and a 165-row run through four zones.

For profiling in a browser, add `?fps` to the URL to log frame rate and draw
calls to the console, and `?autoplay` to let a bot lay the guaranteed path.
