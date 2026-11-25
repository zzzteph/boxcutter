## ============================================================================
##  TUNING - every knob that shapes difficulty and feel lives here.
## ============================================================================
class_name Tuning
extends RefCounted

# --- Board ------------------------------------------------------------------
const COLS := 7                      ## Board width in tiles.
const SOURCE_COL := 3                ## Column of the goo source (row 0).
const MIN_VISIBLE_ROWS := 10.0       ## Rows that always fit on screen (sets tile size).

# --- Flow -------------------------------------------------------------------
const COUNTDOWN_TIME := 10.0         ## Seconds before the goo starts flowing.
const BASE_SEGMENT_TIME := 2.6       ## Seconds to fill one tile at speed 1.0x.
const SPEEDUP_PER_ROW := 0.012       ## Speed gained per row climbed (+1.2% per row).
const MAX_SPEED := 3.5               ## Cap on the height-based speed factor.
const FAST_FORWARD_MULT := 5.0       ## Fast-forward flow multiplier.
const FAST_FORWARD_SCORE_MULT := 2.0 ## Points multiplier while fast-forwarding.
const SLOWMO_MULT := 0.5             ## Flow multiplier while slow-mo is active.
const SLOWMO_DURATION := 8.0         ## Seconds of slow-mo per pickup.
const RESERVOIR_FILL_FACTOR := 4.0   ## Reservoir tiles take this many times longer to fill.

# --- Placement --------------------------------------------------------------
const QUEUE_SIZE := 5                ## Pieces shown in the queue.
const REPLACE_LOCK_TIME := 1.0       ## Seconds the queue is locked after a replace.
const REPLACE_PENALTY := 50          ## Points lost per replace.
## Queue weights, indexed by piece id: H, V, SE(┌), SW(┐), NE(└), NW(┘), CROSS.
const PIECE_WEIGHTS := [16, 16, 14, 14, 14, 14, 5]

# --- Scoring ----------------------------------------------------------------
const SCORE_SEGMENT := 10            ## Points per filled segment.
const SCORE_CROSS_DOUBLE := 100      ## Points when a cross is filled both ways.
const MULT_ROWS_STEP := 25           ## Rows per multiplier step.
const MULT_STEP := 0.5               ## Multiplier gained per step.

# --- Camera / memory --------------------------------------------------------
const CAMERA_LEAD_FRACTION := 0.33   ## Goo head is kept this far up from the bottom.
const CAMERA_STIFFNESS := 3.0        ## Higher = camera catches up faster.
const CAMERA_FLOOR_MARGIN := 1.25    ## Rows of bedrock visible under the floor.
const KEEP_ROWS_BELOW := 20          ## Rows this far below the best height are discarded.
const GENERATE_AHEAD := 8            ## Rows generated above the top of the screen.

# --- Generator --------------------------------------------------------------
const SAFE_ROWS := 5                 ## First rows are obstacle-free.
const ROCK_BASE := 0.10              ## Rock chance per off-path tile at SAFE_ROWS.
const ROCK_PER_ROW := 0.0025         ## Extra rock chance per row.
const ROCK_MAX := 0.40               ## Rock chance cap (before zone multiplier).
const MAX_ROCKS_PER_ROW := 4         ## Never more rocks than this in one row.
const BONUS_START_ROW := 12          ## Bonus tiles appear from this row.
const BONUS_CHANCE := 0.045          ## Chance per free tile.
const BONUS_VALUES := [50, 100, 250] ## Possible bonus values (rarer to the right).
const ONEWAY_START_ROW := 35         ## One-way pipes appear from this row.
const ONEWAY_CHANCE := 0.035         ## Chance per free off-path tile.
const ONEWAY_ON_PATH_CHANCE := 0.09  ## Chance per row that the safe path gets a one-way pipe.
const RESERVOIR_START_ROW := 55      ## Reservoirs appear from this row.
const RESERVOIR_CHANCE := 0.012      ## Chance per free off-path tile.
const RESERVOIR_ON_PATH_CHANCE := 0.06 ## Chance per row that the safe path gets a reservoir.
const POWERUP_START_ROW := 8         ## Power-ups appear from this row.
const POWERUP_CHANCE := 0.12         ## Chance per row (after the minimum gap).
const POWERUP_MIN_GAP := 6           ## Minimum rows between power-ups.
## Power-up weights: slow-mo, bomb, wildcard.
const POWERUP_WEIGHTS := [40, 35, 25]
## How far the guaranteed path drifts sideways per row: weights for 0, 1, 2, 3 columns.
const SPINE_SHIFT_WEIGHTS := [40, 38, 16, 6]

# --- Zones ------------------------------------------------------------------
const ZONE_ROWS := 50                ## Rows per zone.
