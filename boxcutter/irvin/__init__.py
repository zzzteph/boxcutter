"""irvin - a PIPELINE bug-hunter: an explicit, readable spine in code with pluggable agents. One round is
always the same five phases -

    SUGGEST  -> every suggester (a profile expert) reads the landscape and advises in its lane, or skips
    CONCLUDE -> the concluder collects all advice and prioritizes it into one ordered list
    PLAN     -> the planner turns the prioritized conclusions into concrete executor steps
    EXECUTE  -> executors do the work AND verify their own output, enriching the landscape
    (loop)   -> back to SUGGEST until the surface converges (all skip) or a round cap
    REPORT   -> the reporter compiles the final report

Adding an agent = registering it in `agents/__init__.py`; the spine never changes. irvin owns its own
boxcutter tool layer (Runner + LLM provider, in this package). Exposed as `boxcutter irvin <target>`.
"""
