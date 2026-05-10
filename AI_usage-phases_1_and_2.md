# AI Usage Documentation – Phases 1 and 2

## Tool used
Claude (claude-sonnet-4-20250514) via claude.ai chat interface.

---

## Phase 1 – Filter helper functions

### Scope of AI assistance

AI assistance was used only for the two filter helper functions required by the spec:
`parse_condition` and `match_condition`. All other code was written by hand.

### Function 1: `parse_condition`

**Prompt given:**
> I have a C struct called Report with fields: int id, char inspector[64], double latitude,
> double longitude, char category[32], int severity, time_t timestamp, char description[256].
> Write a C function int parse_condition(const char *input, char *field, char *op, char *value)
> that splits a field:operator:value string into its three parts. Supported operators: ==, !=,
> <, <=, >, >=. Return 1 on success, 0 on error.

**What the AI generated:** A function using strchr to find the two ':' delimiters, then copying
each part with strncpy.

**What I changed:**
- Added explicit bounds checks on flen, olen, vlen to prevent silent truncation
- Added validation loop over the six allowed operators — the original accepted anything
- Added explicit null terminators after each strncpy call since strncpy doesn't guarantee them

**What I learned:** strncpy does not null-terminate when the source fills the buffer exactly.
This is a well-known C pitfall that the AI code relied on the caller to handle.

### Function 2: `match_condition`

**Prompt given:**
> Using the same Report struct, write int match_condition(Report *r, const char *field,
> const char *op, const char *value) that returns 1 if the record satisfies the condition.
> Fields: severity (int), category (char[]), inspector (char[]), timestamp (time_t).
> Operators: ==, !=, <, <=, >, >=.

**What the AI generated:** if/else chains per field, atoi() for integer conversion, strcmp
for string fields.

**What I changed:**
- Replaced atoi() with strtol()/strtoll() and checked *endptr to catch invalid input
- Added explicit cast to long long for timestamp to avoid truncation on 64-bit systems
- Changed the default return for unknown fields from 1 to 0 (the original silently matched everything)
- Refactored repeated operator comparisons into STR_CMP and INT_CMP macros

**What I learned:** atoi() silently returns 0 on bad input. On 64-bit Linux, time_t is 64 bits —
casting to int before comparison would break timestamps after 2038.

---

## Phase 2 – Processes and Signals

AI assistance was not used for Phase 2. The new features — remove_district, monitor_reports,
and the SIGUSR1 notification in city_manager — were implemented directly using the POSIX
documentation for fork(), execlp(), waitpid(), sigaction(), and kill().

The decision not to use AI for Phase 2 came from wanting to practice the signal and process
APIs hands-on, which is the main learning goal of the phase.
