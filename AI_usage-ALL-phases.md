# AI Usage Documentation – All Phases

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

---

## Phase 3 – Pipes and Redirects

### Scope of AI assistance

AI was used to help structure the pipe communication architecture for city_hub and the
modified monitor_reports, specifically the typed message protocol and the multi-process
relay design.

### Modified monitor_reports – pipe output

**Prompt given:**
> I have a monitor process that currently writes plain text to stdout. I need to modify it
> so that when given a --pipe-fd <fd> argument, it writes all output to that fd instead of
> stdout, using a typed framing format TYPE:LENGTH:TEXT so the reader can parse messages
> of variable length reliably.

**What the AI generated:** The write_msg helper and the argument parsing for --pipe-fd,
plus the framing format TYPE:LENGTH:TEXT\n.

**What I changed:**
- Added the duplicate-monitor check using kill(pid, 0) before writing the pid file
- Changed all existing printf/write calls to go through write_msg
- Ensured the pipe fd is closed on all exit paths

### city_hub – pipe relay architecture

**Prompt given:**
> Describe how to implement a three-process pipe relay: hub_mon forks monitor_reports
> with a pipe, reads from it, and forwards messages through a second pipe to a reader
> process in the hub parent that prints to the terminal.

**What the AI generated:** The overall fork/pipe structure with relay_pipe and mon_pipe.

**What I changed:**
- Fixed pipe direction (initial version had read/write ends swapped)
- Added proper close() of all unused pipe ends in every process
- Made the reader process non-blocking with respect to the hub's main loop by running
  it as a separate forked process rather than blocking in the parent

### scorer – workload calculator

**Prompt given:**
> Write a C program scorer.c that takes a district name as argv[1], opens district/reports.dat,
> reads Report structs, and prints a workload summary: for each inspector, the number of
> reports and the sum of severity levels.

**What the AI generated:** The basic read loop and the InspectorScore accumulator array.

**What I changed:**
- Replaced printf with write() calls using STDOUT_FILENO to be consistent with dup2 redirect
- Added the MAX_INSPECTORS guard
- Added the district-not-found error path

### calculate_scores – hub command

The dup2() pattern for redirecting scorer stdout into a pipe was implemented directly
from the POSIX documentation without AI assistance.
