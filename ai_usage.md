# AI Usage Documentation – Phase 1

## Tool used
Claude (claude-sonnet-4-20250514) via claude.ai chat interface.

---

## Scope of AI assistance

As required by the project specification, AI assistance was requested **only** for the two
filter helper functions: `parse_condition` and `match_condition`.  All other code
(data structures, permission management, command implementations, logging, symlink
handling, main argument parsing) was written by hand.

---

## Function 1: `parse_condition`

### Prompt given to AI

> "I have a C struct called Report with the following fields:
>   - int id
>   - char inspector[64]
>   - double latitude, longitude
>   - char category[32]
>   - int severity  (1=minor, 2=moderate, 3=critical)
>   - time_t timestamp
>   - char description[256]
>
> Write a C function with signature:
>   int parse_condition(const char *input, char *field, char *op, char *value);
> that splits a condition string of the form field:operator:value into its three parts.
> Supported operators are: ==, !=, <, <=, >, >=.
> Return 1 on success and 0 on error. The buffers field, op, value are caller-provided."

### What the AI generated

The AI produced a function that:
1. Uses `strchr` to find the first and second `:` delimiters.
2. Copies each segment using pointer arithmetic and `strncpy`.
3. Returns 0 if any delimiter is missing.

### What I changed and why

| Problem found during review | Fix applied |
|-----------------------------|-------------|
| No bounds check on `flen`, `olen`, `vlen` — a very long input could silently truncate or corrupt data | Added explicit size checks (`flen >= 32`, `olen >= 4`, `vlen >= 128`) that return 0 on violation |
| The operator was not validated — any string between the two colons was accepted | Added a loop over the six valid operator strings; return 0 if none match |
| Output buffers were null-terminated by `strncpy` only accidentally (when length < buffer) | Explicitly set `field[flen] = '\0'`, `op[olen] = '\0'`, `value[vlen] = '\0'` |

### What I learned

`strncpy` does **not** guarantee null-termination when the source is exactly as long as
the specified length. This is a classic C pitfall. The AI-generated code relied on the
buffers being zero-initialised, which is not guaranteed on the stack. Always add explicit
null terminators.

---

## Function 2: `match_condition`

### Prompt given to AI

> "Using the same Report struct, write:
>   int match_condition(Report *r, const char *field, const char *op, const char *value);
> that returns 1 if the record satisfies the condition, 0 otherwise.
> Fields that should be supported: severity (int), category (char[]), inspector (char[]),
> timestamp (time_t). Operators: ==, !=, <, <=, >, >=.
> String fields only support == and !=; numeric fields support all six operators."

### What the AI generated

The AI produced a function with:
- A chain of `if/else if` blocks for each field name.
- `atoi()` for converting the string value to an integer for `severity` and `timestamp`.
- `strcmp` for string fields.

### What I changed and why

| Problem found during review | Fix applied |
|-----------------------------|-------------|
| `atoi()` silently returns 0 on invalid input, masking bad conditions | Replaced with `strtol()` / `strtoll()` and checked `*endptr != '\0'` to detect conversion errors |
| `timestamp` was compared as `int`, which truncates on 64-bit systems where `time_t` is 64-bit | Added explicit cast to `long long` for the comparison |
| Unknown field names fell through to a final `return 1` — meaning unrecognised fields always matched | Changed to `return 0` with a `fprintf(stderr, ...)` warning |
| Repetitive if-else chains for the six operators were hard to read and error-prone | Replaced with two helper macros `STR_CMP` and `INT_CMP` for clarity |

### What I learned

- `atoi` is almost never the right choice in production C code; `strtol` with error
  checking is safer and only slightly more verbose.
- On modern 64-bit Linux, `time_t` is `long` (64 bits). Casting it to `int` before
  comparison would silently corrupt timestamps after year 2038.
- Macros can reduce code duplication for repeated operator comparisons, but they must
  be written with parentheses around every argument to avoid precedence bugs.

---

## Overall evaluation

The AI-generated code was a correct starting point that saved time writing boilerplate
pointer arithmetic and operator dispatch. However, it produced code that would fail or
behave incorrectly in edge cases:

- Missing bounds checks (buffer overruns)
- Unsafe integer conversion (`atoi`)
- Incorrect type for `timestamp` comparison
- Wrong default return value for unknown fields

None of these would have caused crashes in typical test cases, which is exactly why this
kind of subtle bug is dangerous. Reviewing line by line — as required by the spec — was
essential to catch them. The exercise reinforced that AI output must be treated as a first
draft, not a final answer.
