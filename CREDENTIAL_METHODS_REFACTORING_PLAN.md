# Credential Methods Refactoring Plan

## Overview
Refactoring plan for `credential_create` and `credential_request` methods in `soft_fido2/authenticator.py` to improve code quality, eliminate duplication, and enhance maintainability.

## Affected Methods
- `credential_create` (lines 266-324)
- `credential_request` (lines 326-364)

## Identified Issues
1. **Missing type hints** - Both methods lack type annotations
2. **Code duplication** - Identical JSON parsing logic in both methods (5 lines each)
3. **Code duplication** - Identical keyPair defaulting logic in both methods
4. **Unclear variable names** - `cco` and `cro` are cryptic abbreviations
5. **Verbose JSON parsing** - 5 lines for simple conditional assignment

---

## Phase 1: High Priority (Zero Risk, Non-Breaking)

### 1.1 Add Type Hints to Both Methods

**File:** `soft_fido2/authenticator.py`

**Lines 266-324 - credential_create:**
```python
# BEFORE
def credential_create(self, jsonOptions, atteStmtFmt='packed-self', keyPair=None, uv=True, up=True, be=False, bs=False):

# AFTER
def credential_create(
    self, 
    jsonOptions: Union[str, dict], 
    atteStmtFmt: str = 'packed-self', 
    keyPair: Optional[KeyPair] = None, 
    uv: bool = True, 
    up: bool = True, 
    be: bool = False, 
    bs: bool = False
) -> dict:
```

**Lines 326-364 - credential_request:**
```python
# BEFORE
def credential_request(self, jsonOptions, keyPair=None, uv=True, up=True, be=False, bs=False):

# AFTER
def credential_request(
    self, 
    jsonOptions: Union[str, dict], 
    keyPair: Optional[KeyPair] = None, 
    uv: bool = True, 
    up: bool = True, 
    be: bool = False, 
    bs: bool = False
) -> dict:
```

**Benefits:**
- Enables static type checking with mypy/pyright
- Improves IDE autocomplete and documentation
- Makes function contracts explicit
- Aligns with existing type hints in class `__init__` (lines 33-47)

**Implementation:** Use `apply_diff` tool for both methods

---

### 1.2 Simplify JSON Parsing

**credential_create (lines 318-322):**
```python
# BEFORE
options = {}
if isinstance(jsonOptions, dict):
    options = jsonOptions
else:
    options = json.loads(jsonOptions)

# AFTER
options = jsonOptions if isinstance(jsonOptions, dict) else json.loads(jsonOptions)
```

**credential_request (lines 357-361):**
```python
# BEFORE
options = {}
if isinstance(jsonOptions, dict):
    options = jsonOptions
else:
    options = json.loads(jsonOptions)

# AFTER
options = jsonOptions if isinstance(jsonOptions, dict) else json.loads(jsonOptions)
```

**Benefits:**
- Reduces 5 lines to 1 line in each method (10 lines total saved)
- Eliminates unnecessary empty dict initialization
- More Pythonic and concise
- Functionally equivalent

**Implementation:** Use `apply_diff` tool for both methods

---

### 1.3 Rename Cryptic Variables

**credential_create (line 323):**
```python
# BEFORE
cco = self.attestation_options_response_to_credential_create_options(options)
return self.process_credential_create_options(cco, atteStmtFmt, keyPair, uv, up, be, bs)

# AFTER
credential_options = self.attestation_options_response_to_credential_create_options(options)
return self.process_credential_create_options(credential_options, atteStmtFmt, keyPair, uv, up, be, bs)
```

**credential_request (line 362):**
```python
# BEFORE
cro = self.assertion_options_response_to_credential_request_options(options)
return self.process_credential_request_options(cro, keyPair, uv, up, be, bs)

# AFTER
request_options = self.assertion_options_response_to_credential_request_options(options)
return self.process_credential_request_options(request_options, keyPair, uv, up, be, bs)
```

**Benefits:**
- Self-documenting code
- Eliminates mental overhead of decoding abbreviations
- Improves code readability

**Implementation:** Use `apply_diff` tool for both methods

---

## Phase 2: Medium Priority (Low Risk, Eliminates Duplication)

### 2.1 Extract JSON Parsing Helper Method

**Add new private method after line 265:**
```python
def _parse_json_options(self, jsonOptions: Union[str, dict]) -> dict:
    """Parse JSON options from either dict or JSON string.
    
    Args:
        jsonOptions: Dictionary or JSON string of options
        
    Returns:
        Parsed dictionary
        
    Raises:
        json.JSONDecodeError: If jsonOptions is a string but not valid JSON
    """
    return jsonOptions if isinstance(jsonOptions, dict) else json.loads(jsonOptions)
```

**Update credential_create (line 319):**
```python
# BEFORE
options = jsonOptions if isinstance(jsonOptions, dict) else json.loads(jsonOptions)

# AFTER
options = self._parse_json_options(jsonOptions)
```

**Update credential_request (line 358):**
```python
# BEFORE
options = jsonOptions if isinstance(jsonOptions, dict) else json.loads(jsonOptions)

# AFTER
options = self._parse_json_options(jsonOptions)
```

**Benefits:**
- DRY principle - single source of truth
- Easier to add error handling or validation
- Can be reused if more methods need JSON parsing
- Reduces code duplication

**Implementation:** 
1. Use `insert_content` to add helper method
2. Use `apply_diff` to update both methods

---

## Phase 3: Optional (Consider Trade-offs)

### 3.1 Consolidate KeyPair Defaulting Pattern

**Both methods currently have:**
```python
if keyPair is None:
    keyPair = self.kp
```

**Alternative approach:**
```python
keyPair = keyPair or self.kp
```

**Benefits:**
- Slightly more concise
- Handles both None and falsy values

**Trade-offs:**
- Behavior change if someone explicitly passes a falsy value (unlikely scenario)
- Current code is already clear and explicit

**Recommendation:** Keep current implementation unless team prefers the alternative

---

### 3.2 Rename atteStmtFmt Parameter

**credential_create only:**
```python
# BEFORE
atteStmtFmt: str = 'packed-self'

# AFTER
attestation_format: str = 'packed-self'
```

**Benefits:**
- Follows Python naming conventions (snake_case)
- More descriptive

**Trade-offs:**
- ⚠️ **BREAKING CHANGE** - Requires updating all call sites that use keyword argument
- Need to search codebase for `atteStmtFmt=` usage

**Recommendation:** Only implement if willing to update all call sites

---

## Implementation Order

### Step 1: Phase 1 Changes (Safe, Non-Breaking)
1. Add type hints to `credential_create`
2. Add type hints to `credential_request`
3. Simplify JSON parsing in `credential_create`
4. Simplify JSON parsing in `credential_request`
5. Rename `cco` to `credential_options` in `credential_create`
6. Rename `cro` to `request_options` in `credential_request`

### Step 2: Phase 2 Changes (Eliminate Duplication)
7. Add `_parse_json_options` helper method
8. Update `credential_create` to use helper
9. Update `credential_request` to use helper

### Step 3: Phase 3 (Optional, Requires Discussion)
10. Decide on keyPair defaulting pattern
11. Decide on parameter renaming (breaking change)

---

## Expected Results

### Before Refactoring
- `credential_create`: 59 lines (including docstring)
- `credential_request`: 39 lines (including docstring)
- Total duplicated code: ~10 lines

### After Phase 1 & 2
- `credential_create`: ~54 lines (5 lines saved)
- `credential_request`: ~34 lines (5 lines saved)
- New helper method: ~12 lines
- Net reduction: ~8 lines
- Code duplication: Eliminated

### Code Quality Improvements
- ✅ Type safety with full type hints
- ✅ Zero code duplication
- ✅ Improved readability with clear variable names
- ✅ More maintainable with DRY principle
- ✅ Easier to add validation/error handling in one place

---

## Testing Requirements

After implementing changes:
1. Run existing unit tests to ensure no regression
2. Verify both methods handle dict input correctly
3. Verify both methods handle JSON string input correctly
4. Verify both methods handle invalid JSON gracefully (if error handling added)
5. Test with None keyPair parameter
6. Test with explicit keyPair parameter

---

## Risk Assessment

**Phase 1:** ✅ **Zero Risk**
- All changes are non-breaking
- Functionally equivalent code
- Type hints are optional in Python

**Phase 2:** ✅ **Low Risk**
- Adds one private method
- Changes are internal refactoring only
- No API changes

**Phase 3:** ⚠️ **Medium Risk**
- Parameter renaming is a breaking change
- Requires codebase-wide search and update

---

## Notes

- Import statement already includes `Union` and `Optional` from typing (line 6)
- Class already uses type hints in `__init__` method, so this aligns with existing patterns
- Both methods follow similar structure, making parallel refactoring straightforward
- The helper method can be extended in the future to add validation or better error messages