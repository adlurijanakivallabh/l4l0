<!-- ruff-claude-hook-start -->

# Ruff Hook - Instructions for Claude

## Automatic Code Quality Workflow

This project has an automated ruff workflow that runs **after you edit or create any Python file**.

### How It Works

When you edit or create a Python file, a PostToolUse hook automatically executes:

1. **ruff check --fix** - Automatically fixes linting errors where possible
2. **ruff format** - Formats code to PEP 8 standard
3. **ruff check** - Validates no errors remain

### Your Responsibilities

**If you see this message:**
```
❌ Ruff errors in <file>:
```

**Then you MUST:**

1. **Read the error output** displayed by the hook
2. **Read the file** to understand the context
3. **Fix each error** immediately in the file
4. **Verify the fix** by checking if the errors are resolved
5. **NEVER report completion** while ruff errors exist

### Example Workflow

**User request:** "Add logging to api.py"

**Step 1:** You edit api.py to add logging
```
[Hook runs automatically]
✅ Ruff checks passed: api.py
```

**Step 2:** Report to user:
"Added logging to api.py. All code quality checks passed."

---

**If there are errors:**

**Step 1:** You edit api.py
```
[Hook runs automatically]
❌ Ruff errors in api.py:

api.py:23:5: F841 Local variable 'level' is assigned to but never used
api.py:45:1: F821 Undefined name 'logger'

⚠️  Claude: You MUST fix these errors before continuing
```

**Step 2:** Read the file and fix errors
- Use Read tool to view api.py
- Fix F841: Remove or use the unused `level` variable
- Fix F821: Import or define `logger`

**Step 3:** Edit the file again with fixes
```
[Hook runs automatically]
✅ Ruff checks passed: api.py
```

**Step 4:** Report to user:
"Added logging to api.py. Fixed linting errors (unused variable, missing import). All quality checks passed."

### What NOT to Do

❌ **WRONG:**
```
User: "Add logging to api.py"
You: [Edit file]
[Hook shows errors]
You: "Done! Added logging to api.py."  ← WRONG! Errors not fixed!
```

❌ **WRONG:**
```
User: "Add logging to api.py"
You: [Edit file]
[Hook shows errors]
You: "I'll fix the errors"  ← WRONG! Just saying, not doing!
```

✅ **CORRECT:**
```
User: "Add logging to api.py"
You: [Edit file]
[Hook shows errors]
You: [Use Read tool on api.py]
You: [Edit file to fix specific errors]
[Hook shows success]
You: "Done! Added logging to api.py. All quality checks passed."
```

### Key Rules

1. **Never ignore hook output** - It's showing you real errors
2. **Read the file** when there are errors - don't guess
3. **Fix errors immediately** - Don't move on with broken code
4. **Actually edit the file** - Don't just acknowledge errors
5. **Verify success** - Wait for the ✅ message
6. **Report accurately** - Tell the user about issues you fixed

### Understanding Error Codes

Common ruff error codes you might see:

**Auto-fixable (Phase 1 handles automatically):**
- **E302** - Expected 2 blank lines (formatting)
- **E501** - Line too long (formatting)
- **W291** - Trailing whitespace (formatting)
- **I001** - Import block unsorted (auto-fixed)

**Usually require manual fixes:**
- **F401** - Module imported but unused → Remove the import
- **F841** - Variable assigned but never used → Remove or use it
- **F821** - Undefined name → Import or define it
- **F811** - Redefinition of unused name → Remove duplicate
- **E711** - Comparison to None should use 'is' → Use `is None`
- **E712** - Comparison to True/False → Use `if var:` not `if var == True:`

### Workflow Summary

```
Edit Python file
   ↓
Hook runs automatically
   ↓
✅ Success → Continue
   ↓
❌ Errors → Read file → Fix errors → Hook runs again → ✅ Success
```

---

**Remember:** The goal is to ensure every Python file you edit passes all quality checks before you report completion to the user. Read files when fixing errors, don't guess!

<!-- ruff-claude-hook-end -->
