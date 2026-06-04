# ECS 235B Final Project Confidentiality Model Test Scripts

This project contains three Python test scripts that simulate and compare different confidentiality models in computer security:

1. **Chinese Wall Model**
2. **Lattice-Based Access Control (LBAC)**
3. **Noninterference Confidentiality Model**

Each script is self-contained and can be run from the command line. The scripts do not require any external Python packages beyond the Python standard library.

---

## Files Included

```text
Chinesewall_test.py
lbac_test.py
non_interference_test.py
```

---

## How to Download and Run the Scripts

### 1. Download the files

Download the three Python files from the project submission or repository:

```text
Chinesewall_test.py
lbac_test.py
non_interference_test.py
```

Place all three files in the same folder, such as:

```text
confidentiality-model-tests/
```

### 2. Open a terminal in that folder

On macOS or Linux:

```bash
cd path/to/confidentiality-model-tests
```

On Windows Command Prompt:

```cmd
cd path\to\confidentiality-model-tests
```

### 3. Run each script

Run the Chinese Wall Model test:

```bash
python3 Chinesewall_test.py
```

Run the LBAC test:

```bash
python3 lbac_test.py
```

Run the Noninterference test:

```bash
python3 non_interference_test.py
```

On Windows, use `python` instead of `python3` if your system uses `python` as the command:

```cmd
python Chinesewall_test.py
python lbac_test.py
python non_interference_test.py
```

---

# 1. Chinese Wall Model Test Script

## File

```text
Chinesewall_test.py
```

## Purpose

This script simulates the **Chinese Wall confidentiality model**, which is designed to prevent conflicts of interest. The core principle of the model is that once a user accesses confidential information from one company within a conflict class, they cannot access confidential information from competing companies in the same conflict class.

The script models a small access-control environment with:

- **Users** as subjects, such as `Alice` and `Bob`
- **Company files** as protected objects
- **Conflict-of-interest classes**, including `Technology` and `Healthcare`
- **File classifications**, either `Public` or `Confidential`
- **Access transactions**, represented as `read` or `write` requests

The model allows public information to be accessed by anyone, but restricts confidential information when the user has already accessed a competing company in the same conflict class.

## Behavior

The script creates users and files from different companies. It then runs a fixed sequence of access requests and checks each request using the `can_access_chinese_wall()` function.

The behavior is:

- Public files are always allowed.
- Confidential files are allowed if the user has not accessed a competing company in the same conflict class.
- Confidential files from the same company remain allowed after prior access.
- Confidential files from a competing company in the same conflict class are denied.
- Successful confidential accesses are recorded in the user's access history.

For example, Alice first reads Google's confidential file in the `Technology` conflict class. After that, Alice is denied access to Microsoft's confidential file because Microsoft is also in the `Technology` conflict class and is treated as a competing company. However, Alice is still allowed to access Pfizer's confidential file because Pfizer belongs to the separate `Healthcare` conflict class.

## Expected Output

The script prints a readable access-control log for each request. Each output block includes:

- User name
- Action requested
- File name
- Company
- Conflict class
- Classification
- Access result: `ALLOW` or `DENY`
- The user's previously accessed companies/conflict classes

Example output pattern:

```text
Chinese Wall Model Access-Control Simulation

User: Alice
Action: read
File: google_strategy.docx
Company: Google
Conflict Class: Technology
Classification: Confidential
Access Result: ALLOW
Previously Accessed: {('Google', 'Technology')}
```

Expected high-level results include:

- Alice reading Google confidential data: `ALLOW`
- Alice reading Microsoft confidential data afterward: `DENY`
- Alice reading Pfizer confidential data: `ALLOW`
- Alice reading a public file: `ALLOW`
- Bob reading Microsoft confidential data first: `ALLOW`
- Bob writing to Google confidential data afterward: `DENY`
- Bob writing to Pfizer confidential data: `ALLOW`

---

# 2. Lattice-Based Access Control (LBAC) Test Script

## File

```text
lbac_test.py
```

## Purpose

This script simulates a **Lattice-Based Access Control (LBAC)** model using a simple computer privilege hierarchy:

```text
Guest < Standard User < Power User < Admin
```

The script demonstrates how access decisions change depending on which confidentiality policy is applied. It compares:

1. A practical LBAC-style computer privilege policy
2. A Bell-LaPadula-style confidentiality policy

This is useful because Bell-LaPadula can be viewed as a type of lattice-based confidentiality model, but it enforces stricter information-flow rules than a normal computer permission system.

## Behavior

The script defines users at different privilege levels and files that require different security levels. Each user attempts to `read` and `write` every file.

The script evaluates each request under two policies:

### Practical LBAC policy

This policy behaves like a normal computer privilege system:

- A user can read a file if their level is greater than or equal to the file's required level.
- A user can write to a file if their level is greater than or equal to the file's required level.
- Higher-level users can access lower-level files.

For example, an `Admin` can read and write files that require `Guest`, `Standard User`, `Power User`, or `Admin` access.

### Bell-LaPadula confidentiality policy

This policy focuses on preventing confidentiality leaks:

- **No Read Up:** users cannot read files above their security level.
- **No Write Down:** users cannot write to files below their security level.

Because of this, a high-level user may be denied permission to write to a lower-level file, since that could leak sensitive information downward.

## Expected Output

The script prints one output block for every combination of:

- User
- File
- Action: `read` or `write`
- LBAC result
- Bell-LaPadula result

Example output pattern:

```text
Real-World LBAC vs. Bell-LaPadula Access Test

User: Guest User (Security Level: Guest)
Action: read
File: public_readme.txt (Security Level: Guest)
LBAC: ALLOW
BLP: ALLOW
```

Expected high-level results include:

- Low-level users are denied reads of higher-level files under both policies.
- Under practical LBAC, higher-level users can read and write lower-level files.
- Under Bell-LaPadula, higher-level users can read lower-level files but may be denied writes to lower-level files because of the `No Write Down` rule.
- Some write decisions differ between `LBAC` and `BLP`, which shows the difference between practical privilege enforcement and strict confidentiality enforcement.

---

# 3. Noninterference Confidentiality Model Test Script

## File

```text
non_interference_test.py
```

## Purpose

This script simulates the **Noninterference Confidentiality Model**. Noninterference requires that high-level user actions should not affect what low-level users can observe. In other words, a low-level user should see the same system output whether or not a high-level user performed an action.

The script uses the same privilege hierarchy as the LBAC script:

```text
Guest < Standard User < Power User < Admin
```

The goal is to test whether high-level activity is invisible to lower-level users.

## Behavior

The script has three major parts.

## Part 1: Read / Write Access Control

The script first tests basic read and write behavior for each user and file.

The secure system state enforces:

- A user can write only if their level meets or exceeds the file's required level.
- A user can read only if their level meets or exceeds the file's required level.
- Writes propagate upward to the writer's level and higher levels.
- Lower-level views are not changed by higher-level writes.

This prevents high-level activity from changing what lower-level users can observe.

## Part 2: Secure Noninterference Baseline

The script then checks the noninterference property using a secure baseline system.

For each low-level observer, high-level writer, and file, the script compares two scenarios:

1. Scenario A: the high-level user writes secret data.
2. Scenario B: the high-level user does not write secret data.

If the low-level user's observation is the same in both scenarios, noninterference `HOLDS`. If the low-level user observes a difference, noninterference is `BROKEN`.

In the secure baseline, the expected result is that noninterference should hold because high-level writes do not change lower-level views.

## Part 3: Flawed Systems

The script also tests three flawed implementations that break noninterference.

### Flaw A: Downward Write Leak

This flawed system incorrectly propagates high-level writes to all security levels, including lower levels.

Expected behavior:

- A low-level user may directly read content written by a high-level user.
- This creates an obvious confidentiality leak.
- Some cases should print `Noninterference: BROKEN`.

### Flaw B: Shared Error Counter Side Channel

This flawed system increments a shared denied-write counter whenever a write is denied. Since the counter is visible to all users, a low-level user can infer that a high-level action occurred by observing the counter change.

Expected behavior:

- The low-level user may not see the secret file content directly.
- However, the low-level user can observe the shared counter.
- The counter acts as a side channel.
- Some cases should print `Noninterference: BROKEN`.

### Flaw C: File-Size Metadata Side Channel

This flawed system stores file size metadata in one shared field per file instead of isolating metadata by security level. When a high-level user writes data, the shared file size changes, and a low-level user can detect that change.

Expected behavior:

- The low-level user may not see the high-level content directly.
- However, the low-level user can observe the changed file size.
- The file-size metadata acts as a side channel.
- Some cases should print `Noninterference: BROKEN`.

## Expected Output

The script prints three major sections:

```text
PART 1 — Read / Write Access Control
PART 2 — Noninterference Property Verification (Secure Baseline)
PART 3 — Flawed Systems (Noninterference Violations)
```

Example Part 1 output pattern:

```text
User: Guest User (Level: Guest)
File: public_readme.txt (Required Level: Guest)
  Write : ALLOW
  Read  : [data from Guest User]
```

Example Part 2 or Part 3 output pattern:

```text
LOW observer : Guest User (Level: Guest)
HIGH writer  : System Admin (Level: Admin)
File         : public_readme.txt (Required Level: Guest)
Noninterference: HOLDS
```

Expected high-level results include:

- Part 1 shows which users can read/write each file.
- Part 2 should show the secure baseline, where high-level actions remain invisible to low-level users.
- Part 3 shows flawed systems where high-level activity may leak through direct content changes, shared error counters, or shared file-size metadata.
- Secure cases print `HOLDS`.
- Leaking cases print `BROKEN`.

---

## Troubleshooting

### `python3: command not found`

Try using:

```bash
python script_name.py
```

instead of:

```bash
python3 script_name.py
```

### Output is very long

The noninterference script prints many test cases. To save the output to a text file, run:

```bash
python3 non_interference_test.py > noninterference_output.txt
```

You can do the same for the other scripts:

```bash
python3 Chinesewall_test.py > chinesewall_output.txt
python3 lbac_test.py > lbac_output.txt
```

---

## Summary

These scripts provide simple test implementations of three confidentiality models:

- The **Chinese Wall Model** prevents conflicts of interest by blocking access to competing companies within the same conflict class.
- The **LBAC script** shows how access decisions work in a privilege lattice and compares practical access control with Bell-LaPadula confidentiality rules.
- The **Noninterference script** verifies whether high-level actions remain invisible to low-level users and demonstrates how implementation flaws can break confidentiality.

Together, these scripts show how different confidentiality models evaluate access requests, why each model is best suited for different types of confidentiality problems, and how confidentiality can still fail when information flows through unintended channels.
