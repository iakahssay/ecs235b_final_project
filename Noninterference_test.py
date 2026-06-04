"""
Real world Noninterference Confidentiality Model Example

This script models access control for computer files using the noninterference model.

Noninterference guarantees that HIGH-level users actions are  invisible
to LOW level users. A LOW level user should observe the exact same system outputs
irrespective of what HIGH-level users have done.

User privilege levels used (same as lbac_test.py):
    Guest < Standard User < Power User < Admin

PART 3 demonstrates three realistic flaws that each break noninterference:
    Flaw A — Downward write leak:   HIGH writes bleed into LOW-level file views.
    Flaw B — Shared error channel:  a failed HIGH write changes a visible error counter.
    Flaw C — File-size side channel: LOW user can observe whether a HIGH write occurred
                                     by checking a shared file-size metadata field.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import copy


SECURITY_LEVELS = {
    "Guest": 0,
    "Standard User": 1,
    "Power User": 2,
    "Admin": 3
}


@dataclass
class User:
    name: str
    level: str


@dataclass
class ComputerFile:
    filename: str
    required_level: str


# ---------------------------------------------------------------------------
# Secure SystemState  (HOLDS in all cases)
# ---------------------------------------------------------------------------

@dataclass
class SystemState:
    """
    Simulates the observable state of the system for each security level.

    Each level has its own isolated view of file contents. A write by a HIGH-level
    user affects views at that level or above and LOW level views are never
    altered and this enforces noninterference.
    """
    contents: dict = field(default_factory=dict)

    def initialize(self, files: list):
        """Seed every file with a default value visible at every level."""
        for f in files:
            for level in SECURITY_LEVELS:
                self.contents[(f.filename, level)] = f"[default content of {f.filename}]"

    def write(self, user: User, file: ComputerFile, data: str) -> bool:
        """
        A user may write to a file only when their level meets or exceeds the
        file's required level (no write-down).  The write is then propagated
        upward — every level at or above the writer's level sees the new value —
        but lower levels are left untouched, so their view of the system is
        unaffected by higher-privilege activity.
        """
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return False  # Denied: user lacks sufficient privilege.

        # Propagate the write to this level and every level above it.
        for level, rank in SECURITY_LEVELS.items():
            if rank >= SECURITY_LEVELS[user.level]:
                self.contents[(file.filename, level)] = data
        return True

    def read(self, user: User, file: ComputerFile) -> str | None:
        """
        A user may read a file only when their level meets or exceeds the
        file's required level (no read-up). They see the version of the
        content that was written at their own level or below and never content
        that leaked from a higher level.
        """
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return None  # Denied: user lacks sufficient privilege.

        return self.contents.get(
            (file.filename, user.level),
            f"[default content of {file.filename}]"
        )


# ---------------------------------------------------------------------------
# Flaw A — Downward write leak
# Bug: HIGH writes are incorrectly propagated to ALL levels, including lower ones.
# ---------------------------------------------------------------------------

@dataclass
class FlawedStateA:
    """
    Flaw A: write() propagates to every level instead of upward only.
    A LOW-level user can directly read content written by a HIGH-level user.
    """
    contents: dict = field(default_factory=dict)

    def initialize(self, files: list):
        for f in files:
            for level in SECURITY_LEVELS:
                self.contents[(f.filename, level)] = f"[default content of {f.filename}]"

    def write(self, user: User, file: ComputerFile, data: str) -> bool:
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return False
        # BUG: propagates downward too — all levels see the HIGH write.
        for level in SECURITY_LEVELS:
            self.contents[(file.filename, level)] = data
        return True

    def read(self, user: User, file: ComputerFile) -> str | None:
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return None
        return self.contents.get(
            (file.filename, user.level),
            f"[default content of {file.filename}]"
        )


# ---------------------------------------------------------------------------
# Flaw B — Shared error counter side channel
# Bug: a denied HIGH write still increments a global error counter visible to all.
# ---------------------------------------------------------------------------

@dataclass
class FlawedStateB:
    """
    Flaw B: every denied write, including those by HIGH users on files above them —
    increments a shared error counter that any user can read.  A LOW observer can
    infer HIGH activity by watching the counter change.
    """
    contents: dict = field(default_factory=dict)
    denied_write_counter: int = 0   # shared, visible to everyone — the leak

    def initialize(self, files: list):
        for f in files:
            for level in SECURITY_LEVELS:
                self.contents[(f.filename, level)] = f"[default content of {f.filename}]"

    def write(self, user: User, file: ComputerFile, data: str) -> bool:
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            # BUG: leaks that a write was attempted via the shared counter.
            self.denied_write_counter += 1
            return False
        for level, rank in SECURITY_LEVELS.items():
            if rank >= SECURITY_LEVELS[user.level]:
                self.contents[(file.filename, level)] = data
        return True

    def read(self, user: User, file: ComputerFile) -> str | None:
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return None
        return self.contents.get(
            (file.filename, user.level),
            f"[default content of {file.filename}]"
        )

    def observe(self) -> int:
        """LOW-visible observation: the shared denied-write counter."""
        return self.denied_write_counter


# ---------------------------------------------------------------------------
# Flaw C — File-size metadata side channel
# Bug: a single shared file-size field is updated on every write, regardless of level.
# ---------------------------------------------------------------------------

@dataclass
class FlawedStateC:
    """
    Flaw C: file size metadata is stored in one shared slot per file (not per level).
    When a HIGH user writes, the size changes and a LOW user can observe it,
    revealing that a HIGH-level write occurred even though the content is hidden.
    """
    contents: dict = field(default_factory=dict)
    file_sizes: dict = field(default_factory=dict)   # shared across all levels — the leak

    def initialize(self, files: list):
        for f in files:
            for level in SECURITY_LEVELS:
                default = f"[default content of {f.filename}]"
                self.contents[(f.filename, level)] = default
            # BUG: one shared size entry per file, not per (file, level).
            self.file_sizes[f.filename] = len(f"[default content of {f.filename}]")

    def write(self, user: User, file: ComputerFile, data: str) -> bool:
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return False
        for level, rank in SECURITY_LEVELS.items():
            if rank >= SECURITY_LEVELS[user.level]:
                self.contents[(file.filename, level)] = data
        # BUG: updates a shared size field that every level can observe.
        self.file_sizes[file.filename] = len(data)
        return True

    def read(self, user: User, file: ComputerFile) -> str | None:
        if SECURITY_LEVELS[user.level] < SECURITY_LEVELS[file.required_level]:
            return None
        return self.contents.get(
            (file.filename, user.level),
            f"[default content of {file.filename}]"
        )

    def get_size(self, file: ComputerFile) -> int:
        """LOW-visible observation: the shared file-size field."""
        return self.file_sizes.get(file.filename, 0)


# ---------------------------------------------------------------------------
# Noninterference checkers — one per state variant
# ---------------------------------------------------------------------------

def noninterference_holds(low_user: User, high_user: User,
                           file: ComputerFile, state: SystemState) -> bool:
    """Secure baseline: compares LOW read observations across two scenarios."""
    state_a = copy.deepcopy(state)
    state_a.write(high_user, file, f"[SECRET data written by {high_user.name}]")
    obs_a = state_a.read(low_user, file)

    state_b = copy.deepcopy(state)
    obs_b = state_b.read(low_user, file)

    return obs_a == obs_b


def noninterference_flaw_a(low_user: User, high_user: User,
                            file: ComputerFile, state: FlawedStateA) -> bool:
    """Flaw A: checks whether a downward write leak is observable."""
    state_a = copy.deepcopy(state)
    state_a.write(high_user, file, f"[SECRET data written by {high_user.name}]")
    obs_a = state_a.read(low_user, file)

    state_b = copy.deepcopy(state)
    obs_b = state_b.read(low_user, file)

    return obs_a == obs_b


def noninterference_flaw_b(low_user: User, high_user: User,
                            file: ComputerFile, state: FlawedStateB) -> bool:
    """
    Flaw B: the LOW observation includes the denied-write counter.
    If HIGH attempted a write (even a denied one), the counter differs between
    Scenario A and Scenario B, breaking noninterference.
    """
    state_a = copy.deepcopy(state)
    state_a.write(high_user, file, f"[SECRET data written by {high_user.name}]")
    # LOW observes both the file content AND the shared error counter.
    obs_a = (state_a.read(low_user, file), state_a.observe())

    state_b = copy.deepcopy(state)
    obs_b = (state_b.read(low_user, file), state_b.observe())

    return obs_a == obs_b


def noninterference_flaw_c(low_user: User, high_user: User,
                            file: ComputerFile, state: FlawedStateC) -> bool:
    """
    Flaw C: the LOW observation includes the shared file-size field.
    If HIGH wrote to the file, the size changes and the LOW observer can detect it.
    """
    state_a = copy.deepcopy(state)
    state_a.write(high_user, file, f"[SECRET data written by {high_user.name}]")
    # LOW observes both the file content AND the shared file size.
    obs_a = (state_a.read(low_user, file), state_a.get_size(file))

    state_b = copy.deepcopy(state)
    obs_b = (state_b.read(low_user, file), state_b.get_size(file))

    return obs_a == obs_b


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_tests():
    users = [
        User("Guest User",   "Guest"),
        User("Joshua",         "Standard User"),
        User("Developer",    "Power User"),
        User("System Admin", "Admin"),
    ]

    files = [
        ComputerFile("public_readme.txt",      "Guest"),
        ComputerFile("user_notes.txt",         "Standard User"),
        ComputerFile("project_source_code.py", "Power User"),
        ComputerFile("system_config.conf",     "Admin"),
    ]

    base_state   = SystemState();   base_state.initialize(files)
    flaw_a_state = FlawedStateA();  flaw_a_state.initialize(files)
    flaw_b_state = FlawedStateB();  flaw_b_state.initialize(files)
    flaw_c_state = FlawedStateC();  flaw_c_state.initialize(files)

    print("Noninterference Confidentiality Model Test\n")
    print("=" * 100)

    # -----------------------------------------------------------------------
    # Part 1 — Read / Write access control (unchanged)
    # -----------------------------------------------------------------------
    print("\nPART 1 — Read / Write Access Control\n")
    print(
        "Each user attempts to read and write every file.\n"
        "Writes propagate upward only; reads return the level-appropriate view.\n"
    )

    for user in users:
        for file in files:
            state_copy = copy.deepcopy(base_state)
            write_ok   = state_copy.write(user, file, f"[data from {user.name}]")
            read_value = state_copy.read(user, file)
            print(
                f"User: {user.name} (Level: {user.level})\n"
                f"File: {file.filename} (Required Level: {file.required_level})\n"
                f"  Write : {'ALLOW' if write_ok else 'DENY'}\n"
                f"  Read  : {read_value if read_value is not None else 'DENY'}\n"
            )

    print("=" * 100)

    # -----------------------------------------------------------------------
    # Part 2 — Secure baseline (all HOLDS)
    # -----------------------------------------------------------------------
    print("\nPART 2 — Noninterference Property Verification (Secure Baseline)\n")
    print(
        "For every (LOW observer, HIGH writer, file) triple, we check whether\n"
        "a HIGH-level write changes what the LOW-level user can observe.\n"
        "HOLDS = HIGH activity is invisible to LOW user (secure).\n"
        "BROKEN = HIGH activity leaks information to LOW user (violation).\n"
    )

    for low_user in users:
        for high_user in users:
            if SECURITY_LEVELS[high_user.level] <= SECURITY_LEVELS[low_user.level]:
                continue
            for file in files:
                holds = noninterference_holds(low_user, high_user, file, base_state)
                print(
                    f"LOW observer : {low_user.name} (Level: {low_user.level})\n"
                    f"HIGH writer  : {high_user.name} (Level: {high_user.level})\n"
                    f"File         : {file.filename} (Required Level: {file.required_level})\n"
                    f"Noninterference: {'HOLDS' if holds else 'BROKEN'}\n"
                )

    print("=" * 100)

    # -----------------------------------------------------------------------
    # Part 3 — Flawed systems (BROKEN cases)
    # -----------------------------------------------------------------------
    print("\nPART 3 — Flawed Systems (Noninterference Violations)\n")
    print(
        "Three realistic implementation flaws are tested below.\n"
        "Each flaw introduces a channel through which HIGH activity leaks to LOW observers.\n"
    )

    flaws = [
        (
            "Flaw A — Downward Write Leak",
            "Bug: HIGH writes are propagated to ALL security levels, not just upward.\n"
            "     A LOW user can directly read content written by a HIGH user.",
            flaw_a_state,
            noninterference_flaw_a,
        ),
        (
            "Flaw B — Shared Error Counter Side Channel",
            "Bug: every denied write increments a global counter visible to all levels.\n"
            "     A LOW user can detect HIGH write attempts by watching the counter change.",
            flaw_b_state,
            noninterference_flaw_b,
        ),
        (
            "Flaw C — File-Size Metadata Side Channel",
            "Bug: file-size metadata is stored in one shared slot per file (not per level).\n"
            "     A LOW user can infer that a HIGH write occurred by observing a size change.",
            flaw_c_state,
            noninterference_flaw_c,
        ),
    ]

    for flaw_name, flaw_desc, flaw_state, checker in flaws:
        print(f"--- {flaw_name} ---")
        print(f"{flaw_desc}\n")

        for low_user in users:
            for high_user in users:
                if SECURITY_LEVELS[high_user.level] <= SECURITY_LEVELS[low_user.level]:
                    continue
                for file in files:
                    holds = checker(low_user, high_user, file, flaw_state)
                    print(
                        f"LOW observer : {low_user.name} (Level: {low_user.level})\n"
                        f"HIGH writer  : {high_user.name} (Level: {high_user.level})\n"
                        f"File         : {file.filename} (Required Level: {file.required_level})\n"
                        f"Noninterference: {'HOLDS' if holds else 'BROKEN'}\n"
                    )
        print("-" * 100 + "\n")

    print("=" * 100)


if __name__ == "__main__":
    run_tests()
