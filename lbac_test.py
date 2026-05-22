"""
Real-World Lattice-Based Access Control (LBAC) Example

This script models access control for computer files using user privilege levels:
Guest < Standard User < Power User < Admin

It also compares the behavior to Bell-LaPadula-style confidentiality rules.
"""

from dataclasses import dataclass


# Ordered privilege lattice from lowest to highest
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


def dominates(level_a: str, level_b: str) -> bool:
    """
    Returns True if level_a is greater than or equal to level_b.
    For example:
    Admin dominates Guest.
    Power User dominates Standard User.
    Guest does not dominate Admin.
    """
    return SECURITY_LEVELS[level_a] >= SECURITY_LEVELS[level_b]


def can_access_lbac(user, file, action, policy="practical"):
    """
    LBAC can be configured to behave like Bell-LaPadula,
    but it can also be configured like a practical computer privilege system.

    1) LBAC-style access control using practical access-control interpretation, similar to how
    operating systems often restrict protected files. Higher-level users can both read and write 
    lower-level files (common in normal computer systems).

    2) LBAC-style access control using Bell-LaPadula confidentiality configurations 
        (since Bell-LaPadula is a TYPE of LBAC model) that focuses on preventing information leaks:
        - No Read Up: users cannot read files above their level.
        - No Write Down: users cannot write to files below their level. 
        So, high-level users should not write sensitive information into lower-level files.

    """
    if policy == "confidentiality":
        # Similar to Bell-LaPadula
        if action == "read":
            return dominates(user.level, file.required_level)   # No read up
        elif action == "write":
            return dominates(file.required_level, user.level)   # No write down
        else:
            raise ValueError("Action must be 'read' or 'write'.")

    elif policy == "practical":
        # Similar to normal computer admin permissions
        if action in ["read", "write"]:
            return dominates(user.level, file.required_level)
        else:
            raise ValueError("Action must be 'read' or 'write'.")

    else:
        raise ValueError("Unknown policy.")
    

def run_tests():
    users = [
        User("Guest User", "Guest"),
        User("Iman", "Standard User"),
        User("Developer", "Power User"),
        User("System Admin", "Admin")
    ]

    files = [
        ComputerFile("public_readme.txt", "Guest"),
        ComputerFile("user_notes.txt", "Standard User"),
        ComputerFile("project_source_code.py", "Power User"),
        ComputerFile("system_config.conf", "Admin")
    ]

    actions = ["read", "write"]

    print("Real-World LBAC vs. Bell-LaPadula Access Test\n")
    print("-" * 110)

    for user in users:
        for file in files:
            for action in actions:
                lbac_result = can_access_lbac(user, file, action) #default policy argument will be "practical" or normal computer admin permissions
                blp_result = can_access_lbac(user, file, action, "confidentiality") #policy argument = "confidentiality" or Bell-LaPadula model

                print(
                    f"User: {user.name:13} ({user.level:13}) | "
                    f"Action: {action:5} | "
                    f"File: {file.filename:24} ({file.required_level:13}) | "
                    f"LBAC: {'ALLOW' if lbac_result else 'DENY':5} | "
                    f"BLP: {'ALLOW' if blp_result else 'DENY':5}"
                )

    print("-" * 110)


if __name__ == "__main__":
    run_tests()
