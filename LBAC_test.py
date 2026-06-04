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
        - Admin dominates Guest.
        - Power User dominates Standard User.
        - Guest does not dominate Admin.
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
    # Created a list of test users with different security/privilege levels.
    users = [
        User("Guest User", "Guest"),  # Guest-level user with the lowest access level.
        User("Iman", "Standard User"), # Standard user with a medium-low access level.
        User("Developer", "Power User"), # Power user with a medium-high access level.
        User("System Admin", "Admin") # Admin user with the highest access level.
    ]

    # Created a list of test files with different required security levels.
    files = [
        ComputerFile("public_readme.txt", "Guest"), # Public file that only requires Guest-level access.
        ComputerFile("user_notes.txt", "Standard User"), # User file that requires Standard User-level access.
        ComputerFile("project_source_code.py", "Power User"), # Source Code file that requires Power User-level access.
        ComputerFile("system_config.conf", "Admin") # System configuration file that requires Admin-level access.
    ]

    # Created a list of actions that each user will attempt on each file.
    actions = ["read", "write"]


    print("Real-World LBAC vs. Bell-LaPadula Access Test\n") #Title of output
    print("-" * 110) # Prints a divider line to make the output easier to read.

    for user in users:
        for file in files:
            for action in actions:
                # Checks access using the default LBAC policy, which is the practical policy.
                # This models normal computer permissions, where higher-level users can access lower-level files.
                lbac_result = can_access_lbac(user, file, action) #default policy argument will be "practical" or normal computer admin permissions
                
                # Checks access using the confidentiality policy.
                # This models Bell-LaPadula rules: No Read Up and No Write Down.
                blp_result = can_access_lbac(user, file, action, "confidentiality") ## policy argument = "confidentiality", which makes LBAC behave like the Bell-LaPadula model

                # Prints the access-control result for the current user, file, and action.
                print(
                    f"User: {user.name} (Security Level: {user.level})\n"
                    f"Action: {action}\n"
                    f"File: {file.filename} (Security Level: {file.required_level})\n"
                    f"LBAC: {'ALLOW' if lbac_result else 'DENY'}\n"
                    f"BLP: {'ALLOW' if blp_result else 'DENY'}\n"
                )
           
    print("-" * 110) # Prints a final divider line after all test results are shown.
    


if __name__ == "__main__":
    run_tests()
