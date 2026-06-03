"""
Chinese Wall Model Access-Control Simulation 
- this is a condidentiality model which works on the principle of conflict of interest classes to ensure confidentiality in environments.

Our idea: 
- A user may access data from one company inside a conflict class.
- After accessing one company's confidential data,
  the user cannot access confidential data from competing companies
  within the same conflict class.

Public information is always accessible.
"""

from dataclasses import dataclass, field


@dataclass
class User:
    name: str
    accessed_companies: set = field(default_factory=set)


@dataclass
class CompanyFile:
    filename: str
    company: str
    conflict_class: str
    classification: str  # "Public" or "Confidential"


def can_access_chinese_wall(user, file, action):
    """
    Access control logic assumed:
    1. Public files are always accessible.
    2. Confidential files:
       - A user can access the file if they have never accessed
         another competing company in the same conflict class.
       - OR if they already accessed the SAME company before.

    3. Write operations are allowed only if read access is allowed.
    """

    # Public information is always allowed
    if file.classification == "Public":
        return True

    # Checking previous accesses for conflicts
    for accessed_company, accessed_class in user.accessed_companies:
        # Conflict occurs if:Same conflict class, Different company
        if (
            accessed_class == file.conflict_class
            and accessed_company != file.company
        ):
            return False

    return True


def record_access(user, file):
    """
    Stores the company/conflict-class pair after successful access.
    """
    user.accessed_companies.add(
        (file.company, file.conflict_class)
    )


def run_tests():

    # Users
    users = [
        User("Alice"),
        User("Bob")
    ]

    # Files from different competing companies
    files = [
        CompanyFile(
            "google_strategy.docx",
            "Google",
            "Technology",
            "Confidential"
        ),

        CompanyFile(
            "microsoft_budget.xlsx",
            "Microsoft",
            "Technology",
            "Confidential"
        ),

        CompanyFile(
            "pfizer_research.pdf",
            "Pfizer",
            "Healthcare",
            "Confidential"
        ),

        CompanyFile(
            "public_news.txt",
            "Public",
            "General",
            "Public"
        )
    ]

    actions = ["read", "write"]

    print("Chinese Wall Model Access-Control Simulation\n")
    print("-" * 110)

    # Simulated access sequence
    access_requests = [

        # Alice first accesses Google
        (users[0], files[0], "read"),

        # Alice now tries Microsoft (same conflict class -> DENY)
        (users[0], files[1], "read"),

        # Alice accesses Pfizer (different conflict class -> ALLOW)
        (users[0], files[2], "read"),

        # Alice accesses public file (always ALLOW)
        (users[0], files[3], "read"),

        # Bob accesses Microsoft first
        (users[1], files[1], "read"),

        # Bob tries Google afterward (same conflict class -> DENY)
        (users[1], files[0], "write"),

        # Bob accesses Healthcare company (ALLOW)
        (users[1], files[2], "write")
    ]

    for user, file, action in access_requests:

        result = can_access_chinese_wall(user, file, action)

        # Record successful confidential access
        if result and file.classification == "Confidential":
            record_access(user, file)

        print(
            f"User: {user.name}\n"
            f"Action: {action}\n"
            f"File: {file.filename}\n"
            f"Company: {file.company}\n"
            f"Conflict Class: {file.conflict_class}\n"
            f"Classification: {file.classification}\n"
            f"Access Result: {'ALLOW' if result else 'DENY'}\n"
            f"Previously Accessed: {user.accessed_companies}\n"
        )

    print("-" * 110)


if __name__ == "__main__":
    run_tests()