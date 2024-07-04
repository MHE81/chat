from enum import Enum

class Role(Enum):
    SUPER_ADMIN = "super admin"
    ADMIN = "admin"
    ADVANCED_USER = "advanced user"
    BEGINNER_USER = "beginner user"

# استخراج لیست مقادیر Enum
role_values = [role.value for role in Role]
print(role_values)
