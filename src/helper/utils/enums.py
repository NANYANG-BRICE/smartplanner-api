from enum import Enum

class AppEnvironment(str, Enum):
    development = "development"
    production = "production"
    entretien = "entretien"