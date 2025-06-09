from enum import Enum

class AppEnvironment(str, Enum):
    development = "development"
    production = "production"
    entretien = "entretien"
    
class RoleEnum(str, Enum):
    ADMIN = "admin"
    STUDENT = "student"
    TEACHER = "teacher"
    VISITOR = "visitor"

    
class PermissionEnum(str, Enum):
    # Users
    READ_USERS = "read_users"
    WRITE_USERS = "write_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    MANAGE_USER_PERMISSIONS = "manage_user_permissions"
    UPLOAD_USER_PHOTO = "upload_user_photo"

    # Roles
    READ_ROLES = "read_roles"
    WRITE_ROLES = "write_roles"
    UPDATE_ROLES = "update_roles"
    DELETE_ROLES = "delete_roles"
    MANAGE_ROLE_PERMISSIONS = "manage_role_permissions"

    # Permissions
    READ_PERMISSIONS = "read_permissions"
    WRITE_PERMISSIONS = "write_permissions"
    UPDATE_PERMISSIONS = "update_permissions"
    DELETE_PERMISSIONS = "delete_permissions"

    # Authentication
    LOGIN = "login"
    RESET_PASSWORD = "reset_password"

    # OTP
    CREATE_OTP = "create_otp"
    VERIFY_OTP = "verify_otp"

    # Teachers
    READ_TEACHERS = "read_teachers"
    WRITE_TEACHERS = "write_teachers"
    UPDATE_TEACHERS = "update_teachers"
    DELETE_TEACHERS = "delete_teachers"
    MANAGE_TEACHER_DEPARTEMENTS = "manage_teacher_departements"
    MANAGE_TEACHER_COURS = "manage_teacher_cours"

    # Teacher Availabilities
    READ_AVAILABILITIES = "read_availabilities"
    WRITE_AVAILABILITIES = "write_availabilities"
    UPDATE_AVAILABILITIES = "update_availabilities"
    DELETE_AVAILABILITIES = "delete_availabilities"

    # Students
    READ_STUDENTS = "read_students"
    WRITE_STUDENTS = "write_students"
    UPDATE_STUDENTS = "update_students"
    DELETE_STUDENTS = "delete_students"

    # Schools
    READ_SCHOOLS = "read_schools"
    WRITE_SCHOOLS = "write_schools"
    UPDATE_SCHOOLS = "update_schools"
    DELETE_SCHOOLS = "delete_schools"
    MANAGE_SCHOOL_TEACHERS = "manage_school_teachers"

    # Departements
    READ_DEPARTEMENTS = "read_departements"
    WRITE_DEPARTEMENTS = "write_departements"
    UPDATE_DEPARTEMENTS = "update_departements"
    DELETE_DEPARTEMENTS = "delete_departements"

    # Sections
    READ_SECTIONS = "read_sections"
    WRITE_SECTIONS = "write_sections"
    UPDATE_SECTIONS = "update_sections"
    DELETE_SECTIONS = "delete_sections"
    MANAGE_SECTION_FILIERES = "manage_section_filieres"

    # Filieres
    READ_FILIERES = "read_filieres"
    WRITE_FILIERES = "write_filieres"
    UPDATE_FILIERES = "update_filieres"
    DELETE_FILIERES = "delete_filieres"
    MANAGE_FILIERE_SECTIONS = "manage_filiere_sections"

    # Specialites
    READ_SPECIALITES = "read_specialites"
    WRITE_SPECIALITES = "write_specialites"
    UPDATE_SPECIALITES = "update_specialites"
    DELETE_SPECIALITES = "delete_specialites"
    MANAGE_SPECIALITE_CYCLES = "manage_specialite_cycles"

    # Cycles
    READ_CYCLES = "read_cycles"
    WRITE_CYCLES = "write_cycles"
    UPDATE_CYCLES = "update_cycles"
    DELETE_CYCLES = "delete_cycles"
    MANAGE_CYCLE_SPECIALITES = "manage_cycle_specialites"

    # Cours
    READ_COURS = "read_cours"
    WRITE_COURS = "write_cours"
    UPDATE_COURS = "update_cours"
    DELETE_COURS = "delete_cours"

    # Classes
    READ_CLASSES = "read_classes"
    WRITE_CLASSES = "write_classes"
    UPDATE_CLASSES = "update_classes"
    DELETE_CLASSES = "delete_classes"
    MANAGE_CLASSE_COURS = "manage_classe_cours"

    # Salles
    READ_SALLES = "read_salles"
    WRITE_SALLES = "write_salles"
    UPDATE_SALLES = "update_salles"
    DELETE_SALLES = "delete_salles"

    # Occupations
    READ_OCCUPATIONS = "read_occupations"
    WRITE_OCCUPATIONS = "write_occupations"
    UPDATE_OCCUPATIONS = "update_occupations"
    DELETE_OCCUPATIONS = "delete_occupations"

    # Ressources
    READ_RESSOURCES = "read_ressources"
    WRITE_RESSOURCES = "write_ressources"
    UPDATE_RESSOURCES = "update_ressources"
    DELETE_RESSOURCES = "delete_ressources"
    MANAGE_RESSOURCE_COURS = "manage_ressource_cours"

    # Evenements
    READ_EVENEMENTS = "read_evenements"
    WRITE_EVENEMENTS = "write_evenements"
    UPDATE_EVENEMENTS = "update_evenements"
    DELETE_EVENEMENTS = "delete_evenements"

    # Reservations
    READ_RESERVATIONS = "read_reservations"
    WRITE_RESERVATIONS = "write_reservations"
    UPDATE_RESERVATIONS = "update_reservations"
    DELETE_RESERVATIONS = "delete_reservations"
    MANAGE_RESERVATION_RESSOURCES = "manage_reservation_ressources"

    # Plannings
    GENERATE_PLANNING = "generate_planning"
    READ_PLANNING = "read_planning"
    READ_HISTORICAL_PLANNINGS = "read_historical_plannings"
    


    

DEFAULT_ROLE_PERMISSIONS = {
    RoleEnum.ADMIN: [perm for perm in PermissionEnum],  # Toutes les permissions

    RoleEnum.TEACHER: [
        PermissionEnum.READ_USERS,
        PermissionEnum.UPDATE_USERS,
        PermissionEnum.UPLOAD_USER_PHOTO,

        PermissionEnum.READ_TEACHERS,
        PermissionEnum.UPDATE_TEACHERS,

        PermissionEnum.READ_COURS,
        PermissionEnum.READ_CLASSES,
        PermissionEnum.READ_SALLES,
        PermissionEnum.READ_OCCUPATIONS,
        PermissionEnum.READ_SCHOOLS,
        PermissionEnum.READ_PLANNING,

        PermissionEnum.READ_RESERVATIONS,
        PermissionEnum.WRITE_RESERVATIONS,
        PermissionEnum.UPDATE_RESERVATIONS,
        PermissionEnum.DELETE_RESERVATIONS,
        PermissionEnum.MANAGE_RESERVATION_RESSOURCES,

        PermissionEnum.READ_AVAILABILITIES,
        PermissionEnum.WRITE_AVAILABILITIES,
        PermissionEnum.UPDATE_AVAILABILITIES,
        PermissionEnum.DELETE_AVAILABILITIES,
    ],

    RoleEnum.STUDENT: [
        PermissionEnum.READ_USERS,
        PermissionEnum.UPDATE_USERS,
        PermissionEnum.UPLOAD_USER_PHOTO,

        PermissionEnum.READ_SCHOOLS,
        PermissionEnum.READ_TEACHERS,
        PermissionEnum.READ_COURS,
        PermissionEnum.READ_CLASSES,
        PermissionEnum.READ_SALLES,
        PermissionEnum.READ_PLANNING,

        PermissionEnum.READ_RESERVATIONS,
        PermissionEnum.WRITE_RESERVATIONS,
        PermissionEnum.UPDATE_RESERVATIONS,
        PermissionEnum.DELETE_RESERVATIONS,
        PermissionEnum.MANAGE_RESERVATION_RESSOURCES,
    ],

    RoleEnum.VISITOR: [
        PermissionEnum.READ_USERS,
        PermissionEnum.READ_SCHOOLS,
        PermissionEnum.READ_TEACHERS,
        PermissionEnum.READ_COURS,
        PermissionEnum.READ_CLASSES,
        PermissionEnum.READ_SALLES,
    ]
}
    
class GenderEnum(str, Enum):
    MALE = "Masculin"
    FEMALE = "Femninin"
    OTHER = "other"
    

class TypeEtablissement(str, Enum):
    # Universités
    UNIVERSITE_PUBLIQUE = "université publique"
    UNIVERSITE_PRIVEE = "université privée"
    UNIVERSITE_INTERNATIONALE = "université internationale"
    UNIVERSITE_TECHNOLOGIQUE = "université technologique"
    UNIVERSITE_POLYTECHNIQUE = "université polytechnique"
    UNIVERSITE_A_DISTANCE = "université à distance"
    UNIVERSITE_CONFESSIONNELLE = "université confessionnelle"

    # Instituts
    INSTITUT_DE_TECHNOLOGIE = "institut de technologie"
    INSTITUT_DE_FORMATION_PROFESSIONNELLE = "institut de formation professionnelle"
    INSTITUT_DES_SCIENCES_APPLIQUEES = "institut des sciences appliquées"
    INSTITUT_DE_COMMERCE = "institut de commerce"
    INSTITUT_DE_GESTION = "institut de gestion"
    INSTITUT_D_AGRICULTURE = "institut d’agriculture"
    INSTITUT_D_INFORMATIQUE = "institut d’informatique"
    INSTITUT_DES_SCIENCES_DE_LA_SANTE = "institut des sciences de la santé"
    INSTITUT_DE_TRADUCTION_ET_INTERPRETATION = "institut de traduction et d’interprétation"
    INSTITUT_D_ETUDES_RELIGIEUSES = "institut d’études religieuses"

    # Grandes écoles / Écoles spécialisées
    ECOLE_NORMALE_SUPERIEURE = "école normale supérieure"
    ECOLE_NATIONALE_D_ADMINISTRATION = "école nationale d’administration"
    ECOLE_NATIONALE_POLYTECHNIQUE = "école nationale polytechnique"
    ECOLE_DE_COMMERCE = "école de commerce"
    ECOLE_D_INGENIEURS = "école d’ingénieurs"
    ECOLE_DE_JOURNALISME = "école de journalisme"
    ECOLE_D_ARCHITECTURE = "école d’architecture"
    ECOLE_D_ART_ET_DE_DESIGN = "école d’art et de design"
    ECOLE_DE_CINEMA_ET_DES_MEDIAS = "école de cinéma et des médias"
    ECOLE_DE_MUSIQUE_ET_DE_DANSE = "école de musique et de danse"
    ECOLE_DE_DROIT = "école de droit"
    FACULTE_DE_MEDECINE = "faculté de médecine"
    FACULTE_DE_PHARMACIE = "faculté de pharmacie"
    ECOLE_DE_SANTE_PUBLIQUE = "école de santé publique"
    ECOLE_VETERINAIRE = "école vétérinaire"
    ACADEMIE_MILITAIRE = "académie militaire"

    # Centres techniques et professionnels
    CENTRE_DE_FORMATION_PROFESSIONNELLE = "centre de formation professionnelle"
    CENTRE_TECHNOLOGIQUE = "centre technologique"
    CENTRE_AGRICOLE = "centre agricole"
    CENTRE_DE_FORMATION_MARITIME = "centre de formation maritime"
    CENTRE_DE_MAINTENANCE_INDUSTRIELLE = "centre de maintenance industrielle"

    # Autres types
    COLLEGE_UNIVERSITAIRE = "collège universitaire"
    ACADEMIE_DES_SCIENCES = "académie des sciences"
    ACADEMIE_DES_BEUX_ARTS = "académie des beaux-arts"
    SEMINAIRE_THEOLOGIQUE = "séminaire théologique"
    UNIVERSITE_BILINGUE = "université bilingue"
    ETABLISSEMENT_PUBLIC_PRIVE = "établissement public-privé"
    UNIVERSITE_COMMUNAUTAIRE = "université communautaire"
    UNIVERSITE_OUVERTE = "université ouverte"

class SectionEnum(Enum):
    FRANCOPHONE = "Francophone"
    ANGLOPHONE = "Anglophone"
    BILINGUE = "Bilingue"  # Si pertinent

class CycleEnum(str, Enum):
    LICENCE = "licence"
    MASTER = "master"
    INGENIEUR = "ingénieur"
    DOCTORAT = "doctorat"
    BTS = "bts"
    
    
class TypeSalleEnum(str, Enum):
    SALLE_DE_CLASSE = "Salle de classe"
    SALLE_INFORMATIQUE = "Salle informatique"
    SALLE_DE_CONFERENCE = "Salle de conférence"
    SALLE_DE_TP = "Salle de TP"
    SALLE_DE_REUNION = "Salle de réunion"
    SALLE_DE_SPORT = "Salle de sport"
    SALLE_DE_MUSIQUE = "Salle de musique"
    AMPHITHEATRE = "Amphithéâtre"
    SALLE_DE_DETENTE = "Salle de détente"
    BIBLIOTHEQUE = "Bibliothèque"
    SALLE_DE_SIMULATION = "Salle de simulation"


class StudentCoursStatusEnum(Enum):
    INSCRIT = "Inscrit"
    EXCLU = "Exclu"
    EXEMPTE = "Exempté"
    
    
class TypeCourEnum(str, Enum):
    COURS_MAGISTRAL = "Cours magistral"
    SEMINAIRE = "Séminaire"
    TD = "Travaux dirigés"
    TP = "Travaux pratiques"
    COURS_EN_LIGNE = "Cours en ligne (MOOC)"
    FORMATION_CONTINUE = "Formation continue"
    DEVELOPPEMENT_PERSONNEL = "Ateliers de développement personnel"
    CERTIFICATIONS_PROFESSIONNELLES = "Certifications professionnelles"
    E_LEARNING = "E-learning"
    WEBINAIRE = "Webinaire"
    COURS_EN_STREAMING = "Cours en streaming"
    PREPARATION_EXAMEN = "Cours de préparation aux examens"
    COURS_PRATIQUES = "Cours pratiques"
    REMISE_A_NIVEAU = "Cours de remise à niveau"
    ALTERNANCE = "Cours en alternance"
    SOUTIEN_SCOLAIRE = "Cours de soutien scolaire"
    EVEIL = "Cours d’éveil"
    COURS_DE_LANGUES = "Cours de langues"
    COURS_INTENSIFS = "Cours intensifs"
    BOOTCAMP = "Bootcamp"
    IMMERSION = "Cours en immersion"
    COURS_PARTICULIERS = "Cours particuliers"
    COACHING = "Coaching" 
    
    
class WeekdayEnum(str, Enum):
    MONDAY = "Lundi"
    TUESDAY = "Mardi"
    WEDNESDAY = "Mercredi"
    THURSDAY = "Jeudi"
    FRIDAY = "Vendredi"
    SATURDAY = "Samedi"
    

class ReservationStatusEnum(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
    IN_PROGRESS = "IN_PROGRESS"
    WAITLISTED = "WAITLISTED"
    
class ResourceTypeEnum(str, Enum):
    LIVRE = "LIVRE"
    MATERIEL = "MATERIEL"
    NUMERIQUE = "NUMERIQUE"
    FOURNITURE = "FOURNITURE"
    
class EventTypeEnum(str, Enum):
    COURS = "Cours"
    TD = "Travaux Dirigés"
    TP = "Travaux Pratiques"
    EXAMEN = "Examen"
    SOUTENANCE = "Soutenance"
    SEMESTRE = "Semestre"
    RATTRAPAGE = "Rattrapage"
    CONFÉRENCE = "Conférence"
    REUNION = "Réunion"
    WORKSHOP = "Workshop"
    SEMINAIRE = "Séminaire"
    FORMATION = "Formation"
    WEBINAIRE = "Webinaire"
    TABLE_RONDE = "Table Ronde"
    CULTUREL = "Événement Culturel"
    FESTIVAL = "Festival"
    SOIREE = "Soirée"
    COCKTAIL = "Cocktail"
    GALA = "Gala"
    MATCH = "Match"
    TOURNOI = "Tournoi"
    JOURNEE_SPORTIVE = "Journée Sportive"
    STAGE_SPORTIF = "Stage Sportif"
    PARRAINAGE = "Parrainage"
    CEREMONIE = "Cérémonie"
    CAMPAGNE_SENSIBILISATION = "Campagne de Sensibilisation"
    EXPOSITION = "Exposition"
    FOIRE = "Foire"
    CONFÉRENCE_WEB = "Conférence Web"
    INTEGRATION = "Journée de l'intégration"

    # Examens
    EXAMEN_CC = "Contrôle Continu"  # Contrôles continus
    EXAMEN_MEDIAN = "Examen Médian"  # Examen médian
    EXAMEN_SESSION1 = "Examen Session 1"  # Session normale du semestre 1
    EXAMEN_SESSION2 = "Examen Session 2"  # Session normale du semestre 2