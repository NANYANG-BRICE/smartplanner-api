from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session
from api.models import *
from api.schemas import *
from api.services import *
from typing import List
from helper.database.db import get_db
from helper.utils.enums import (
    AppEnvironment, RoleEnum, PermissionEnum, GenderEnum,
    TypeEtablissement, SectionEnum, CycleEnum, TypeSalleEnum,
    StudentCoursStatusEnum, TypeCourEnum, WeekdayEnum,
    ReservationStatusEnum, ResourceTypeEnum, EventTypeEnum
)


# ============================
# Tags Routes
# ============================

permissions = APIRouter(prefix="/permissions", tags=["Permissions"])
roles = APIRouter(prefix="/roles", tags=["Roles"])
auth = APIRouter(prefix="/auth", tags=["Authentication"])
users = APIRouter(prefix="/users", tags=["Users"])
otp = APIRouter(prefix="/otp", tags=["OTP"])
departements = APIRouter(prefix="/departements", tags=["Departements"])
teachers = APIRouter(prefix="/teachers", tags=["Teachers"])
availabilities = APIRouter(prefix="/teacher-availabilities", tags=["Teacher Availabilities"])
students = APIRouter(prefix="/students", tags=["Students"])
schools = APIRouter(prefix="/schools", tags=["Schools"])
sections = APIRouter(prefix="/sections", tags=["Sections"])
filieres = APIRouter(prefix="/filieres", tags=["Filieres"])
specialites = APIRouter(prefix="/specialites", tags=["Specialites"])
cycles = APIRouter(prefix="/cycles", tags=["Cycles"])
cours = APIRouter(prefix="/cours", tags=["Cours"])
classes = APIRouter(prefix="/classes", tags=["Classes"])
salles = APIRouter(prefix="/salles", tags=["Salles"])
occupations = APIRouter(prefix="/occupations", tags=["Occupations"])
ressources = APIRouter(prefix="/ressources", tags=["Ressources"])
evenements = APIRouter(prefix="/evenements", tags=["Evenements"])
reservations = APIRouter(prefix="/reservations", tags=["Reservations"])
plannings = APIRouter(prefix="/plannings", tags=["Plannings"])
enums = APIRouter(prefix="/enums", tags=["Enums"])




# ============================
# Services Injections routes
# ============================


async def get_permission_service(db: AsyncSession = Depends(get_db)):
    return PermissionService(db)

async def get_role_service(db: AsyncSession = Depends(get_db)):
    return RoleService(db)

async def get_auth_service(db: AsyncSession = Depends(get_db)):
    return AuthenticationService(db)

async def get_user_service(db: AsyncSession = Depends(get_db)):
    return UserService(db)

async def get_otp_service(db: AsyncSession = Depends(get_db)):
    return OTPService(db)

async def get_departement_service(db: AsyncSession = Depends(get_db)):
    return DepartementService(db)

async def get_teacher_service(db: AsyncSession = Depends(get_db)):
    return TeacherService(db)

async def get_teacher_availability_service(db: AsyncSession = Depends(get_db)):
    return TeacherAvailabilityService(db)

async def get_student_service(db: AsyncSession = Depends(get_db)):
    user_service = UserService(db)
    return StudentService(db, user_service)

async def get_school_service(db: AsyncSession = Depends(get_db)):
    return SchoolService(db)

async def get_section_service(db: AsyncSession = Depends(get_db)):
    return SectionService(db)

async def get_filiere_service(db: AsyncSession = Depends(get_db)):
    return FiliereService(db)

async def get_specialite_service(db: AsyncSession = Depends(get_db)):
    return SpecialiteService(db)

async def get_cycle_service(db: AsyncSession = Depends(get_db)):
    return CycleService(db)

async def get_salle_service(db: AsyncSession = Depends(get_db)):
    return SalleService(db)

async def get_classe_service(db: AsyncSession = Depends(get_db)):
    return ClasseService(db)

async def get_cours_service(db: AsyncSession = Depends(get_db)):
    return CoursService(db)

async def get_planning_service(db: AsyncSession = Depends(get_db)):
    return PlanningService(db)

async def get_reservation_service(db: AsyncSession = Depends(get_db)):
    return ReservationService(db)

async def get_evenement_service(db: AsyncSession = Depends(get_db)):
    return EvenementService(db)

async def get_ressource_service(db: AsyncSession = Depends(get_db)):
    return RessourceService(db)

async def get_occupation_service(db: AsyncSession = Depends(get_db)):
    return OccupationService(db)

async def get_enum_service():
    return EnumService()



# ============================
# Permissions Routes
# ============================

@permissions.post("", response_model=List[Permission], summary="Create new permissions")
async def create_permissions(perms_create: List[PermissionCreate], permission_service: PermissionService = Depends(get_permission_service)):
    """Creates one or more new permissions in the system."""
    return await permission_service.create_permissions(perms_create)

@permissions.delete("", summary="Delete permissions")
async def delete_permissions(permission_ids: List[int], permission_service: PermissionService = Depends(get_permission_service)):
    """Deletes multiple permissions by their IDs."""
    permission_service.delete_permissions(permission_ids)
    return {"message": "Permissions deleted successfully"}

@permissions.get("/{permission_id}", response_model=Permission, summary="Get a permission")
async def get_permission(permission_id: int, permission_service: PermissionService = Depends(get_permission_service)):
    """Retrieves a single permission by ID."""
    return await permission_service.get_permission(permission_id)

@permissions.get("", response_model=List[Permission], summary="Get all permissions")
async def get_all_permissions(skip: int = 0, limit: int = 100, permission_service: PermissionService = Depends(get_permission_service)):
    """Retrieves a list of all permissions with pagination."""
    return await permission_service.get_all_permissions(skip=skip, limit=limit)




# ============================
# Role Routes
# ============================

@roles.post("", response_model=List[Role], summary="Create new roles")
async def create_roles(roles_create: List[RoleCreate], role_service: RoleService = Depends(get_role_service)):
    """Creates one or more new roles in the system."""
    return await role_service.create_roles(roles_create)

@roles.get("/{role_id}", response_model=Role, summary="Get a role")
async def get_role(role_id: int, role_service: RoleService = Depends(get_role_service)):
    """Retrieves a single role by ID."""
    return await role_service.get_role(role_id)

@roles.get("", response_model=List[Role], summary="Get all roles")
async def get_all_roles(skip: int = 0, limit: int = 100, role_service: RoleService = Depends(get_role_service)):
    """Retrieves a list of all roles with pagination."""
    return await role_service.get_all_roles(skip=skip, limit=limit)

@roles.delete("", summary="Delete roles")
async def delete_roles(role_ids: List[int], role_service: RoleService = Depends(get_role_service)):
    """Deletes multiple roles by their IDs."""
    role_service.delete_roles(role_ids)
    return {"message": "Roles deleted successfully"}

@roles.post("/{role_id}/permissions", response_model=Role, summary="Add permissions to role")
async def add_permissions_to_role(role_id: int, permission_ids: List[int], role_service: RoleService = Depends(get_role_service)):
    """Adds permissions to a role."""
    return await role_service.add_permissions_to_role(role_id, permission_ids)

@roles.delete("/{role_id}/permissions", response_model=Role, summary="Remove permissions from role")
async def remove_permissions_from_role(role_id: int, permission_ids: List[int], role_service: RoleService = Depends(get_role_service)):
    """Removes permissions from a role."""
    return await role_service.remove_permissions_from_role(role_id, permission_ids)




# ============================
# Authentication Routes
# ============================

@auth.post("/login", response_model=Token, summary="Login")
async def login(credentials: AuthenticateUserRequest, auth_service: AuthenticationService = Depends(get_auth_service)):
    """Authenticates a user and returns a JWT token."""
    return await auth_service.authenticate_user(credentials.identifier, credentials.password)

@auth.post("/reset-password", summary="Reset password")
async def reset_password(reset_request: ResetPasswordRequest, auth_service: AuthenticationService = Depends(get_auth_service)):
    """Resets a user's password and sends a new password via email."""
    auth_service.reset_password(reset_request.email)
    return {"message": "Password reset email sent"}




# ============================
# Users Routes
# ============================

@users.post("/{user_id}/photo", response_model=str, summary="Upload user photo")
async def upload_user_photo(user_id: int, file: UploadFile = File(...), user_service: UserService = Depends(get_user_service)):
    """Uploads a profile photo for a user."""
    return await user_service.upload_user_photo(user_id, file)

@users.post("", response_model=User, summary="Create a user")
async def create_user(user_create: UserCreate, user_service: UserService = Depends(get_user_service)):
    """Creates a new user with a generated password."""
    return await user_service.create_user(user_create)

@users.get("/{user_id}", response_model=User, summary="Get a user")
async def get_user(user_id: int, user_service: UserService = Depends(get_user_service)):
    """Retrieves a single user by ID."""
    return await user_service.get_user(user_id)

@users.get("", response_model=List[User], summary="Get all users")
async def get_all_users(skip: int = 0, limit: int = 100, user_service: UserService = Depends(get_user_service)):
    """Retrieves a list of all users with pagination."""
    return await user_service.get_all_users(skip=skip, limit=limit)

@users.put("/{user_id}", response_model=User, summary="Update a user")
async def update_user(user_id: int, user_update: UserUpdate, user_service: UserService = Depends(get_user_service)):
    """Updates an existing user."""
    return await user_service.update_user(user_id, user_update)

@users.delete("/{user_id}", summary="Delete a user")
async def delete_user(user_id: int, user_service: UserService = Depends(get_user_service)):
    """Deletes a user by ID."""
    user_service.delete_user(user_id)
    return {"message": "User deleted successfully"}

@users.post("/{user_id}/permissions", response_model=User, summary="Add permissions to user")
async def add_permissions_to_user(user_id: int, permission_ids: List[int], user_service: UserService = Depends(get_user_service)):
    """Adds extra permissions to a user."""
    return await user_service.add_permissions_to_user(user_id, permission_ids)

@users.delete("/{user_id}/permissions", response_model=User, summary="Remove permissions from user")
async def remove_permissions_from_user(user_id: int, permission_ids: List[int], user_service: UserService = Depends(get_user_service)):
    """Removes extra permissions from a user."""
    return await user_service.remove_permissions_from_user(user_id, permission_ids)




# ============================
# OTP Routes
# ============================

@otp.post("/create", response_model=OTP, summary="Create OTP")
async def create_otp(user_id: int, otp_service: OTPService = Depends(get_otp_service)):
    """Creates an OTP for a user."""
    return await otp_service.create_otp(user_id)

@otp.post("/verify", response_model=bool, summary="Verify OTP")
async def verify_otp(otp_verification: OTPVerification, otp_service: OTPService = Depends(get_otp_service)):
    """Verifies an OTP for a user and activates the user if valid."""
    return await otp_service.verify_otp(otp_verification.user_id, otp_verification.otp_code)




# ============================
# Departements Routes
# ============================

@departements.post("", response_model=List[Departement], summary="Create departements")
async def create_departements(dept_creates: List[DepartementCreate], departement_service: DepartementService = Depends(get_departement_service)):
    """Creates one or more new departements with unique codes."""
    return await departement_service.create_departements(dept_creates)

@departements.get("/{departement_id}", response_model=Departement, summary="Get a departement")
async def get_departement(departement_id: int, departement_service: DepartementService = Depends(get_departement_service)):
    """Retrieves a single departement by ID."""
    return await departement_service.get_departement(departement_id)

@departements.get("", response_model=List[Departement], summary="Get all departements")
async def get_all_departements(skip: int = 0, limit: int = 100, departement_service: DepartementService = Depends(get_departement_service)):
    """Retrieves a list of all departements with pagination."""
    return await departement_service.get_all_departements(skip=skip, limit=limit)

@departements.put("/{departement_id}", response_model=Departement, summary="Update a departement")
async def update_department(departement_id: int, dept_update: DepartementUpdate, departement_service: DepartementService = Depends(get_departement_service)):
    """Updates an existing departement."""
    return await departement_service.update_department(departement_id, dept_update)

@departements.delete("", summary="Delete departements")
async def delete_departements(departement_ids: List[int], departement_service: DepartementService = Depends(get_departement_service)):
    """Deletes multiple departements by their IDs."""
    departement_service.delete_departements(departement_ids)
    return {"message": "Departements deleted successfully"}




# ============================
# Teachers Routes
# ============================

@teachers.post("/", response_model=Teacher, summary="Create a teacher with user")
async def create_teacher_with_user(teacher_data: TeacherCreate, user_data: UserCreate, teacher_service: TeacherService = Depends(get_teacher_service)):
    """Creates a new teacher along with an associated user."""
    return await teacher_service.create_teacher_with_user(teacher_data, user_data)

@teachers.get("/{teacher_id}", response_model=Teacher, summary="Get a teacher")
async def get_teacher(teacher_id: int, teacher_service: TeacherService = Depends(get_teacher_service)):
    """Retrieves a single teacher by ID."""
    return await teacher_service.get_teacher(teacher_id)

@teachers.get("/", response_model=List[Teacher], summary="Get all teachers")
async def get_all_teachers(skip: int = 0, limit: int = 100, teacher_service: TeacherService = Depends(get_teacher_service)):
    """Retrieves a list of all teachers with pagination."""
    return await teacher_service.get_all_teachers(skip=skip, limit=limit)

@teachers.put("/{teacher_id}", response_model=Teacher, summary="Update a teacher")
async def update_teacher(teacher_id: int, teacher_data: TeacherUpdate, teacher_service: TeacherService = Depends(get_teacher_service)):
    """Updates an existing teacher and optionally their user."""
    return await teacher_service.update_teacher(teacher_id, teacher_data)

@teachers.delete("/", summary="Delete teachers")
async def delete_teachers(teacher_ids: List[int], delete_user: bool = False, teacher_service: TeacherService = Depends(get_teacher_service)):
    """Deletes multiple teachers by their IDs, optionally deleting their users."""
    teacher_service.delete_teachers(teacher_ids, delete_user)
    return {"message": "Teachers deleted successfully"}

@teachers.post("/{teacher_id}/departements", response_model=Teacher, summary="Add departements to teacher")
async def add_departements_to_teacher(teacher_id: int, departement_ids: List[int], teacher_service: TeacherService = Depends(get_teacher_service)):
    """Adds departements to a teacher."""
    return await teacher_service.add_departements_to_teacher(teacher_id, departement_ids)

@teachers.delete("/{teacher_id}/departements", response_model=Teacher, summary="Remove departements from teacher")
async def remove_departements_from_teacher(teacher_id: int, departement_ids: List[int], teacher_service: TeacherService = Depends(get_teacher_service)):
    """Removes departements from a teacher."""
    return await teacher_service.remove_departements_from_teacher(teacher_id, departement_ids)

@teachers.post("/{teacher_id}/cours", response_model=Teacher, summary="Add cours to teacher")
async def add_cours_to_teacher(teacher_id: int, cours_ids: List[int], teacher_service: TeacherService = Depends(get_teacher_service)):
    """Adds cours to a teacher."""
    return await teacher_service.add_cours_to_teacher(teacher_id, cours_ids)

@teachers.delete("/{teacher_id}/cours", response_model=Teacher, summary="Remove cours from teacher")
async def remove_cours_from_teacher(teacher_id: int, cours_ids: List[int], teacher_service: TeacherService = Depends(get_teacher_service)):
    """Removes cours from a teacher."""
    return await teacher_service.remove_cours_from_teacher(teacher_id, cours_ids)





# ============================
# TeacherAvailability Routes
# ============================

@availabilities.post("/", response_model=TeacherAvailability, summary="Create teacher availability")
async def create_teacher_availability(availability_create: TeacherAvailabilityCreate, teacher_availability_service: TeacherAvailabilityService = Depends(get_teacher_availability_service)):
    """Creates a new availability slot for a teacher."""
    return await teacher_availability_service.create_teacher_availability(availability_create)

@availabilities.get("/{availability_id}", response_model=TeacherAvailability, summary="Get teacher availability")
async def get_teacher_availability(availability_id: int, teacher_availability_service: TeacherAvailabilityService = Depends(get_teacher_availability_service)):
    """Retrieves a single teacher availability by ID."""
    return await teacher_availability_service.get_teacher_availability(availability_id)

@availabilities.get("/", response_model=List[TeacherAvailability], summary="Get all teacher availabilities")
async def get_all_teacher_availabilities(skip: int = 0, limit: int = 100, teacher_availability_service: TeacherAvailabilityService = Depends(get_teacher_availability_service)):
    """Retrieves a list of all teacher availabilities with pagination."""
    return await teacher_availability_service.get_all_teacher_availabilities(skip=skip, limit=limit)

@availabilities.put("/{availability_id}", response_model=TeacherAvailability, summary="Update teacher availability")
async def update_teacher_availability(availability_id: int, availability_update: TeacherAvailabilityUpdate, teacher_availability_service: TeacherAvailabilityService = Depends(get_teacher_availability_service)):
    """Updates an existing teacher availability."""
    return await teacher_availability_service.update_teacher_availability(availability_id, availability_update)

@availabilities.delete("/", summary="Delete teacher availabilities")
async def delete_teacher_availabilities(availability_ids: List[int], teacher_availability_service: TeacherAvailabilityService = Depends(get_teacher_availability_service)):
    """Deletes multiple teacher availabilities by their IDs."""
    teacher_availability_service.delete_teacher_availabilities(availability_ids)
    return {"message": "Availabilities deleted successfully"}




# ============================
# Students Routes
# ============================


@students.post("", response_model=Student, summary="Create a student with user")
async def create_student_with_user(payload: StudentWithUserCreate, student_service: StudentService = Depends(get_student_service)):
    """Creates a new student along with an associated user."""
    return await student_service.create_student_with_user(payload.student_data, payload.user_data)

@students.get("/{student_id}", response_model=Student, summary="Get a student")
async def get_student(student_id: int, student_service: StudentService = Depends(get_student_service)):
    """Retrieves a single student by ID."""
    return await student_service.get_student(student_id)

@students.get("", response_model=List[Student], summary="Get all students")
async def get_all_students(skip: int = 0, limit: int = 100, student_service: StudentService = Depends(get_student_service)):
    """Retrieves a list of all students with pagination."""
    return await student_service.get_all_students(skip=skip, limit=limit)

@students.put("/{student_id}", response_model=Student, summary="Update a student")
async def update_student(student_id: int, payload: StudentWithUserCreate, student_service: StudentService = Depends(get_student_service)):
    """Updates an existing student and optionally their user."""
    return await student_service.update_student(student_id, payload.student_data, payload.user_data)

@students.delete("/{student_id}", summary="Delete a student")
async def delete_student(student_id: int, student_service: StudentService = Depends(get_student_service)):
    """Deletes a student by ID."""
    student_service.delete_student(student_id)
    return {"message": "Student deleted successfully"}




# ============================
# School Routes
# ============================

@schools.post("", response_model=School, summary="Create a school")
async def create_school(school_create: SchoolCreate, logo_file: Optional[UploadFile] = File(None), school_service: SchoolService = Depends(get_school_service)):
    """Creates a new school with optional logo upload."""
    return await school_service.create_school(school_create, logo_file)

@schools.get("/{school_id}", response_model=School, summary="Get a school")
async def get_school(school_id: int, school_service: SchoolService = Depends(get_school_service)):
    """Retrieves a single school by ID."""
    return await school_service.get_school(school_id)

@schools.get("", response_model=List[School], summary="Get all schools")
async def get_all_schools(skip: int = 0, limit: int = 100, school_service: SchoolService = Depends(get_school_service)):
    """Retrieves a list of all schools with pagination."""
    return await school_service.get_all_schools(skip=skip, limit=limit)

@schools.put("/{school_id}", response_model=School, summary="Update a school")
async def update_school(school_id: int, school_update: SchoolUpdate, logo_file: Optional[UploadFile] = File(None), school_service: SchoolService = Depends(get_school_service)):
    """Updates an existing school with optional logo upload."""
    return await school_service.update_school(school_id, school_update, logo_file)

@schools.delete("/{school_id}", summary="Delete a school")
async def delete_school(school_id: int, school_service: SchoolService = Depends(get_school_service)):
    """Deletes a school by ID."""
    school_service.delete_school(school_id)
    return {"message": "School deleted successfully"}

@schools.post("/{school_id}/teachers", response_model=School, summary="Add teachers to school")
async def add_teachers_to_school(school_id: int, user_ids: List[int], school_service: SchoolService = Depends(get_school_service)):
    """Adds multiple teachers to a school."""
    return await school_service.add_teachers_to_school(school_id, user_ids)

@schools.delete("/{school_id}/teachers", response_model=School, summary="Remove teachers from school")
async def remove_teachers_from_school(school_id: int, user_ids: List[int], school_service: SchoolService = Depends(get_school_service)):
    """Removes multiple teachers from a school."""
    return await school_service.remove_teachers_from_school(school_id, user_ids)




# ============================
# Section Routes
# ============================

@sections.post("", response_model=Section, summary="Create a section")
async def create_section(section_create: SectionCreate, section_service: SectionService = Depends(get_section_service)):
    """Creates a new section."""
    return await section_service.create_section(section_create)

@sections.get("/{section_id}", response_model=Section, summary="Get a section")
async def get_section(section_id: int, section_service: SectionService = Depends(get_section_service)):
    """Retrieves a single section by ID."""
    return await section_service.get_section(section_id)

@sections.get("", response_model=List[Section], summary="Get all sections")
async def get_all_sections(skip: int = 0, limit: int = 100, section_service: SectionService = Depends(get_section_service)):
    """Retrieves a list of all sections with pagination."""
    return await section_service.get_all_sections(skip=skip, limit=limit)

@sections.put("/{section_id}", response_model=Section, summary="Update a section")
async def update_section(section_id: int, section_update: SectionUpdate, section_service: SectionService = Depends(get_section_service)):
    """Updates an existing section."""
    return await section_service.update_section(section_id, section_update)

@sections.delete("", summary="Delete sections")
async def delete_sections(section_ids: List[int], section_service: SectionService = Depends(get_section_service)):
    """Deletes multiple sections by their IDs."""
    section_service.delete_sections(section_ids)
    return {"message": "Sections deleted successfully"}

@sections.post("/{section_id}/filieres", response_model=Section, summary="Add filieres to section")
async def add_filieres_to_section(section_id: int, filiere_ids: List[int], section_service: SectionService = Depends(get_section_service)):
    """Adds multiple filieres to a section."""
    return await section_service.add_filieres_to_section(section_id, filiere_ids)

@sections.delete("/{section_id}/filieres", response_model=Section, summary="Remove filieres from section")
async def remove_filieres_from_section(section_id: int, filiere_ids: List[int], section_service: SectionService = Depends(get_section_service)):
    """Removes multiple filieres from a section."""
    return await section_service.remove_filieres_from_section(section_id, filiere_ids)




# ============================
# Filiere Routes
# ============================

@filieres.post("", response_model=Filiere, summary="Create a filiere")
async def create_filiere(filiere_create: FiliereCreate, filiere_service: FiliereService = Depends(get_filiere_service)):
    """Creates a new filiere."""
    return await filiere_service.create_filiere(filiere_create)

@filieres.get("/{filiere_id}", response_model=Filiere, summary="Get a filiere")
async def get_filiere(filiere_id: int, filiere_service: FiliereService = Depends(get_filiere_service)):
    """Retrieves a single filiere by ID."""
    return await filiere_service.get_filiere(filiere_id)

@filieres.get("", response_model=List[Filiere], summary="Get all filieres")
async def get_all_filieres(skip: int = 0, limit: int = 100, filiere_service: FiliereService = Depends(get_filiere_service)):
    """Retrieves a list of all filieres with pagination."""
    return await filiere_service.get_all_filieres(skip=skip, limit=limit)

@filieres.put("/{filiere_id}", response_model=Filiere, summary="Update a filiere")
async def update_filiere(filiere_id: int, filiere_update: FiliereUpdate, filiere_service: FiliereService = Depends(get_filiere_service)):
    """Updates an existing filiere."""
    return await filiere_service.update_filiere(filiere_id, filiere_update)

@filieres.delete("", summary="Delete filieres")
async def delete_filieres(filiere_ids: List[int], filiere_service: FiliereService = Depends(get_filiere_service)):
    """Deletes multiple filieres by their IDs."""
    filiere_service.delete_filieres(filiere_ids)
    return {"message": "Filieres deleted successfully"}

@filieres.post("/{filiere_id}/sections", response_model=Filiere, summary="Add sections to filiere")
async def add_sections_to_filiere(filiere_id: int, section_ids: List[int], filiere_service: FiliereService = Depends(get_filiere_service)):
    """Adds multiple sections to a filiere."""
    return await filiere_service.add_section_to_filiere(filiere_id, section_ids)

@filieres.delete("/{filiere_id}/sections", response_model=Filiere, summary="Remove sections from filiere")
async def remove_sections_from_filiere(filiere_id: int, section_ids: List[int], filiere_service: FiliereService = Depends(get_filiere_service)):
    """Removes multiple sections from a filiere."""
    return await filiere_service.remove_section_from_filiere(filiere_id, section_ids)




# ============================
# Specialite Routes
# ============================

@specialites.post("", response_model=Specialite, summary="Create a specialite")
async def create_specialite(specialite_create: SpecialiteCreate, specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Creates a new specialite."""
    return await specialite_service.create_specialite(specialite_create)

@specialites.get("/{specialite_id}", response_model=Specialite, summary="Get a specialite")
async def get_specialite(specialite_id: int, specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Retrieves a single specialite by ID."""
    return await specialite_service.get_specialite(specialite_id)

@specialites.get("", response_model=List[Specialite], summary="Get all specialites")
async def get_all_specialites(skip: int = 0, limit: int = 100, specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Retrieves a list of all specialites with pagination."""
    return await specialite_service.get_all_specialites(skip=skip, limit=limit)

@specialites.put("/{specialite_id}", response_model=Specialite, summary="Update a specialite")
async def update_specialite(specialite_id: int, specialite_update: SpecialiteUpdate, specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Updates an existing specialite."""
    return await specialite_service.update_specialite(specialite_id, specialite_update)

@specialites.delete("", summary="Delete specialites")
async def delete_specialites(specialite_ids: List[int], specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Deletes multiple specialites by their IDs."""
    specialite_service.delete_specialites(specialite_ids)
    return {"message": "Specialites deleted successfully"}

@specialites.post("/{specialite_id}/cycles", response_model=Specialite, summary="Add cycles to specialite")
async def add_cycles_to_specialite(specialite_id: int, cycle_ids: List[int], specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Adds multiple cycles to a specialite."""
    return await specialite_service.add_cycle_to_specialite(specialite_id, cycle_ids)

@specialites.delete("/{specialite_id}/cycles", response_model=Specialite, summary="Remove cycles from specialite")
async def remove_cycles_from_specialite(specialite_id: int, cycle_ids: List[int], specialite_service: SpecialiteService = Depends(get_specialite_service)):
    """Removes multiple cycles from a specialite."""
    return await specialite_service.remove_cycle_from_specialite(specialite_id, cycle_ids)




# ============================
# Cycle Routes
# ============================

@cycles.post("", response_model=Cycle, summary="Create a cycle")
async def create_cycle(cycle_create: CycleCreate, cycle_service: CycleService = Depends(get_cycle_service)):
    """Creates a new cycle."""
    return await cycle_service.create_cycle(cycle_create)

@cycles.get("/{cycle_id}", response_model=Cycle, summary="Get a cycle")
async def get_cycle(cycle_id: int, cycle_service: CycleService = Depends(get_cycle_service)):
    """Retrieves a single cycle by ID."""
    return await cycle_service.get_cycle(cycle_id)

@cycles.get("", response_model=List[Cycle], summary="Get all cycles")
async def get_all_cycles(skip: int = 0, limit: int = 100, cycle_service: CycleService = Depends(get_cycle_service)):
    """Retrieves a list of all cycles with pagination."""
    return await cycle_service.get_all_cycles(skip=skip, limit=limit)

@cycles.put("/{cycle_id}", response_model=Cycle, summary="Update a cycle")
async def update_cycle(cycle_id: int, cycle_update: CycleUpdate, cycle_service: CycleService = Depends(get_cycle_service)):
    """Updates an existing cycle."""
    return await cycle_service.update_cycle(cycle_id, cycle_update)

@cycles.delete("", summary="Delete cycles")
async def delete_cycles(cycle_ids: List[int], cycle_service: CycleService = Depends(get_cycle_service)):
    """Deletes multiple cycles by their IDs."""
    cycle_service.delete_cycles(cycle_ids)
    return {"message": "Cycles deleted successfully"}

@cycles.post("/{cycle_id}/specialites", response_model=Cycle, summary="Add specialites to cycle")
async def add_specialites_to_cycle(cycle_id: int, specialite_ids: List[int], cycle_service: CycleService = Depends(get_cycle_service)):
    """Adds multiple specialites to a cycle."""
    return await cycle_service.add_specialites_to_cycle(cycle_id, specialite_ids)

@cycles.delete("/{cycle_id}/specialites", response_model=Cycle, summary="Remove specialites from cycle")
async def remove_specialites_from_cycle(cycle_id: int, specialite_ids: List[int], cycle_service: CycleService = Depends(get_cycle_service)):
    """Removes multiple specialites from a cycle."""
    return await cycle_service.remove_specialites_from_cycle(cycle_id, specialite_ids)





# ============================
# Cours Routes
# ============================

@cours.post("", response_model=Cours, summary="Create a course")
async def create_course(course_create: CoursCreate, cours_service: CoursService = Depends(get_cours_service)):
    """Creates a new course with automatic code generation."""
    return await cours_service.create_course(course_create)

@cours.get("/{course_id}", response_model=Cours, summary="Get a course")
async def get_course(course_id: int, cours_service: CoursService = Depends(get_cours_service)):
    """Retrieves a single course by ID."""
    return await cours_service.get_course(course_id)

@cours.get("", response_model=List[Cours], summary="Get all courses")
async def get_all_courses(skip: int = 0, limit: int = 100, cours_service: CoursService = Depends(get_cours_service)):
    """Retrieves a list of all courses with pagination."""
    return await cours_service.get_all_courses(skip=skip, limit=limit)

@cours.put("/{course_id}", response_model=Cours, summary="Update a course")
async def update_course(course_id: int, course_update: CoursUpdate, cours_service: CoursService = Depends(get_cours_service)):
    """Updates an existing course."""
    return await cours_service.update_course(course_id, course_update)

@cours.delete("", summary="Delete courses")
async def delete_courses(course_ids: List[int], cours_service: CoursService = Depends(get_cours_service)):
    """Deletes multiple courses by their IDs."""
    cours_service.delete_courses(course_ids)
    return {"message": "Courses deleted successfully"}





# ============================
# Classe Routes
# ============================

@classes.post("", response_model=Classe, summary="Create a classe")
async def create_classe(classe_create: ClasseCreate, classe_service: ClasseService = Depends(get_classe_service)):
    """Creates a new classe."""
    return await classe_service.create_classe(classe_create)

@classes.get("/{classe_id}", response_model=Classe, summary="Get a classe")
async def get_classe(classe_id: int, classe_service: ClasseService = Depends(get_classe_service)):
    """Retrieves a single classe by ID."""
    return await classe_service.get_classe(classe_id)

@classes.get("", response_model=List[Classe], summary="Get all classes")
async def get_all_classes(skip: int = 0, limit: int = 100, classe_service: ClasseService = Depends(get_classe_service)):
    """Retrieves a list of all classes with pagination."""
    return await classe_service.get_all_classes(skip=skip, limit=limit)

@classes.put("/{classe_id}", response_model=Classe, summary="Update a classe")
async def update_classe(classe_id: int, classe_update: ClasseUpdate, classe_service: ClasseService = Depends(get_classe_service)):
    """Updates an existing classe."""
    return await classe_service.update_classe(classe_id, classe_update)

@classes.delete("", summary="Delete classes")
async def delete_classes(classe_ids: List[int], classe_service: ClasseService = Depends(get_classe_service)):
    """Deletes multiple classes by their IDs."""
    classe_service.delete_classes(classe_ids)
    return {"message": "Classes deleted successfully"}

@classes.post("/{classe_id}/cours", response_model=Classe, summary="Add cours to classe")
async def add_cours_to_classe(classe_id: int, cours_ids: List[int], classe_service: ClasseService = Depends(get_classe_service)):
    """Adds multiple cours to a classe."""
    return await classe_service.add_cours_to_classe(classe_id, cours_ids)

@classes.delete("/{classe_id}/cours", response_model=Classe, summary="Remove cours from classe")
async def remove_cours_from_classe(classe_id: int, cours_ids: List[int], classe_service: ClasseService = Depends(get_classe_service)):
    """Removes multiple cours from a classe."""
    return await classe_service.remove_cours_from_classe(classe_id, cours_ids)





# ============================
# Salle Routes
# ============================

@salles.post("", response_model=Salle, summary="Create a salle")
async def create_salle(salle_create: SalleCreate, salle_service: SalleService = Depends(get_salle_service)):
    """Creates a new salle."""
    return await salle_service.create_salle(salle_create)

@salles.get("/{salle_id}", response_model=Salle, summary="Get a salle")
async def get_salle(salle_id: int, salle_service: SalleService = Depends(get_salle_service)):
    """Retrieves a single salle by ID."""
    return await salle_service.get_salle(salle_id)

@salles.get("", response_model=List[Salle], summary="Get all salles")
async def get_all_salles(skip: int = 0, limit: int = 100, salle_service: SalleService = Depends(get_salle_service)):
    """Retrieves a list of all salles with pagination."""
    return await salle_service.get_all_salles(skip=skip, limit=limit)

@salles.put("/{salle_id}", response_model=Salle, summary="Update a salle")
async def update_salle(salle_id: int, salle_update: SalleUpdate, salle_service: SalleService = Depends(get_salle_service)):
    """Updates an existing salle."""
    return await salle_service.update_salle(salle_id, salle_update)

@salles.delete("", summary="Delete salles")
async def delete_salles(salle_ids: List[int], salle_service: SalleService = Depends(get_salle_service)):
    """Deletes multiple salles by their IDs."""
    salle_service.delete_salles(salle_ids)
    return {"message": "Salles deleted successfully"}





# ============================
# Occupation Routes
# ============================

@occupations.post("", response_model=Occupation, summary="Create an occupation")
async def create_occupation(occupation: OccupationCreate, occupation_service: OccupationService = Depends(get_occupation_service)):
    """Creates a new occupation with validations."""
    return await occupation_service.create_occupation(occupation)

@occupations.get("/{occupation_id}", response_model=Occupation, summary="Get an occupation")
async def get_occupation(occupation_id: int, occupation_service: OccupationService = Depends(get_occupation_service)):
    """Retrieves a single occupation by ID."""
    return await occupation_service.get_occupation(occupation_id)

@occupations.get("", response_model=List[Occupation], summary="Get all occupations")
async def get_all_occupations(skip: int = 0, limit: int = 100, occupation_service: OccupationService = Depends(get_occupation_service)):
    """Retrieves a list of all occupations with pagination."""
    return await occupation_service.get_all_occupations(skip=skip, limit=limit)

@occupations.put("/{occupation_id}", response_model=Occupation, summary="Update an occupation")
async def update_occupation(occupation_id: int, occupation_update: OccupationUpdate, occupation_service: OccupationService = Depends(get_occupation_service)):
    """Updates an existing occupation."""
    return await occupation_service.update_occupation(occupation_id, occupation_update)

@occupations.delete("", summary="Delete occupations")
async def delete_occupations(occupation_ids: List[int], occupation_service: OccupationService = Depends(get_occupation_service)):
    """Deletes multiple occupations by their IDs."""
    occupation_service.delete_occupations(occupation_ids)
    return {"message": "Occupations deleted successfully"}




# ============================
# Ressource Routes
# ============================

@ressources.post("", response_model=Ressource, summary="Create a ressource")
async def create_ressource(ressource_data: RessourceCreate, ressource_service: RessourceService = Depends(get_ressource_service)):
    """Creates a new ressource."""
    return await ressource_service.create_ressource(ressource_data)

@ressources.get("/{ressource_id}", response_model=Ressource, summary="Get a ressource")
async def get_ressource(ressource_id: int, ressource_service: RessourceService = Depends(get_ressource_service)):
    """Retrieves a single ressource by ID."""
    return await ressource_service.get_ressource(ressource_id)

@ressources.get("", response_model=List[Ressource], summary="Get all ressources")
async def get_all_ressources(skip: int = 0, limit: int = 100, ressource_service: RessourceService = Depends(get_ressource_service)):
    """Retrieves a list of all ressources with pagination."""
    return await ressource_service.get_all_ressources(skip=skip, limit=limit)

@ressources.put("/{ressource_id}", response_model=Ressource, summary="Update a ressource")
async def update_ressource(ressource_id: int, update_data: RessourceUpdate, ressource_service: RessourceService = Depends(get_ressource_service)):
    """Updates an existing ressource."""
    return await ressource_service.update_ressource(ressource_id, update_data)

@ressources.delete("", summary="Delete ressources")
async def delete_ressources(ressource_ids: List[int], ressource_service: RessourceService = Depends(get_ressource_service)):
    """Deletes multiple ressources by their IDs."""
    ressource_service.delete_ressources(ressource_ids)
    return {"message": "Ressources deleted successfully"}

@ressources.post("/{ressource_id}/cours", response_model=Ressource, summary="Add cours to ressource")
async def add_cours_to_ressource(ressource_id: int, cours_id: int, ressource_service: RessourceService = Depends(get_ressource_service)):
    """Adds a course to a ressource."""
    return await ressource_service.add_cours_to_ressource(ressource_id, cours_id)





# ============================
# Evenement Routes
# ============================

@evenements.post("", response_model=Evenement, summary="Create an evenement")
async def create_evenement(evenement_data: EvenementCreate, evenement_service: EvenementService = Depends(get_evenement_service)):
    """Creates a new evenement with validations."""
    return await evenement_service.create_evenement(evenement_data)

@evenements.get("/{evenement_id}", response_model=Evenement, summary="Get an evenement")
async def get_evenement(evenement_id: int, evenement_service: EvenementService = Depends(get_evenement_service)):
    """Retrieves a single evenement by ID."""
    return await evenement_service.get_evenement(evenement_id)

@evenements.get("", response_model=List[Evenement], summary="Get all evenements")
async def get_all_evenements(skip: int = 0, limit: int = 100, evenement_service: EvenementService = Depends(get_evenement_service)):
    """Retrieves a list of all evenements with pagination."""
    return await evenement_service.get_all_evenements(skip=skip, limit=limit)

@evenements.put("/{evenement_id}", response_model=Evenement, summary="Update an evenement")
async def update_evenement(evenement_id: int, evenement_update: EvenementUpdate, evenement_service: EvenementService = Depends(get_evenement_service)):
    """Updates an existing evenement."""
    return await evenement_service.update_evenement(evenement_id, evenement_update)

@evenements.delete("", summary="Delete evenements")
async def delete_evenements(evenement_ids: List[int], evenement_service: EvenementService = Depends(get_evenement_service)):
    """Deletes multiple evenements by their IDs."""
    evenement_service.delete_evenements(evenement_ids)
    return {"message": "Evenements deleted successfully"}





# ============================
# Reservation Routes
# ============================

@reservations.post("", response_model=Reservation, summary="Create a reservation")
async def create_reservation(reservation: ReservationCreate, reservation_service: ReservationService = Depends(get_reservation_service)):
    """Creates a new reservation with validations."""
    return await reservation_service.create_reservation(reservation)

@reservations.get("/{reservation_id}", response_model=Reservation, summary="Get a reservation")
async def get_reservation(reservation_id: int, reservation_service: ReservationService = Depends(get_reservation_service)):
    """Retrieves a single reservation by ID."""
    return await reservation_service.get_reservation(reservation_id)

@reservations.get("", response_model=List[Reservation], summary="Get all reservations")
async def get_all_reservations(skip: int = 0, limit: int = 100, reservation_service: ReservationService = Depends(get_reservation_service)):
    """Retrieves a list of all reservations with pagination."""
    return await reservation_service.get_all_reservations(skip=skip, limit=limit)

@reservations.put("/{reservation_id}", response_model=Reservation, summary="Update a reservation")
async def update_reservation(reservation_id: int, reservation_update: ReservationUpdate, reservation_service: ReservationService = Depends(get_reservation_service)):
    """Updates an existing reservation."""
    return await reservation_service.update_reservation(reservation_id, reservation_update)

@reservations.delete("/{reservation_id}", summary="Delete a reservation")
async def delete_reservation(reservation_id: int, reservation_service: ReservationService = Depends(get_reservation_service)):
    """Deletes a reservation by ID."""
    reservation_service.delete_reservation(reservation_id)
    return {"message": "Reservation deleted successfully"}

@reservations.post("/{reservation_id}/ressources", response_model=Reservation, summary="Add ressources to reservation")
async def add_ressources_to_reservation(reservation_id: int, ressources_quantities: List[RessourceQuantity], reservation_service: ReservationService = Depends(get_reservation_service)):
    """Adds multiple ressources with quantities to a reservation."""
    return await reservation_service.add_ressources_to_reservation(reservation_id, ressources_quantities)





# ============================
# Planning Routes
# ============================

@plannings.post("/generate-current-week", response_model=PlanningSchemas, summary="Generate planning for current week")
async def generate_current_week_planning(admin_id: int, school_id: int, required_hours_dict: Dict[Tuple[int, int], float], planning_service: PlanningService = Depends(get_planning_service)):
    """Generates and applies the planning for the current week."""
    return await planning_service.generate_current_week_planning(admin_id, school_id, required_hours_dict)

@plannings.get("/date/{input_date}", response_model=PlanningSchemas, summary="Get planning for a date")
async def get_planning_for_date(input_date: date, planning_service: PlanningService = Depends(get_planning_service)):
    """Retrieves the planning for a specific date."""
    return await planning_service.get_planning_for_date(input_date)

@plannings.get("/current", response_model=PlanningSchemas, summary="Get current planning")
async def get_current_planning(planning_service: PlanningService = Depends(get_planning_service)):
    """Retrieves the planning for the current week."""
    return await planning_service.get_current_planning()

@plannings.get("/historical", response_model=List[PlanningSchemas], summary="Get historical plannings")
async def get_historical_plannings(limit: int = 10, planning_service: PlanningService = Depends(get_planning_service)):
    """Retrieves a list of historical plannings."""
    return await planning_service.get_historical_plannings(limit=limit)



# ============================
# Enum Routes
# ============================

@enums.get("/app-environments", summary="List of application environments")
async def get_app_environments():
    return await EnumService.enum_to_list(AppEnvironment)

@enums.get("/roles", summary="List of roles")
async def get_roles():
    return await EnumService.enum_to_list(RoleEnum)

@enums.get("/permissions", summary="List of permissions")
async def get_permissions():
    return await EnumService.enum_to_list(PermissionEnum)

@enums.get("/genders", summary="List of genders")
async def get_genders():
    return await EnumService.enum_to_list(GenderEnum)

@enums.get("/type-etablissements", summary="List of institution types")
async def get_type_etablissements():
    return await EnumService.enum_to_list(TypeEtablissement)

@enums.get("/sections", summary="List of sections")
async def get_sections():
    return await EnumService.enum_to_list(SectionEnum)

@enums.get("/cycles", summary="List of academic cycles")
async def get_cycles():
    return await EnumService.enum_to_list(CycleEnum)

@enums.get("/type-salles", summary="List of room types")
async def get_type_salles():
    return await EnumService.enum_to_list(TypeSalleEnum)

@enums.get("/student-cours-status", summary="List of student course statuses")
async def get_student_cours_status():
    return await EnumService.enum_to_list(StudentCoursStatusEnum)

@enums.get("/type-cours", summary="List of course types")
async def get_type_cours():
    return await EnumService.enum_to_list(TypeCourEnum)

@enums.get("/weekdays", summary="List of weekdays")
async def get_weekdays():
    return await EnumService.enum_to_list(WeekdayEnum)

@enums.get("/reservation-statuses", summary="List of reservation statuses")
async def get_reservation_statuses():
    return await EnumService.enum_to_list(ReservationStatusEnum)

@enums.get("/resource-types", summary="List of resource types")
async def get_resource_types():
    return await EnumService.enum_to_list(ResourceTypeEnum)

@enums.get("/event-types", summary="List of event types")
async def get_event_types():
    return await EnumService.enum_to_list(EventTypeEnum)
