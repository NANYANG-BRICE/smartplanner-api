from datetime import datetime, date, time
from typing import List, Optional
from pydantic import BaseModel, EmailStr, HttpUrl, model_validator, validator
import re

from helper.utils.enums import ReservationStatusEnum


# ============================
# Permission Schemas
# ============================

class PermissionBase(BaseModel):
    name: str
    description: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class Permission(PermissionBase):
    id: int
    # roles: List[Role] = []

    class Config:
        from_attributes = True
        
        
        
# ============================
# Role Schemas
# ============================

class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    pass

class Role(RoleBase):
    id: int
    permissions: List["Permission"] = []

    class Config:
        from_attributes = True


# ============================
# Role Schemas
# ============================

class AuthenticateUserRequest(BaseModel):
    identifier: str
    password: str

class ResetPasswordRequest(BaseModel):
    email: str
    
class Token(BaseModel):
    access_token: str
    token_type: str


# ============================
# User Schemas
# ============================

class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    address: Optional[str] = None
    gender: str
    is_active: bool = False
    last_login: Optional[datetime] = None
    picture: Optional[str] = None

class UserCreate(UserBase):
    password: Optional[str] = None
    role_id: int
    extra_permissions: Optional[List[int]] = []

class UserUpdate(BaseModel):
    first_name: Optional[str]
    last_name: Optional[str]
    email: Optional[EmailStr]
    phone: Optional[str]
    address: Optional[str]
    password: Optional[str]
    gender: Optional[str]
    is_active: Optional[bool]
    picture: Optional[str]
    role_id: Optional[int]
    extra_permissions: Optional[List[int]]

class User(UserBase):
    id: int
    role: Optional[Role] = None
    extra_permissions: List[Permission] = []
    created_at: datetime
    updated_at: Optional[datetime] = None
    admin_schools: List["School"] = []
    teacher_schools: List["School"] = []

    class Config:
        from_attributes = True


# ============================
# OTP Schemas
# ============================

class OTPBase(BaseModel):
    code: str
    expires_at: datetime

class OTPCreate(OTPBase):
    user_id: int
    
class OTPVerification(BaseModel):
    user_id: int
    otp_code: str

class OTP(OTPBase):
    id: int
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# ============================
# Departement Schemas
# ============================

class DepartementBase(BaseModel):
    name: str
    code: str

class DepartementCreate(DepartementBase):
    school_id: int

class DepartementUpdate(BaseModel):
    name: Optional[str]
    code: Optional[str]

class Departement(DepartementBase):
    id: int
    school: Optional["School"] = None
    teachers: List["Teacher"] = []

    class Config:
        from_attributes = True


# ============================
# Teacher Schemas
# ============================

class TeacherBase(BaseModel):
    pass

class TeacherCreate(TeacherBase):
    user_id: int
    departements: List[int]
    cours: Optional[List[int]] = []

class Teacher(TeacherBase):
    id: int
    user: Optional[User] = None
    departements: Optional[List[Departement]] = []
    cours: Optional[List["Cours"]] = []
    availability: Optional[List["TeacherAvailability"]] = []

    class Config:
        from_attributes = True

class TeacherUpdate(BaseModel):
    departements: Optional[List[int]] = None
    cours: Optional[List[int]] = None

# ============================
# TeacherAvailability Schemas
# ============================

class TeacherAvailabilityBase(BaseModel):
    date: date
    start_time: time
    end_time: time

    @validator('date')
    def validate_date(cls, v):
        if v.weekday() > 5:
            raise ValueError("Availability can only be Monday to Saturday.")
        return v

    @validator('start_time', 'end_time')
    def validate_times(cls, v):
        if not (time(8,0) <= v <= time(17,0)):
            raise ValueError("Time must be between 08:00 and 17:00.")
        return v

    @validator('end_time')
    def validate_time_order(cls, v, values):
        if 'start_time' in values and v <= values['start_time']:
            raise ValueError("End time must be after start time.")
        return v

class TeacherAvailabilityCreate(TeacherAvailabilityBase):
    teacher_id: int

class TeacherAvailabilityUpdate(BaseModel):
    date: Optional[date]
    start_time: Optional[time]
    end_time: Optional[time]

class TeacherAvailability(TeacherAvailabilityBase):
    id: int
    teacher_id: int

    class Config:
        from_attributes = True

# ============================
# Student Schemas
# ============================

class StudentBase(BaseModel):
    matricule: Optional[str]

class StudentCreate(StudentBase):
    user_id: int
    school_id: int
    classe_id: Optional[int]

class StudentUpdate(BaseModel):
    matricule: Optional[str]
    school_id: Optional[int]
    classe_id: Optional[int]
    
    
class StudentWithUserCreate(BaseModel):
    student_data: StudentCreate
    user_data: UserCreate
    
    
class StudentWithUseUpdate(BaseModel):
    student_data: StudentUpdate
    user_data: UserUpdate

class Student(StudentBase):
    id: int
    user: Optional[User] = None
    school: Optional["School"] = None
    classe: Optional["Classe"] = None
    cours_status: List["Cours"] = []

    class Config:
        from_attributes = True

# ============================
# School Schemas
# ============================
class SchoolBase(BaseModel):
    name: str
    sigle: str
    address: str
    creation_date: date
    establishment_type: str
    description: Optional[str] = None
    website: str
    logo: Optional[str] = None


class SchoolCreate(SchoolBase):
    phones: List[str]
    emails: List[EmailStr]

    @validator('phones')
    def no_duplicate_phones(cls, v):
        if len(v) != len(set(v)):
            raise ValueError("Duplicate phone numbers not allowed")
        if not v:
            raise ValueError("At least one phone number is required")
        return v

    @validator('emails')
    def no_duplicate_emails(cls, v):
        if len(v) != len(set(v)):
            raise ValueError("Duplicate emails not allowed")
        if not v:
            raise ValueError("At least one email is required")
        return v

class SchoolUpdate(BaseModel):
    name: Optional[str] = None
    sigle: Optional[str] = None
    address: Optional[str] = None
    establishment_type: Optional[str] = None
    description: Optional[str] = None
    website: Optional[str] = None
    logo: Optional[str] = None
    phones: Optional[List[str]] = None
    emails: Optional[List[EmailStr]] = None

    @validator('phones')
    def no_duplicate_phones(cls, v):
        if v is not None and len(v) != len(set(v)):
            raise ValueError("Duplicate phone numbers not allowed")
        if v is not None and not v:
            raise ValueError("At least one phone number is required")
        return v

    @validator('emails')
    def no_duplicate_emails(cls, v):
        if v is not None and len(v) != len(set(v)):
            raise ValueError("Duplicate emails not allowed")
        if v is not None and not v:
            raise ValueError("At least one email is required")
        return v

class School(SchoolBase):
    id: int
    phones: List[str]
    emails: List[EmailStr]
    creation_date: date
    created_at: datetime
    updated_at: Optional[datetime] = None
    sections: List["Section"] = []
    departements: List["Departement"] = []
    admins: List["User"] = []
    teacher_schools: List["User"] = []
    students: List["Student"] = []
    ressources: List["Ressource"] = []
    evenements: List["Evenement"] = []

    class Config:
        from_attributes = True

# ============================
# Section Schemas
# ============================

class SectionBase(BaseModel):
    name: str

class SectionCreate(SectionBase):
    school_id: int
    filieres: Optional[List[int]] = []

class SectionUpdate(BaseModel):
    name: Optional[str]
    filieres: Optional[List[int]]

class Section(SectionBase):
    id: int
    school: Optional[School] = None
    filieres: List["Filiere"] = []
    classes: List["Classe"] = []

    class Config:
        from_attributes = True

# ============================
# Filiere Schemas
# ============================

class FiliereBase(BaseModel):
    name: str

class FiliereCreate(FiliereBase):
    pass
class FiliereUpdate(BaseModel):
    name: Optional[str]

class Filiere(FiliereBase):
    id: int
    sections: List[Section] = []
    specialites: List["Specialite"] = []
    classes: List["Classe"] = []
    cours: List["Cours"] = []

    class Config:
        from_attributes = True


# ============================
# Specialite Schemas
# ============================

class SpecialiteBase(BaseModel):
    name: str

class SpecialiteCreate(SpecialiteBase):
    filiere_id: int
    cycles: Optional[List[int]] = []

class SpecialiteUpdate(BaseModel):
    name: Optional[str]
    filiere_id: Optional[int]
    cycles: Optional[List[int]]

class Specialite(SpecialiteBase):
    id: int
    filiere: Optional[Filiere] = None
    cycles: List["Cycle"] = []
    classes: List["Classe"] = []
    cours: List["Cours"] = []

    class Config:
        from_attributes = True


# ============================
# Cycle Schemas
# ============================

class CycleBase(BaseModel):
    name: str

class CycleCreate(CycleBase):
    specialites: Optional[List[int]] = []

class CycleUpdate(BaseModel):
    name: Optional[str]
    specialites: Optional[List[int]]

class Cycle(CycleBase):
    id: int
    specialites: List[Specialite] = []
    classes: List["Classe"] = []

    class Config:
        from_attributes = True


# ============================
# Cours Schemas
# ============================

class CoursBase(BaseModel):
    name: str
    code: str
    type_cours: str
    description: Optional[str] = None
    color: Optional[str] = None

    @validator('color')
    def validate_color(cls, v):
        if v and not re.match(r'^#[0-9A-Fa-f]{6}$', v):
            raise ValueError("Invalid color hex code.")
        return v

class CoursCreate(CoursBase):
    filiere_id: Optional[int] = None
    specialite_id: Optional[int] = None
    teachers: Optional[List[int]] = []
    classes: Optional[List[int]] = []
    ressources: Optional[List[int]] = []

class CoursUpdate(BaseModel):
    name: Optional[str]
    code: Optional[str]
    type_cours: Optional[str]
    description: Optional[str]
    color: Optional[str]
    filiere_id: Optional[int]
    specialite_id: Optional[int]
    teachers: Optional[List[int]]
    classes: Optional[List[int]]
    ressources: Optional[List[int]]

class Cours(CoursBase):
    id: int
    filiere: Optional[Filiere] = None
    specialite: Optional[Specialite] = None
    teachers: List[Teacher] = []
    classes: List["Classe"] = []
    student_status: List[Student] = []
    ressources: List["Ressource"] = []
    occupations: List["Occupation"] = []

    class Config:
        from_attributes = True


# ============================
# Classe Schemas
# ============================

class ClasseBase(BaseModel):
    name: str
    code: str
    level: int

class ClasseCreate(ClasseBase):
    section_id: int
    filiere_id: int
    specialite_id: int
    cycle_id: int
    cours: Optional[List[int]] = []

class ClasseUpdate(BaseModel):
    name: Optional[str]
    code: Optional[str]
    level: Optional[int]
    section_id: Optional[int]
    filiere_id: Optional[int]
    specialite_id: Optional[int]
    cycle_id: Optional[int]
    cours: Optional[List[int]]

class Classe(ClasseBase):
    id: int
    section: Optional[Section] = None
    filiere: Optional[Filiere] = None
    specialite: Optional[Specialite] = None
    cycle: Optional[Cycle] = None
    students: List[Student] = []
    cours: List[Cours] = []
    occupations: List["Occupation"] = []

    class Config:
        from_attributes = True


# ============================
# Salle Schemas
# ============================

class SalleBase(BaseModel):
    name: str
    code: str
    type_salle: str
    capacity: int

class SalleCreate(SalleBase):
    pass

class SalleUpdate(BaseModel):
    name: Optional[str]
    code: Optional[str]
    type_salle: Optional[str]
    capacity: Optional[int]

class Salle(SalleBase):
    id: int
    occupations: List["Occupation"] = []
    reservations: List["Reservation"] = []

    class Config:
        from_attributes = True


# ============================
# Occupation Schemas
# ============================

class OccupationBase(BaseModel):
    jour: str
    heure_debut: time
    heure_fin: time

    @validator('heure_debut', 'heure_fin')
    def validate_times(cls, v):
        if not (time(8,0) <= v <= time(17,0)):
            raise ValueError("Time must be between 08:00 and 17:00.")
        return v

    @validator('heure_fin')
    def validate_order(cls, v, values):
        if 'heure_debut' in values and v <= values['heure_debut']:
            raise ValueError("End time must be after start time.")
        return v

class OccupationCreate(OccupationBase):
    salle_id: int
    classe_id: int
    cours_id: int
    teacher_id: int

class OccupationUpdate(BaseModel):
    jour: Optional[str]
    heure_debut: Optional[time]
    heure_fin: Optional[time]
    salle_id: Optional[int]
    classe_id: Optional[int]
    cours_id: Optional[int]
    teacher_id: Optional[int]

class Occupation(OccupationBase):
    id: int
    salle: Optional[Salle] = None
    classe: Optional[Classe] = None
    cours: Optional[Cours] = None
    teacher: Optional[Teacher] = None
    reservations: List["Reservation"] = []

    class Config:
        from_attributes = True


# ============================
# Ressource Schemas
# ============================

class RessourceBase(BaseModel):
    name: str
    code: str
    type_ressource: str
    description: Optional[str] = None
    quantity: int
    status: Optional[str] = None
    location: Optional[str] = None

    @validator('status')
    def validate_status(cls, v):
        valid = ["neuf", "usagé", "endommagé", "en réparation"]
        if v and v.lower() not in valid:
            raise ValueError(f"Status must be one of {valid}")
        return v

class RessourceCreate(RessourceBase):
    school_id: int

class RessourceUpdate(BaseModel):
    name: Optional[str]
    code: Optional[str]
    type_ressource: Optional[str]
    description: Optional[str]
    quantity: Optional[int]
    status: Optional[str]
    location: Optional[str]
    school_id: Optional[int]

class Ressource(RessourceBase):
    id: int
    school: Optional[School] = None
    cours: List["Cours"] = []
    reservations: List["Reservation"] = []
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class RessourceQuantity(BaseModel):
    ressource_id: int  
    quantity: int       

    class Config:
        from_attributes = True

# ============================
# Evenement Schemas
# ============================

class EvenementBase(BaseModel):
    name: str
    code: str
    type_evenement: str
    description: Optional[str] = None
    start_datetime: datetime
    end_datetime: datetime
    location: Optional[str] = None

    @validator('end_datetime')
    def validate_dates(cls, v, values):
        if 'start_datetime' in values and v <= values['start_datetime']:
            raise ValueError("End datetime must be after start datetime.")
        return v

class EvenementCreate(EvenementBase):
    school_id: int

class EvenementUpdate(BaseModel):
    name: Optional[str]
    code: Optional[str]
    type_evenement: Optional[str]
    description: Optional[str]
    start_datetime: Optional[datetime]
    end_datetime: Optional[datetime]
    location: Optional[str]
    school_id: Optional[int]

class Evenement(EvenementBase):
    id: int
    school: Optional[School] = None
    reservations: List["Reservation"] = []
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================
# Reservation Schemas
# ============================

class ReservationBase(BaseModel):
    quantity_reserved: int
    status: ReservationStatusEnum = ReservationStatusEnum.PENDING
    start_datetime: datetime
    end_datetime: datetime

    @validator('quantity_reserved')
    def quantity_positive(cls, v):
        if v <= 0:
            raise ValueError("Quantity reserved must be positive.")
        return v

    @validator('end_datetime')
    def validate_dates(cls, v, values):
        if 'start_datetime' in values and v <= values['start_datetime']:
            raise ValueError("End datetime must be after start datetime.")
        return v

class ReservationCreate(ReservationBase):
    occupation_id: Optional[int] = None
    evenement_id: Optional[int] = None
    salle_id: Optional[int] = None
    user_id: int
    admin_id: Optional[int] = None
    ressources: Optional[List[int]] = []

    @model_validator(mode='after')
    def validate_exclusive(cls, model):
        if model.occupation_id is not None and model.evenement_id is not None:
            raise ValueError("Cannot link to both occupation and evenement.")
        return model

class ReservationUpdate(BaseModel):
    quantity_reserved: Optional[int]
    status: Optional[str]
    start_datetime: Optional[datetime]
    end_datetime: Optional[datetime]
    occupation_id: Optional[int]
    evenement_id: Optional[int]
    salle_id: Optional[int]
    user_id: Optional[int]
    admin_id: Optional[int]
    ressources: Optional[List[int]]

class Reservation(ReservationBase):
    id: int
    occupation: Optional[Occupation] = None
    evenement: Optional[Evenement] = None
    salle: Optional[Salle] = None
    user: Optional[User] = None
    admin: Optional[User] = None
    ressources: List[Ressource] = []
    processed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ======================================
# Planning Schemas
# ======================================

class PlanningSchemas(BaseModel):
    id: int
    classe_id: int
    semaine: str
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# ======================================
# Résoudre les références circulaires
# ======================================
Role.update_forward_refs()
Permission.update_forward_refs()
User.update_forward_refs()
Departement.update_forward_refs()
Teacher.update_forward_refs()
Student.update_forward_refs()
School.update_forward_refs()
Section.update_forward_refs()
Filiere.update_forward_refs()
Specialite.update_forward_refs()
Cycle.update_forward_refs()
Cours.update_forward_refs()
Classe.update_forward_refs()
Salle.update_forward_refs()
Occupation.update_forward_refs()
Ressource.update_forward_refs()
Evenement.update_forward_refs()
Reservation.update_forward_refs()





