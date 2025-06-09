import json
from enum import Enum
import re
from typing import List
from sqlalchemy import (
    CheckConstraint, Column, Date, Integer, String, ForeignKey, Table, DateTime, Boolean,
    Enum as SqlEnum, Text, Time, UniqueConstraint, and_, or_
)
from sqlalchemy.orm import relationship, DeclarativeBase, validates
from sqlalchemy.sql import func
from datetime import time
from helper.utils.enums import (
    CycleEnum, EventTypeEnum, GenderEnum, PermissionEnum, RoleEnum, StudentCoursStatusEnum,
    TypeCourEnum, TypeEtablissement, TypeSalleEnum, WeekdayEnum, ResourceTypeEnum,
    ReservationStatusEnum
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


# ============================
# Association Tables
# ============================

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)

user_permissions = Table(
    "user_permissions",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)

school_admins = Table(
    "school_admins",
    Base.metadata,
    Column("school_id", Integer, ForeignKey("schools.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)

school_teachers = Table(
    "school_teachers",
    Base.metadata,
    Column("school_id", Integer, ForeignKey("schools.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)

section_filieres = Table(
    "section_filieres",
    Base.metadata,
    Column("section_id", Integer, ForeignKey("sections.id", ondelete="CASCADE"), primary_key=True),
    Column("filiere_id", Integer, ForeignKey("filieres.id", ondelete="CASCADE"), primary_key=True),
)

cycle_specialites = Table(
    "cycle_specialites",
    Base.metadata,
    Column("cycle_id", Integer, ForeignKey("cycles.id", ondelete="CASCADE"), primary_key=True),
    Column("specialite_id", Integer, ForeignKey("specialites.id", ondelete="CASCADE"), primary_key=True),
)

teacher_cours = Table(
    "teacher_cours",
    Base.metadata,
    Column("teacher_id", Integer, ForeignKey("teachers.id", ondelete="CASCADE"), primary_key=True),
    Column("cours_id", Integer, ForeignKey("cours.id", ondelete="CASCADE"), primary_key=True),
)

classe_cours = Table(
    "classe_cours",
    Base.metadata,
    Column("classe_id", Integer, ForeignKey("classes.id", ondelete="CASCADE"), primary_key=True),
    Column("cours_id", Integer, ForeignKey("cours.id", ondelete="CASCADE"), primary_key=True),
    Column("total_hours", Integer, nullable=False),
)

student_cours_status = Table(
    "student_cours_status",
    Base.metadata,
    Column("student_id", Integer, ForeignKey("students.id", ondelete="CASCADE"), primary_key=True),
    Column("cours_id", Integer, ForeignKey("cours.id", ondelete="CASCADE"), primary_key=True),
    Column("status", SqlEnum(StudentCoursStatusEnum), nullable=False, default=StudentCoursStatusEnum.INSCRIT),
)

teacher_departements = Table(
    "teacher_departements",
    Base.metadata,
    Column("teacher_id", Integer, ForeignKey("teachers.id", ondelete="CASCADE"), primary_key=True),
    Column("departement_id", Integer, ForeignKey("departements.id", ondelete="CASCADE"), primary_key=True),
)

cours_ressources = Table(
    "cours_ressources",
    Base.metadata,
    Column("cours_id", Integer, ForeignKey("cours.id", ondelete="CASCADE"), primary_key=True),
    Column("ressource_id", Integer, ForeignKey("ressources.id", ondelete="CASCADE"), primary_key=True),
)

reservation_ressources = Table(
    "reservation_ressources",
    Base.metadata,
    Column("reservation_id", Integer, ForeignKey("reservations.id", ondelete="CASCADE"), primary_key=True),
    Column("ressource_id", Integer, ForeignKey("ressources.id", ondelete="CASCADE"), primary_key=True),
)


# ============================
# Role Model
# ============================

class RoleModel(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(SqlEnum(RoleEnum), unique=True, nullable=False)
    description = Column(String, nullable=True)
    permissions = relationship("PermissionModel", secondary=role_permissions, back_populates="roles")
    users = relationship("UserModel", back_populates="role")


# ============================
# Permission Model
# ============================

class PermissionModel(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(SqlEnum(PermissionEnum), unique=True, nullable=False)
    description = Column(String, nullable=True)
    roles = relationship("RoleModel", secondary=role_permissions, back_populates="permissions")
    users = relationship("UserModel", secondary=user_permissions, back_populates="extra_permissions")


# ============================
# User Model
# ============================

class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    address = Column(String, nullable=True)
    password = Column(String, nullable=False)
    is_active = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=True)
    picture = Column(String, nullable=True)
    gender = Column(SqlEnum(GenderEnum), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    role_id = Column(Integer, ForeignKey("roles.id"))
    role = relationship("RoleModel", back_populates="users")

    extra_permissions = relationship("PermissionModel", secondary=user_permissions, back_populates="users")

    otp = relationship("OTPModel", uselist=False, back_populates="user")
    teacher = relationship("TeacherModel", uselist=False, back_populates="user")
    student = relationship("StudentModel", uselist=False, back_populates="user")

    admin_schools = relationship("SchoolModel", secondary=school_admins, back_populates="admins")
    teacher_schools = relationship("SchoolModel", secondary=school_teachers, back_populates="teacher_schools")

    reservations = relationship("ReservationModel", back_populates="user", foreign_keys="[ReservationModel.user_id]")
    processed_reservations = relationship("ReservationModel", back_populates="admin", foreign_keys="[ReservationModel.admin_id]")


# ============================
# OTP Model
# ============================

class OTPModel(Base):
    __tablename__ = "otps"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("UserModel", back_populates="otp")


# ============================
# Departement Model
# ============================

class DepartementModel(Base):
    __tablename__ = "departements"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    code = Column(String(50), unique=True, nullable=False)
    school_id = Column(Integer, ForeignKey("schools.id", ondelete="CASCADE"), nullable=False)

    school = relationship("SchoolModel", back_populates="departements")
    teachers = relationship("TeacherModel", secondary=teacher_departements, back_populates="departements")


# ============================
# Teacher Model
# ============================

class TeacherModel(Base):
    __tablename__ = "teachers"
    id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)

    user = relationship("UserModel", back_populates="teacher")

    departements = relationship("DepartementModel", secondary=teacher_departements, back_populates="teachers")
    cours = relationship("CoursModel", secondary=teacher_cours, back_populates="teachers")
    occupations = relationship("OccupationModel", back_populates="teacher")
    availability = relationship("TeacherAvailabilityModel", back_populates="teacher", cascade="all, delete-orphan")

    @validates('departements')
    def validate_departements(self, key, departement):
        if not self.departements:
            raise ValueError("A teacher must be associated with at least one departement.")
        # Vérifie que le département appartient à une école où le professeur enseigne
        teacher_school_ids = [school.id for school in self.teacher_schools]
        if departement.school_id not in teacher_school_ids:
            raise ValueError("The departement must belong to one of the teacher's schools.")
        return departement


# ============================
# Teacher Availability Model
# ============================

class TeacherAvailabilityModel(Base):
    __tablename__ = "teacher_availability"

    id = Column(Integer, primary_key=True, index=True)
    teacher_id = Column(Integer, ForeignKey("teachers.id", ondelete="CASCADE"), nullable=False)
    date = Column(Date, nullable=False)
    start_time = Column(Time, nullable=False)
    end_time = Column(Time, nullable=False)

    teacher = relationship("TeacherModel", back_populates="availability")

    __table_args__ = (
        CheckConstraint("start_time < end_time", name="check_time_order"),
    )

    @validates('date')
    def validate_date(self, key, value):
        # Disponibilité du lundi (0) au samedi (5) uniquement
        if value.weekday() > 5:
            raise ValueError("Availability can only be set for Monday to Saturday.")
        return value

    @validates('start_time', 'end_time')
    def validate_times(self, key, value):
        valid_start = time(8, 0)
        valid_end = time(17, 0)
        if not (valid_start <= value <= valid_end):
            raise ValueError(f"{key.replace('_', ' ').capitalize()} must be between 08:00 and 17:00.")
        return value


# ============================
# Student Model
# ============================

class StudentModel(Base):
    __tablename__ = "students"
    id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    matricule = Column(String, nullable=True)
    school_id = Column(Integer, ForeignKey("schools.id", ondelete="CASCADE"), nullable=False)
    classe_id = Column(Integer, ForeignKey("classes.id", ondelete="CASCADE"), nullable=True)

    user = relationship("UserModel", back_populates="student")
    school = relationship("SchoolModel", back_populates="students")
    classe = relationship("ClasseModel", back_populates="students")
    cours_status = relationship("CoursModel", secondary=student_cours_status, back_populates="student_status")

    @validates('classe_id')
    def validate_classe_school(self, key, value):
        if value is not None:
            classe = self._session.query(ClasseModel).filter(ClasseModel.id == value).first()
            if classe and classe.section.school_id != self.school_id:
                raise ValueError("The classe must belong to the student's school.")
        return value


# ============================
# School Model
# ============================

class SchoolModel(Base):
    __tablename__ = "schools"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    sigle = Column(String(50), unique=True, nullable=False)
    address = Column(String(255), nullable=False)
    phones = Column(Text, nullable=False)
    emails = Column(Text, nullable=False)  # Changed to store JSON list of emails
    creation_date = Column(Date, nullable=False)
    establishment_type = Column(SqlEnum(TypeEtablissement), nullable=False)
    description = Column(Text, nullable=True)
    website = Column(String(255), nullable=False, unique=True)
    logo = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    sections = relationship("SectionModel", back_populates="school", cascade="all, delete-orphan")
    departements = relationship("DepartementModel", back_populates="school", cascade="all, delete-orphan")
    admins = relationship("UserModel", secondary=school_admins, back_populates="admin_schools")
    teacher_schools = relationship("UserModel", secondary=school_teachers, back_populates="teacher_schools")
    students = relationship("StudentModel", back_populates="school")
    ressources = relationship("RessourceModel", back_populates="school", cascade="all, delete-orphan")
    evenements = relationship("EvenementModel", back_populates="school", cascade="all, delete-orphan")

    def set_phones(self, phones_list: List[str]) -> None:
        if not phones_list:
            raise ValueError("At least one phone number is required")
        if len(phones_list) != len(set(phones_list)):
            raise ValueError("Duplicate phone numbers are not allowed for a single school")
        self.phones = json.dumps(phones_list)

    def get_phones(self) -> List[str]:
        return json.loads(self.phones) if self.phones else []

    def set_emails(self, emails_list: List[str]) -> None:
        if not emails_list:
            raise ValueError("At least one email is required")
        if len(emails_list) != len(set(emails_list)):
            raise ValueError("Duplicate emails are not allowed for a single school")
        self.emails = json.dumps(emails_list)

    def get_emails(self) -> List[str]:
        return json.loads(self.emails) if self.emails else []


# ============================
# Section Model
# ============================

class SectionModel(Base):
    __tablename__ = "sections"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    school_id = Column(Integer, ForeignKey("schools.id", ondelete="CASCADE"), nullable=False)

    school = relationship("SchoolModel", back_populates="sections")
    filieres = relationship("FiliereModel", secondary=section_filieres, back_populates="sections")
    classes = relationship("ClasseModel", back_populates="section", cascade="all, delete-orphan")


# ============================
# Filiere Model
# ============================

class FiliereModel(Base):
    __tablename__ = "filieres"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)

    sections = relationship("SectionModel", secondary=section_filieres, back_populates="filieres")
    specialites = relationship("SpecialiteModel", back_populates="filiere", cascade="all, delete-orphan")
    classes = relationship("ClasseModel", back_populates="filiere", cascade="all, delete-orphan")
    cours = relationship("CoursModel", back_populates="filiere")


# ============================
# Specialite Model
# ============================

class SpecialiteModel(Base):
    __tablename__ = "specialites"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    filiere_id = Column(Integer, ForeignKey("filieres.id", ondelete="CASCADE"), nullable=False)

    filiere = relationship("FiliereModel", back_populates="specialites")
    cycles = relationship("CycleModel", secondary=cycle_specialites, back_populates="specialites")
    classes = relationship("ClasseModel", back_populates="specialite", cascade="all, delete-orphan")
    cours = relationship("CoursModel", back_populates="specialite")


# ============================
# Cycle Model
# ============================

class CycleModel(Base):
    __tablename__ = "cycles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(SqlEnum(CycleEnum), unique=True, nullable=False)

    specialites = relationship("SpecialiteModel", secondary=cycle_specialites, back_populates="cycles")
    classes = relationship("ClasseModel", back_populates="cycle", cascade="all, delete-orphan")


# ============================
# Cours Model
# ============================

class CoursModel(Base):
    __tablename__ = "cours"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    code = Column(String(50), unique=True, nullable=False)
    type_cours = Column(SqlEnum(TypeCourEnum), nullable=False)
    description = Column(String, nullable=True)
    filiere_id = Column(Integer, ForeignKey("filieres.id", ondelete="SET NULL"), nullable=True)
    specialite_id = Column(Integer, ForeignKey("specialites.id", ondelete="SET NULL"), nullable=True)
    color = Column(String(7), nullable=True)  # Code hexadécimal, ex: #FF5733

    filiere = relationship("FiliereModel", back_populates="cours")
    specialite = relationship("SpecialiteModel", back_populates="cours")
    teachers = relationship("TeacherModel", secondary=teacher_cours, back_populates="cours")
    occupations = relationship("OccupationModel", back_populates="cours")
    classes = relationship("ClasseModel", secondary=classe_cours, back_populates="cours")
    student_status = relationship("StudentModel", secondary=student_cours_status, back_populates="cours_status")
    ressources = relationship("RessourceModel", secondary=cours_ressources, back_populates="cours")

    @validates('color')
    def validate_color(self, key, value):
        if value is not None:
            # Vérifie que la couleur est un code hexadécimal valide (#RRGGBB)
            if not re.match(r'^#[0-9A-Fa-f]{6}$', value):
                raise ValueError("Color must be a valid hexadecimal code (e.g., #FF5733).")
        return value
    
    @validates('priority')
    def validate_priority(self, key, value):
        if not (1 <= value <= 5):
            raise ValueError("Priority must be between 1 (highest) and 5 (lowest).")
        return value

    @validates('filiere_id', 'specialite_id')
    def validate_filiere_specialite(self, key, value):
        if key == 'specialite_id' and value is not None:
            specialite = self._session.query(SpecialiteModel).filter(SpecialiteModel.id == value).first()
            if specialite and specialite.filiere_id != self.filiere_id:
                raise ValueError("The specialite must belong to the selected filiere.")
        if key == 'filiere_id' and value is not None:
            classes = self._session.query(ClasseModel).join(classe_cours).filter(classe_cours.c.cours_id == self.id).all()
            for classe in classes:
                if classe.filiere_id != value:
                    raise ValueError("The filiere must match the filiere of associated classes.")
        return value

    @validates('teachers')
    def validate_teachers(self, key, teacher):
        if self.filiere_id or self.specialite_id:
            departements = self._session.query(DepartementModel).join(teacher_departements).filter(
                teacher_departements.c.teacher_id == teacher.id
            ).all()
            if not departements:
                raise ValueError("Teacher must belong to at least one department.")
            # Optional: Add validation for department-filiere/specialite compatibility here
        return teacher


# ============================
# Classe Model
# ============================

class ClasseModel(Base):
    __tablename__ = "classes"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    code = Column(String(50), unique=True, nullable=False)
    level = Column(Integer, nullable=False)
    section_id = Column(Integer, ForeignKey("sections.id", ondelete="CASCADE"), nullable=False)
    filiere_id = Column(Integer, ForeignKey("filieres.id", ondelete="CASCADE"), nullable=False)
    specialite_id = Column(Integer, ForeignKey("specialites.id", ondelete="CASCADE"), nullable=False)
    cycle_id = Column(Integer, ForeignKey("cycles.id", ondelete="CASCADE"), nullable=False)

    section = relationship("SectionModel", back_populates="classes")
    filiere = relationship("FiliereModel", back_populates="classes")
    specialite = relationship("SpecialiteModel", back_populates="classes")
    cycle = relationship("CycleModel", back_populates="classes")
    students = relationship("StudentModel", back_populates="classe")
    occupations = relationship("OccupationModel", back_populates="classe")
    cours = relationship("CoursModel", secondary=classe_cours, back_populates="classes")

    @validates('level')
    def validate_level(self, key, value):
        if not (1 <= value <= 5):
            raise ValueError("Level must be between 1 and 5.")
        return value

    @validates('specialite_id', 'filiere_id')
    def validate_specialite_filiere(self, key, value):
        if key == 'specialite_id':
            specialite = self._session.query(SpecialiteModel).filter(SpecialiteModel.id == value).first()
            if specialite and specialite.filiere_id != self.filiere_id:
                raise ValueError("The specialite must belong to the filiere.")
        return value

    @validates('cycle_id')
    def validate_cycle(self, key, value):
        cycle = self._session.query(CycleModel).filter(CycleModel.id == value).first()
        if cycle and self.specialite_id:
            specialite = self._session.query(SpecialiteModel).filter(SpecialiteModel.id == self.specialite_id).first()
            if specialite and specialite not in cycle.specialites:
                raise ValueError("The cycle must be associated with the selected specialite.")
        return value


# ============================
# Salle Model
# ============================

class SalleModel(Base):
    __tablename__ = "salles"
    __table_args__ = (
        CheckConstraint('capacity > 0', name='check_capacity_positive'),
    )

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    type_salle = Column(SqlEnum(TypeSalleEnum), nullable=False)
    code = Column(String(50), unique=True)
    capacity = Column(Integer, nullable=False)

    occupations = relationship("OccupationModel", back_populates="salle")
    reservations = relationship("ReservationModel", back_populates="salle")

    @validates('capacity')
    def validate_capacity(self, key, value):
        if value <= 0:
            raise ValueError("Capacity must be strictly positive.")
        return value


# ============================
# Occupation Model
# ============================

class OccupationModel(Base):
    __tablename__ = "occupations"

    id = Column(Integer, primary_key=True, index=True)
    salle_id = Column(Integer, ForeignKey("salles.id", ondelete="CASCADE"), nullable=False)
    classe_id = Column(Integer, ForeignKey("classes.id", ondelete="CASCADE"), nullable=False)
    cours_id = Column(Integer, ForeignKey("cours.id", ondelete="CASCADE"), nullable=False)
    teacher_id = Column(Integer, ForeignKey("teachers.id", ondelete="CASCADE"), nullable=False)
    jour = Column(SqlEnum(WeekdayEnum), nullable=False)
    heure_debut = Column(Time, nullable=False)
    heure_fin = Column(Time, nullable=False)
    planning_id = Column(Integer, ForeignKey("plannings.id"))

    salle = relationship("SalleModel", back_populates="occupations")
    classe = relationship("ClasseModel", back_populates="occupations")
    cours = relationship("CoursModel", back_populates="occupations")
    teacher = relationship("TeacherModel", back_populates="occupations")
    reservations = relationship("ReservationModel", back_populates="occupation")
    planning = relationship("PlanningModel", back_populates="occupations")

    @validates("cours_id")
    def validate_cours_id(self, key, value):
        # 1. Vérifie l'association cours/classe
        classe = self._session.query(ClasseModel).filter(ClasseModel.id == self.classe_id).first()
        if classe and value not in [c.id for c in classe.cours]:
            raise ValueError("The cours must be associated with the selected classe.")

        # 2. Vérifie l'association cours/teacher
        if self.teacher_id:
            assoc = self._session.query(teacher_cours).filter(
                and_(
                    teacher_cours.c.teacher_id == self.teacher_id,
                    teacher_cours.c.cours_id == value
                )
            ).first()
            if not assoc:
                raise ValueError("The teacher must be associated with the selected cours.")

        # 3. Vérifie les ressources réservées
        ressources_requises = self._session.query(cours_ressources).filter(
            cours_ressources.c.cours_id == value
        ).all()
        if ressources_requises:
            reservation = self._session.query(ReservationModel).filter(
                and_(
                    ReservationModel.occupation_id == self.id,
                    ReservationModel.status == ReservationStatusEnum.APPROVED
                )
            ).first()
            if not reservation:
                raise ValueError("A reservation for the required resources must be approved for this occupation.")
            reserved_ids = [r.id for r in reservation.ressources]
            required_ids = [r.ressource_id for r in ressources_requises]
            if not all(r_id in reserved_ids for r_id in required_ids):
                raise ValueError("All required resources for the cours must be reserved.")
        return value

    @validates("teacher_id")
    def validate_teacher_id(self, key, value):
        # L'association avec le cours est déjà validée dans validate_cours_id
        # Ici on ajoute d'autres règles si nécessaire plus tard
        return value

    @validates("classe_id")
    def validate_classe_id(self, key, value):
        # L'association avec le cours est déjà validée dans validate_cours_id
        return value

    @validates("jour", "heure_debut", "heure_fin")
    def validate_availability(self, key, value):
        # On ne fait la validation que lorsque tous les champs nécessaires sont définis
        self._set_attr(key, value)  # mise à jour temporaire pour valider avec les bons champs

        if self.teacher_id and self.jour and self.heure_debut and self.heure_fin:
            availability = self._session.query(TeacherAvailabilityModel).filter(
                and_(
                    TeacherAvailabilityModel.teacher_id == self.teacher_id,
                    TeacherAvailabilityModel.date == self.jour,
                    TeacherAvailabilityModel.start_time <= self.heure_debut,
                    TeacherAvailabilityModel.end_time >= self.heure_fin
                )
            ).first()
            if not availability:
                raise ValueError("Teacher is not available at the specified date and time.")
        return value

    def _set_attr(self, key, value):
        """
        Cette méthode met temporairement à jour l'attribut self.<key> 
        pour permettre la validation croisée (utile dans validate_availability).
        """
        setattr(self, key, value)

    def is_valid_time(self):
        valid_start = time(8, 0)
        valid_end = time(17, 0)
        return valid_start <= self.heure_debut < self.heure_fin <= valid_end



# ============================
# Ressource Model
# ============================

class RessourceModel(Base):
    __tablename__ = "ressources"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    code = Column(String(50), unique=True, nullable=False)
    type_ressource = Column(SqlEnum(ResourceTypeEnum), nullable=False)
    description = Column(Text, nullable=True)
    quantity = Column(Integer, nullable=False)
    status = Column(String(50), nullable=True)
    location = Column(String(100), nullable=True)
    school_id = Column(Integer, ForeignKey("schools.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    school = relationship("SchoolModel", back_populates="ressources")
    cours = relationship("CoursModel", secondary=cours_ressources, back_populates="ressources")
    reservations = relationship("ReservationModel", secondary=reservation_ressources, back_populates="ressources")

    @validates('quantity')
    def validate_quantity(self, key, value):
        if value < 0:
            raise ValueError("Quantity cannot be negative.")
        return value

    @validates('status')
    def validate_status(self, key, value):
        valid_statuses = ["neuf", "usagé", "endommagé", "en réparation"]
        if value and value.lower() not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}.")
        return value


# ============================
# Evenement Model
# ============================

class EvenementModel(Base):
    __tablename__ = "evenements"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    code = Column(String(50), unique=True, nullable=False)
    type_evenement = Column(SqlEnum(EventTypeEnum), nullable=False)
    description = Column(Text, nullable=True)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    location = Column(String(100), nullable=True)
    school_id = Column(Integer, ForeignKey("schools.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    school = relationship("SchoolModel", back_populates="evenements")
    reservations = relationship("ReservationModel", back_populates="evenement")

    @validates('end_datetime')
    def validate_dates(self, key, value):
        if value <= self.start_datetime:
            raise ValueError("End datetime must be after start datetime.")
        return value


# ============================
# Reservation Model
# ============================

class ReservationModel(Base):
    __tablename__ = "reservations"
    id = Column(Integer, primary_key=True, index=True)
    occupation_id = Column(Integer, ForeignKey("occupations.id", ondelete="SET NULL"), nullable=True)
    evenement_id = Column(Integer, ForeignKey("evenements.id", ondelete="SET NULL"), nullable=True)
    salle_id = Column(Integer, ForeignKey("salles.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    quantity_reserved = Column(Integer, nullable=False)
    status = Column(SqlEnum(ReservationStatusEnum), nullable=False, default=ReservationStatusEnum.PENDING)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    processed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    ressources = relationship("RessourceModel", secondary=reservation_ressources, back_populates="reservations")
    occupation = relationship("OccupationModel", back_populates="reservations")
    evenement = relationship("EvenementModel", back_populates="reservations")
    salle = relationship("SalleModel", back_populates="reservations")
    user = relationship("UserModel", back_populates="reservations", foreign_keys=[user_id])
    admin = relationship("UserModel", back_populates="processed_reservations", foreign_keys=[admin_id])

    @validates('quantity_reserved')
    def validate_quantity_reserved(self, key, value):
        if value <= 0:
            raise ValueError("Quantity reserved must be positive.")
        return value

    @validates('status')
    def validate_status(self, key, value):
        if value != ReservationStatusEnum.PENDING and self.admin_id is None:
            raise ValueError("An admin must be provided to approve or reject a reservation.")
        if value in [ReservationStatusEnum.APPROVED, ReservationStatusEnum.REJECTED]:
            self.processed_at = func.now()
        return value

    @validates('end_datetime')
    def validate_dates(self, key, value):
        if value <= self.start_datetime:
            raise ValueError("End datetime must be after start datetime.")
        return value

    @validates('occupation_id', 'evenement_id')
    def validate_exclusive(self, key, value):
        if key == 'occupation_id' and value is not None and self.evenement_id is not None:
            raise ValueError("A reservation cannot be linked to both an occupation and an evenement.")
        if key == 'evenement_id' and value is not None and self.occupation_id is not None:
            raise ValueError("A reservation cannot be linked to both an evenement and an occupation.")
        return value

    @validates('admin_id')
    def validate_admin(self, key, value):
        if value is not None:
            admin = self._session.query(UserModel).filter(UserModel.id == value).first()
            if not admin:
                raise ValueError("Admin user does not exist.")
            # Vérification que l'admin appartient bien à une école liée à la ressource ou salle de la réservation
            school_ids = set()
            if self.salle_id:
                salle = self._session.query(SalleModel).filter(SalleModel.id == self.salle_id).first()
                if salle:
                    # Salle liée à une école (via section->school)
                    school_ids.add(salle.id)  # Ajuster selon schéma réel (ici pas de section dans salle ?)
            for ressource in self.ressources:
                school_ids.add(ressource.school_id)
            is_admin = self._session.query(school_admins).filter(
                and_(
                    school_admins.c.user_id == value,
                    school_admins.c.school_id.in_(school_ids)
                )
            ).first()
            if not is_admin:
                raise ValueError("The user approving or rejecting must be an admin of the resource's or salle's school.")
        return value

    @validates('salle_id')
    def validate_salle(self, key, value):
        if value is not None:
            salle = self._session.query(SalleModel).filter(SalleModel.id == value).first()
            if not salle:
                raise ValueError("Salle does not exist.")
            # Vérifier que la salle appartient à la même école que l'occupation ou l'événement
            school_id = None
            if self.occupation_id:
                occupation = self._session.query(OccupationModel).filter(OccupationModel.id == self.occupation_id).first()
                if occupation and occupation.classe:
                    school_id = occupation.classe.section.school_id
            elif self.evenement_id:
                evenement = self._session.query(EvenementModel).filter(EvenementModel.id == self.evenement_id).first()
                if evenement:
                    school_id = evenement.school_id
            # Ici, salle n'a pas de school direct, vérifier via section si possible ?
            # Supposons qu'on ait salle.section_id relié à section.school_id
            salle_section = None
            # if salle.section_id:
            #     salle_section = self._session.query(SectionModel).filter(SectionModel.id == salle.section_id).first()
            # if salle_section and school_id and salle_section.school_id != school_id:
            #     raise ValueError("The salle must belong to the school of the occupation or event.")
            # (Supposé car la définition de salle ne contient pas section_id dans ton modèle)
            
            # Vérification des conflits avec d'autres réservations approuvées
            conflit_reservation = self._session.query(ReservationModel).filter(
                and_(
                    ReservationModel.salle_id == value,
                    ReservationModel.id != self.id,
                    ReservationModel.status == ReservationStatusEnum.APPROVED,
                    ReservationModel.start_datetime < self.end_datetime,
                    ReservationModel.end_datetime > self.start_datetime
                )
            ).first()
            if conflit_reservation:
                raise ValueError("The salle is already reserved for this time period.")

            conflit_occupation = self._session.query(OccupationModel).filter(
                and_(
                    OccupationModel.salle_id == value,
                    OccupationModel.date == self.start_datetime.date(),
                    or_(
                        and_(
                            OccupationModel.heure_debut >= self.start_datetime.time(),
                            OccupationModel.heure_debut < self.end_datetime.time(),
                        ),
                        and_(
                            OccupationModel.heure_fin > self.start_datetime.time(),
                            OccupationModel.heure_fin <= self.end_datetime.time(),
                        )
                    )
                )
            ).first()
            if conflit_occupation:
                raise ValueError("The salle is already occupied for this time period.")
        return value


# ============================
# Planning Model
# ============================

class PlanningModel(Base):
    __tablename__ = "plannings"
    id = Column(Integer, primary_key=True, index=True)
    start_date = Column(Date, nullable=False)  # Date de début (lundi de la semaine)
    end_date = Column(Date, nullable=False)    # Date de fin (dimanche de la semaine)
    created_at = Column(DateTime, server_default=func.now())  # Date de création
    occupations = relationship("OccupationModel", back_populates="planning")

    __table_args__ = (
        UniqueConstraint('start_date', name='unique_week'),  # Unicité par semaine
    )