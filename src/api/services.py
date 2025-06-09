from datetime import date, datetime, time, timedelta
from enum import Enum
from pathlib import Path
import random
import string
from fastapi import File, HTTPException, UploadFile
from sqlalchemy import and_, or_, func, select
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from typing import Dict, List, Optional, Tuple, Type
from collections import defaultdict
from api.models import *
from api.schemas import *
from helper.config.settings import Settings
from helper.security.security import create_access_token, hash_password, verify_password
from helper.services.emailing import EmailService
from sqlalchemy.ext.asyncio import AsyncSession
from helper.utils.enums import *
settings = Settings()


# ============================
# Permission Service
# ============================

class PermissionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_permission_or_404(self, permission_id: int) -> PermissionModel:
        # Chargement des relations liées (rôles et utilisateurs associés à la permission)
        result = await self.db.execute(
            select(PermissionModel)
            .options(joinedload(PermissionModel.roles), joinedload(PermissionModel.users))
            .filter(PermissionModel.id == permission_id)
        )
        permission = result.scalars().first()
        
        if not permission:
            raise HTTPException(404, "Permission non trouvée")
        
        return permission

    async def _check_permission_name_unique(self, name: str, exclude_id: int = None):
        query = select(PermissionModel).filter(PermissionModel.name == name)
        if exclude_id:
            query = query.filter(PermissionModel.id != exclude_id)
        
        result = await self.db.execute(query)
        if result.scalars().first():
            return True

    async def create_permissions(self, perms_create: List[PermissionCreate]) -> List[Permission]:
        created_permissions = []
        try:
            for perm_create in perms_create:
                exists = await self._check_permission_name_unique(perm_create.name)
                if exists:
                    continue
                db_perm = PermissionModel(**perm_create.dict())
                self.db.add(db_perm)
                created_permissions.append(db_perm)

            await self.db.commit()

            # Rafraîchir les permissions créées
            for perm in created_permissions:
                await self.db.refresh(perm)

            return [Permission.from_orm(perm) for perm in created_permissions]

        except IntegrityError as e:
            await self.db.rollback()
            raise HTTPException(400, f"Erreur d'intégrité : {str(e)}")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_permissions(self, permission_ids: List[int]):
        permissions_to_delete = []
        
        for permission_id in permission_ids:
            try:
                perm = await self._get_permission_or_404(permission_id)

                # Vérifier si la permission a des rôles ou des utilisateurs associés
                if perm.roles or perm.users:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Impossible de supprimer la permission {permission_id} avec des rôles ou utilisateurs associés"
                    )

                permissions_to_delete.append(perm)
            except HTTPException as e:
                if e.status_code == 404:
                    continue
                else:
                    raise e
        
        try:
            # Supprimer les permissions
            for perm in permissions_to_delete:
                self.db.delete(perm)
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_permission(self, permission_id: int) -> Permission:
        permission = await self._get_permission_or_404(permission_id)
        return Permission.from_orm(permission)

    async def get_all_permissions(self, skip: int = 0, limit: int = 100) -> List[Permission]:
        result = await self.db.execute(
            select(PermissionModel)
            .options(joinedload(PermissionModel.roles), joinedload(PermissionModel.users))
            .offset(skip)
            .limit(limit)
        )
        permissions = result.unique().scalars().all()
        return [Permission.from_orm(p) for p in permissions]


# ============================
# Role Service
# ============================

class RoleService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_role_or_404(self, role_id: int) -> RoleModel:
        result = await self.db.execute(
            select(RoleModel)
            .options(joinedload(RoleModel.permissions), joinedload(RoleModel.users))
            .filter(RoleModel.id == role_id)
        )
        role = result.scalars().first()

        if not role:
            raise HTTPException(404, "Rôle non trouvé")
        return role

    async def _check_role_name_unique(self, name: str, exclude_id: int = None):
        query = select(RoleModel).filter(RoleModel.name == name)
        if exclude_id:
            query = query.filter(RoleModel.id != exclude_id)
        result = await self.db.execute(query)
        if result.scalars().first():
            raise HTTPException(400, "Un rôle avec ce nom existe déjà")

    async def assign_default_permissions_to_role(self, role: RoleModel):
        try:
            role_enum = RoleEnum(role.name)
        except ValueError:
            return

        default_permissions = DEFAULT_ROLE_PERMISSIONS.get(role_enum, [])
        if not default_permissions:
            return

        result = await self.db.execute(
            select(PermissionModel).filter(
                PermissionModel.name.in_([perm.value for perm in default_permissions])
            )
        )
        permission_models = result.scalars().all()

        role.permissions.extend(permission_models)
        await self.db.commit()
        await self.db.refresh(role)

    async def create_roles(self, roles_create: List[RoleCreate]) -> List[Role]:
        created_roles = []
        try:
            for role_create in roles_create:
                try:
                    await self._check_role_name_unique(role_create.name)
                except HTTPException as e:
                    if e.status_code == 400:
                        # Le rôle existe déjà, on l’ignore
                        continue
                    else:
                        raise

                db_role = RoleModel(**role_create.dict())
                self.db.add(db_role)
                created_roles.append(db_role)

            await self.db.commit()

            for role in created_roles:
                await self.assign_default_permissions_to_role(role)

            return [Role.from_orm(role) for role in created_roles]
        except IntegrityError as e:
            await self.db.rollback()
            raise HTTPException(400, f"Erreur d'intégrité : {str(e)}")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_role(self, role_id: int) -> Role:
        role = await self._get_role_or_404(role_id)
        return Role.from_orm(role)

    async def get_all_roles(self, skip: int = 0, limit: int = 100) -> List[Role]:
        result = await self.db.execute(
            select(RoleModel)
            .options(joinedload(RoleModel.permissions), joinedload(RoleModel.users))
            .offset(skip)
            .limit(limit)
        )
        roles = result.scalars().all()
        return [Role.from_orm(role) for role in roles]

    async def delete_roles(self, role_ids: List[int]):
        roles_to_delete = []

        for role_id in role_ids:
            try:
                role = await self._get_role_or_404(role_id)
                if role.users:
                    raise HTTPException(400, f"Impossible de supprimer le rôle {role_id} avec des utilisateurs associés")
                roles_to_delete.append(role)
            except HTTPException as e:
                if e.status_code != 404:
                    raise e

        try:
            for role in roles_to_delete:
                self.db.delete(role)
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def add_permissions_to_role(self, role_id: int, permission_ids: List[int]) -> Role:
        role = await self._get_role_or_404(role_id)
        permissions_to_add = []

        for permission_id in permission_ids:
            result = await self.db.execute(
                select(PermissionModel).filter(PermissionModel.id == permission_id)
            )
            permission = result.scalars().first()
            if not permission:
                continue
            if permission in role.permissions:
                raise HTTPException(400, f"La permission {permission_id} est déjà attribuée au rôle")
            permissions_to_add.append(permission)

        try:
            role.permissions.extend(permissions_to_add)
            await self.db.commit()
            await self.db.refresh(role)
            return Role.from_orm(role)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_permissions_from_role(self, role_id: int, permission_ids: List[int]) -> Role:
        role = await self._get_role_or_404(role_id)
        permissions_to_remove = []

        for permission_id in permission_ids:
            result = await self.db.execute(
                select(PermissionModel).filter(PermissionModel.id == permission_id)
            )
            permission = result.scalars().first()
            if not permission:
                continue
            if permission not in role.permissions:
                raise HTTPException(400, f"La permission {permission_id} n'est pas attribuée au rôle")
            permissions_to_remove.append(permission)

        try:
            for permission in permissions_to_remove:
                role.permissions.remove(permission)
            await self.db.commit()
            await self.db.refresh(role)
            return Role.from_orm(role)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))     
        
# ============================
# Auth Service
# ============================

class AuthenticationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def authenticate_user(self, identifier: str, password: str) -> dict:
        """Authentifier un utilisateur avec email ou téléphone et mot de passe, retourner un token JWT."""
        result = await self.db.execute(
            select(UserModel).filter(
                (UserModel.email == identifier) | (UserModel.phone == identifier)
            )
        )
        user = result.scalars().first()

        if not user or not verify_password(password, user.password):
            raise HTTPException(401, "Identifiants invalides")

        # Générer un token JWT
        access_token = create_access_token(data={"sub": str(user.id)})

        return {
            "access_token": access_token,
            "token_type": "bearer"
        }

    async def reset_password(self, email: str) -> None:
        """Réinitialiser le mot de passe de l'utilisateur et envoyer le nouveau mot de passe par email."""
        result = await self.db.execute(
            select(UserModel).filter(UserModel.email == email)
        )
        user = result.scalars().first()
        if not user:
            raise HTTPException(404, "Utilisateur avec cet email n'existe pas")

        # Générer un nouveau mot de passe aléatoire
        new_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        hashed_password = hash_password(new_password)

        # Mettre à jour le mot de passe de l'utilisateur
        user.password = hashed_password
        try:
            await self.db.commit()
            await self.db.refresh(user)
            # Envoyer le nouveau mot de passe par email
            EmailService.send_new_password_email(email, new_password)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, f"Échec de la réinitialisation du mot de passe : {str(e)}")

# ============================
# User Service
# ============================

class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_user_or_404(self, user_id: int) -> UserModel:
        result = await self.db.execute(
            select(UserModel)
            .options(
                joinedload(UserModel.role),
                joinedload(UserModel.extra_permissions),
                joinedload(UserModel.teacher),
                joinedload(UserModel.student),
                joinedload(UserModel.admin_schools),
                joinedload(UserModel.teacher_schools)
            )
            .filter(UserModel.id == user_id)
        )
        user = result.scalars().first()
        if not user:
            raise HTTPException(404, "Utilisateur non trouvé")
        return user

    async def _get_role_or_404(self, role_id: int) -> RoleModel:
        result = await self.db.execute(
            select(RoleModel).filter(RoleModel.id == role_id)
        )
        role = result.scalars().first()
        if not role:
            raise HTTPException(400, "Rôle n'existe pas")
        return role

    async def _get_permission_or_404(self, permission_id: int) -> PermissionModel:
        result = await self.db.execute(
            select(PermissionModel).filter(PermissionModel.id == permission_id)
        )
        perm = result.scalars().first()
        if not perm:
            raise HTTPException(400, f"La permission {permission_id} n'existe pas")
        return perm

    async def _check_unique_fields(self, email: Optional[str] = None, phone: Optional[str] = None, exclude_id: Optional[int] = None):
        if email:
            query = select(UserModel).filter(UserModel.email == email)
            if exclude_id:
                query = query.filter(UserModel.id != exclude_id)
            result = await self.db.execute(query)
            if result.scalars().first():
                raise HTTPException(400, "Email déjà existant")
        if phone:
            query = select(UserModel).filter(UserModel.phone == phone)
            if exclude_id:
                query = query.filter(UserModel.id != exclude_id)
            result = await self.db.execute(query)
            if result.scalars().first():
                raise HTTPException(400, "Numéro de téléphone déjà existant")

    async def _validate_image(self, file: UploadFile) -> None:
        ext = file.filename.split(".")[-1].lower()
        if ext not in settings.allowed_extensions_list:
            raise HTTPException(400, f"Type de fichier invalide : {ext}")
        file_size_mb = len(file.file.read()) / (1024 * 1024)
        if file_size_mb > settings.MAX_UPLOAD_SIZE_MB:
            raise HTTPException(400, f"Fichier trop volumineux : {file_size_mb:.2f} MB")
        file.file.seek(0)

    async def _save_image(self, file: UploadFile, user_id: int) -> str:
        self._validate_image(file)
        filename = f"user_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file.filename.split('.')[-1]}"
        path = Path(settings.UPLOAD_PICTURE_DIR) / filename
        with open(path, "wb") as f:
            f.write(file.file.read())
        return str(path)

    async def upload_user_photo(self, user_id: int, file: UploadFile = File(...)) -> str:
        user = await self._get_user_or_404(user_id)
        path = self._save_image(file, user_id)
        user.picture = path
        try:
            await self.db.commit()
            await self.db.refresh(user)
            return path
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def _generate_password(self, length: int = 8) -> str:
        """Générer un mot de passe sécurisé de lettres et chiffres de la longueur spécifiée."""
        characters = string.ascii_letters + string.digits
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    async def create_user(self, user_create: UserCreate) -> User:
        """Créer un nouvel utilisateur avec mot de passe haché."""
        await self._check_unique_fields(user_create.email, user_create.phone)

        password = self._generate_password(length=random.randint(8, 12))
        hashed_password = hash_password(password)

        role = await self._get_role_or_404(user_create.role_id)
        extra_perms = [await self._get_permission_or_404(pid) for pid in user_create.extra_permissions or []]

        user_data = user_create.dict(exclude={"extra_permissions", "password"})
        user_data["password"] = hashed_password

        user = UserModel(**user_data, role=role, extra_permissions=extra_perms)
        try:
            self.db.add(user)
            await self.db.commit()
            await self.db.refresh(user)
            EmailService.send_new_password_email(user_create.email, password)
            return User.from_orm(user)
        except IntegrityError:
            await self.db.rollback()
            raise HTTPException(400, "Utilisateur avec cet email ou téléphone existe déjà")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_user(self, user_id: int) -> User:
        result = await self.db.execute(
            select(UserModel)
            .options(
                joinedload(UserModel.role),
                joinedload(UserModel.extra_permissions),
                joinedload(UserModel.teacher).joinedload(TeacherModel.departements).joinedload(DepartementModel.school),
                joinedload(UserModel.teacher).joinedload(TeacherModel.cours),
                joinedload(UserModel.teacher).joinedload(TeacherModel.availability),
                joinedload(UserModel.student).joinedload(StudentModel.school),
                joinedload(UserModel.student).joinedload(StudentModel.classe),
                joinedload(UserModel.student).joinedload(StudentModel.cours_status),
                joinedload(UserModel.admin_schools),
                joinedload(UserModel.teacher_schools),
                joinedload(UserModel.reservations),
                joinedload(UserModel.processed_reservations)
            )
            .filter(UserModel.id == user_id)
        )
        user = result.scalars().first()

        if not user:
            raise HTTPException(404, "Utilisateur non trouvé")

        return User.from_orm(user)

    async def get_all_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        result = await self.db.execute(
            select(UserModel)
            .options(
                joinedload(UserModel.role),
                joinedload(UserModel.extra_permissions),
                joinedload(UserModel.teacher).joinedload(TeacherModel.departements).joinedload(DepartementModel.school),
                joinedload(UserModel.teacher).joinedload(TeacherModel.cours),
                joinedload(UserModel.teacher).joinedload(TeacherModel.availability),
                joinedload(UserModel.student).joinedload(StudentModel.school),
                joinedload(UserModel.student).joinedload(StudentModel.classe),
                joinedload(UserModel.student).joinedload(StudentModel.cours_status),
                joinedload(UserModel.admin_schools),
                joinedload(UserModel.teacher_schools),
                joinedload(UserModel.reservations),
                joinedload(UserModel.processed_reservations)
            )
            .offset(skip)
            .limit(limit)
        )
        users = result.scalars().all()

        return [User.from_orm(u) for u in users]

    async def update_user(self, user_id: int, user_update: UserUpdate) -> User:
        user = await self._get_user_or_404(user_id)
        data = user_update.dict(exclude_unset=True)
        await self._check_unique_fields(data.get("email"), data.get("phone"), exclude_id=user_id)

        if "role_id" in data:
            user.role = await self._get_role_or_404(data["role_id"])

        if "extra_permissions" in data:
            user.extra_permissions = [await self._get_permission_or_404(pid) for pid in data["extra_permissions"]]

        for key, value in data.items():
            if key not in {"role_id", "extra_permissions"}:
                setattr(user, key, value)

        try:
            await self.db.commit()
            await self.db.refresh(user)
            return User.from_orm(user)
        except IntegrityError:
            await self.db.rollback()
            raise HTTPException(400, "Données de mise à jour invalides (email ou téléphone en double)")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_user(self, user_id: int) -> None:
        user = await self._get_user_or_404(user_id)
        if user.teacher or user.student or user.admin_schools or user.teacher_schools:
            raise HTTPException(400, "Impossible de supprimer l'utilisateur avec des entités liées")
        try:
            self.db.delete(user)
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def add_permissions_to_user(self, user_id: int, permission_ids: List[int]) -> User:
        user = await self._get_user_or_404(user_id)
        for pid in permission_ids:
            perm = await self._get_permission_or_404(pid)
            if perm not in user.extra_permissions:
                user.extra_permissions.append(perm)
        try:
            await self.db.commit()
            await self.db.refresh(user)
            return User.from_orm(user)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_permissions_from_user(self, user_id: int, permission_ids: List[int]) -> User:
        user = await self._get_user_or_404(user_id)
        user.extra_permissions = [perm for perm in user.extra_permissions if perm.id not in permission_ids]
        try:
            await self.db.commit()
            await self.db.refresh(user)
            return User.from_orm(user)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))
             
# ============================
# OTP Service
# ============================

class OTPService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.otp_expiration_minutes = settings.OTP_EXPIRE_MINUTES

    async def _get_user_or_400(self, user_id: int) -> UserModel:
        """Vérifier si l'utilisateur existe."""
        result = await self.db.execute(
            select(UserModel).filter(UserModel.id == user_id)
        )
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=400, detail="Utilisateur n'existe pas")
        return user

    async def _generate_otp_code(self) -> str:
        """Générer un code OTP aléatoire à 6 chiffres."""
        return str(random.randint(100000, 999999))

    async def _get_active_otp_for_user(self, user_id: int) -> OTPModel:
        """Vérifier s'il existe un OTP actif pour l'utilisateur."""
        result = await self.db.execute(
            select(OTPModel).filter(
                OTPModel.user_id == user_id,
                OTPModel.expires_at > datetime.utcnow()
            )
        )
        return result.scalars().first()

    async def create_otp(self, user_id: int) -> OTP:
        """Créer un OTP pour un utilisateur."""
        user = await self._get_user_or_400(user_id)

        # Vérifier s'il existe déjà un OTP actif
        active_otp = await self._get_active_otp_for_user(user_id)
        expires_at = datetime.utcnow() + timedelta(minutes=self.otp_expiration_minutes)

        if active_otp:
            # Si un OTP actif existe, prolonger son expiration
            active_otp.expires_at = expires_at
            await self.db.commit()
            await self.db.refresh(active_otp)
            return OTP.from_orm(active_otp)

        # S'il n'y a pas d'OTP actif, créer un nouveau
        otp_code = self._generate_otp_code()
        db_otp = OTPModel(user_id=user_id, code=otp_code, expires_at=expires_at)

        try:
            self.db.add(db_otp)
            await self.db.commit()
            await self.db.refresh(db_otp)
            return OTP.from_orm(db_otp)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    async def verify_otp(self, user_id: int, otp_code: str) -> bool:
        """Vérifier si le code OTP est valide pour l'utilisateur et activer l'utilisateur."""
        # Récupérer l'utilisateur
        await self._get_user_or_400(user_id)

        # Vérifier l'OTP valide
        result = await self.db.execute(
            select(OTPModel).filter(
                OTPModel.user_id == user_id,
                OTPModel.code == otp_code,
                OTPModel.expires_at > datetime.utcnow()
            )
        )
        otp = result.scalars().first()

        if not otp:
            raise HTTPException(status_code=400, detail="OTP invalide ou expiré")

        # Si l'OTP est valide, activer l'utilisateur
        result = await self.db.execute(
            select(UserModel).filter(UserModel.id == user_id)
        )
        user = result.scalars().first()
        if user:
            user.is_active = True
            try:
                await self.db.commit()
                await self.db.refresh(user)
                return True
            except Exception as e:
                await self.db.rollback()
                raise HTTPException(status_code=500, detail=f"Erreur lors de la mise à jour de l'utilisateur : {str(e)}")

        raise HTTPException(status_code=400, detail="Utilisateur non trouvé")

# ============================
# Departement Service
# ============================

class DepartementService:
    def __init__(self, db: AsyncSession):
        """Initialiser le service des départements avec une session de base de données asynchrone."""
        self.db = db

    async def _handle_exception(self, exception, rollback: bool = True) -> None:
        """Gestion centralisée des exceptions."""
        if rollback:
            await self.db.rollback()
        if isinstance(exception, HTTPException):
            raise
        if isinstance(exception, ValueError):
            raise HTTPException(status_code=400, detail=str(exception))
        if isinstance(exception, IntegrityError):
            field = str(exception).split('key ')[1].split('=')[0].strip() if 'key ' in str(exception) else 'données'
            raise HTTPException(status_code=400, detail=f"{field} invalide : déjà existant")
        raise HTTPException(status_code=500, detail=str(exception))

    async def _get_or_404(self, model, **kwargs):
        """Récupérer un enregistrement ou lever une erreur 404."""
        result = await self.db.execute(select(model).filter_by(**kwargs))
        record = result.scalars().first()
        if not record:
            model_name = model.__tablename__.rstrip('s').capitalize()
            raise HTTPException(status_code=404, detail=f"{model_name} non trouvé")
        return record

    async def generate_department_code(self) -> str:
        """Générer un code de département unique (DEP-<aléatoire>-<année>)."""
        current_year = datetime.now().year
        for _ in range(100):
            random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            code = f"DEP-{random_part}-{current_year}"
            result = await self.db.execute(select(DepartementModel).filter(DepartementModel.code == code))
            if not result.scalars().first():
                return code
        raise ValueError("Impossible de générer un code de département unique après plusieurs tentatives")

    async def create_departements(self, dept_creates: List[DepartementCreate]) -> List[Departement]:
        """Créer plusieurs départements avec des codes uniques."""
        if not dept_creates:
            raise HTTPException(status_code=400, detail="Aucun département fourni")

        created_departements = []
        try:
            for dept_create in dept_creates:
                # Valider l'école
                await self._get_or_404(SchoolModel, id=dept_create.school_id)

                # Générer un code unique
                dept_create_dict = dept_create.dict()
                dept_create_dict['code'] = await self.generate_department_code()

                # Créer le département
                db_dept = DepartementModel(**dept_create_dict)
                self.db.add(db_dept)
                created_departements.append(db_dept)

            await self.db.commit()
            for db_dept in created_departements:
                await self.db.refresh(db_dept)
            return [Departement.from_orm(db_dept) for db_dept in created_departements]
        except Exception as e:
            await self._handle_exception(e)

    async def get_departement(self, departement_id: int) -> Departement:
        """Récupérer un département par ID avec les entités liées."""
        result = await self.db.execute(
            select(DepartementModel)
            .filter(DepartementModel.id == departement_id)
            .options(joinedload(DepartementModel.school), joinedload(DepartementModel.teachers))
        )
        dept = result.scalars().first()
        if not dept:
            raise HTTPException(status_code=404, detail="Département non trouvé")
        return Departement.from_orm(dept)

    async def get_all_departements(self, skip: int = 0, limit: int = 100) -> List[Departement]:
        """Récupérer tous les départements avec pagination."""
        try:
            result = await self.db.execute(
                select(DepartementModel)
                .options(joinedload(DepartementModel.school), joinedload(DepartementModel.teachers))
                .offset(skip)
                .limit(limit)
            )
            depts = result.scalars().all()
            return [Departement.from_orm(dept) for dept in depts]
        except Exception as e:
            await self._handle_exception(e)

    async def update_department(self, departement_id: int, dept_update: DepartementUpdate) -> Departement:
        """Mettre à jour un département, en excluant le code."""
        dept = await self._get_or_404(DepartementModel, id=departement_id)

        # Valider school_id si fourni
        if dept_update.school_id is not None:
            await self._get_or_404(SchoolModel, id=dept_update.school_id)

        try:
            for key, value in dept_update.dict(exclude_unset=True, exclude={'code'}).items():
                setattr(dept, key, value)
            await self.db.commit()
            await self.db.refresh(dept)
            return Departement.from_orm(dept)
        except Exception as e:
            await self._handle_exception(e)

    async def delete_departements(self, departement_ids: List[int]) -> None:
        """Supprimer plusieurs départements, en vérifiant les entités associées."""
        try:
            # Récupérer les départements avec les enseignants liés
            result = await self.db.execute(
                select(DepartementModel)
                .filter(DepartementModel.id.in_(departement_ids))
                .options(joinedload(DepartementModel.teachers))
            )
            departments = result.scalars().all()

            # Valider que tous les IDs existent
            if len(departments) != len(departement_ids):
                missing_ids = set(departement_ids) - {dept.id for dept in departments}
                raise HTTPException(
                    status_code=404,
                    detail=f"Départements avec IDs {missing_ids} non trouvés"
                )

            # Vérifier les enseignants associés
            for dept in departments:
                if dept.teachers:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Le département {dept.id} ne peut être supprimé car il a des enseignants associés"
                    )

            # Supprimer les départements
            for dept in departments:
                self.db.delete(dept)

            await self.db.commit()

        except Exception as e:
            await self._handle_exception(e)
                
# ============================
# Teacher Service
# ============================

class TeacherService:
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_service = UserService(db)
        self.departement_service = DepartementService(db)
        self.cours_service = CoursService(db)

    async def _handle_exception(self, exception, rollback: bool = True) -> None:
        """Gestion centralisée des exceptions."""
        if rollback:
            await self.db.rollback()
        if isinstance(exception, HTTPException):
            raise
        if isinstance(exception, ValueError):
            raise HTTPException(status_code=400, detail=str(exception))
        if isinstance(exception, IntegrityError):
            field = str(exception).split('key ')[1].split('=')[0].strip() if 'key ' in str(exception) else 'données'
            raise HTTPException(status_code=400, detail=f"{field} invalide : déjà existant")
        raise HTTPException(status_code=500, detail=str(exception))

    async def _get_or_404(self, model, **kwargs):
        """Récupérer un enregistrement ou lever une erreur 404."""
        result = await self.db.execute(select(model).filter_by(**kwargs))
        record = result.scalars().first()
        if not record:
            model_name = model.__tablename__.rstrip('s').capitalize()
            raise HTTPException(status_code=404, detail=f"{model_name} non trouvé")
        return record

    async def create_teacher_with_user(self, teacher_data: TeacherCreate, user_data: UserCreate) -> Teacher:
        """Créer un enseignant avec un utilisateur associé."""
        # Vérifier l'existence de l'utilisateur
        result = await self.db.execute(
            select(UserModel).filter(
                (UserModel.email == user_data.email) | (UserModel.phone == user_data.phone)
            )
        )
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="Utilisateur avec cet email ou téléphone existe déjà")

        # Créer l'utilisateur
        user = await self.user_service.create_user(user_data)

        # Valider l'enseignant
        teacher_school_ids = {school.id for school in user.teacher_schools}
        result = await self.db.execute(
            select(DepartementModel).filter(DepartementModel.id.in_(teacher_data.departements))
        )
        departements = result.scalars().all()
        if len(departements) != len(teacher_data.departements):
            missing_ids = set(teacher_data.departements) - {d.id for d in departements}
            raise HTTPException(status_code=404, detail=f"IDs de départements {missing_ids} non trouvés")

        for dept in departements:
            if dept.school_id not in teacher_school_ids:
                raise HTTPException(
                    status_code=400, detail=f"L'ID de département {dept.id} doit appartenir aux écoles de l'enseignant"
                )

        cours = []
        if teacher_data.cours:
            result = await self.db.execute(
                select(CoursModel).filter(CoursModel.id.in_(teacher_data.cours))
            )
            cours = result.scalars().all()
            if len(cours) != len(teacher_data.cours):
                missing_ids = set(teacher_data.cours) - {c.id for c in cours}
                raise HTTPException(status_code=404, detail=f"IDs de cours {missing_ids} non trouvés")

        # Créer l'enseignant
        db_teacher = TeacherModel(id=user.id, departements=departements, cours=cours)
        try:
            self.db.add(db_teacher)
            await self.db.commit()
            await self.db.refresh(db_teacher)
            return Teacher.from_orm(db_teacher)
        except Exception as e:
            await self._handle_exception(e)

    async def get_teacher(self, teacher_id: int) -> Teacher:
        """Récupérer un enseignant par ID."""
        result = await self.db.execute(
            select(TeacherModel)
            .filter(TeacherModel.id == teacher_id)
            .options(
                joinedload(TeacherModel.user).joinedload(UserModel.teacher_schools),
                joinedload(TeacherModel.departements),
                joinedload(TeacherModel.cours),
                joinedload(TeacherModel.occupations)
            )
        )
        teacher = result.scalars().first()
        if not teacher:
            raise HTTPException(status_code=404, detail="Enseignant non trouvé")
        return Teacher.from_orm(teacher)

    async def get_all_teachers(self, skip: int = 0, limit: int = 100) -> List[Teacher]:
        """Récupérer tous les enseignants avec pagination."""
        try:
            result = await self.db.execute(
                select(TeacherModel)
                .options(
                    joinedload(TeacherModel.user).joinedload(UserModel.teacher_schools),
                    joinedload(TeacherModel.departements),
                    joinedload(TeacherModel.cours)
                )
                .offset(skip)
                .limit(limit)
            )
            teachers = result.scalars().all()
            return [Teacher.from_orm(t) for t in teachers]
        except Exception as e:
            await self._handle_exception(e)

    async def update_teacher(self, teacher_id: int, teacher_data: TeacherUpdate, user_data: Optional[UserUpdate] = None) -> Teacher:
        """Mettre à jour un enseignant et éventuellement son utilisateur."""
        teacher = await self._get_or_404(TeacherModel, id=teacher_id)

        # Mettre à jour l'utilisateur si fourni
        if user_data:
            await self.user_service.update_user(teacher.user_id, user_data)

        # Mettre à jour les départements si fournis
        if teacher_data.departements is not None:
            teacher_school_ids = {school.id for school in teacher.user.teacher_schools}
            result = await self.db.execute(
                select(DepartementModel).filter(DepartementModel.id.in_(teacher_data.departements))
            )
            departements = result.scalars().all()
            if len(departements) != len(teacher_data.departements):
                missing_ids = set(teacher_data.departements) - {d.id for d in departements}
                raise HTTPException(status_code=404, detail=f"IDs de départements {missing_ids} non trouvés")
            for dept in departements:
                if dept.school_id not in teacher_school_ids:
                    raise HTTPException(
                        status_code=400, detail=f"L'ID de département {dept.id} doit appartenir aux écoles de l'enseignant"
                    )
            teacher.departements = departements

        # Mettre à jour les cours si fournis
        if teacher_data.cours is not None:
            result = await self.db.execute(
                select(CoursModel).filter(CoursModel.id.in_(teacher_data.cours))
            )
            cours = result.scalars().all()
            if len(cours) != len(teacher_data.cours):
                missing_ids = set(teacher_data.cours) - {c.id for c in cours}
                raise HTTPException(status_code=404, detail=f"IDs de cours {missing_ids} non trouvés")
            teacher.cours = cours

        try:
            await self.db.commit()
            await self.db.refresh(teacher)
            return Teacher.from_orm(teacher)
        except Exception as e:
            await self._handle_exception(e)

    async def delete_teachers(self, teacher_ids: List[int], delete_user: bool = False) -> None:
        """Supprimer plusieurs enseignants, éventuellement leurs utilisateurs."""
        try:
            result = await self.db.execute(
                select(TeacherModel)
                .filter(TeacherModel.id.in_(teacher_ids))
                .options(joinedload(TeacherModel.occupations))
            )
            teachers = result.scalars().all()
            if len(teachers) != len(teacher_ids):
                missing_ids = set(teacher_ids) - {t.id for t in teachers}
                raise HTTPException(status_code=404, detail=f"Enseignants avec IDs {missing_ids} non trouvés")

            for teacher in teachers:
                if teacher.occupations:
                    raise HTTPException(
                        status_code=400, detail=f"Impossible de supprimer l'enseignant ID {teacher.id} avec des occupations associées"
                    )
                self.db.delete(teacher)

                if delete_user:
                    result = await self.db.execute(
                        select(UserModel).filter(UserModel.id == teacher.id)
                    )
                    user = result.scalars().first()
                    if user:
                        self.db.delete(user)

            await self.db.commit()
        except HTTPException as e:
            await self._handle_exception(e, rollback=True)
        except Exception as e:
            await self._handle_exception(e)

    async def add_departements_to_teacher(self, teacher_id: int, departement_ids: List[int]) -> Teacher:
        """Ajouter des départements à un enseignant."""
        result = await self.db.execute(
            select(TeacherModel)
            .filter(TeacherModel.id == teacher_id)
            .options(joinedload(TeacherModel.user).joinedload(UserModel.teacher_schools))
        )
        teacher = result.scalars().first()
        if not teacher:
            raise HTTPException(status_code=404, detail="Enseignant non trouvé")

        teacher_school_ids = {school.id for school in teacher.user.teacher_schools}
        result = await self.db.execute(
            select(DepartementModel).filter(DepartementModel.id.in_(departement_ids))
        )
        departements = result.scalars().all()
        if len(departements) != len(departement_ids):
            missing_ids = set(departement_ids) - {d.id for d in departements}
            raise HTTPException(status_code=404, detail=f"IDs de départements {missing_ids} non trouvés")

        departements_to_add = []
        for dept in departements:
            if dept in teacher.departements:
                continue
            if dept.school_id not in teacher_school_ids:
                raise HTTPException(
                    status_code=400, detail=f"L'ID de département {dept.id} doit appartenir aux écoles de l'enseignant"
                )
            departements_to_add.append(dept)

        try:
            teacher.departements.extend(departements_to_add)
            await self.db.commit()
            await self.db.refresh(teacher)
            return Teacher.from_orm(teacher)
        except Exception as e:
            await self._handle_exception(e)

    async def remove_departements_from_teacher(self, teacher_id: int, departement_ids: List[int]) -> Teacher:
        """Retirer des départements d'un enseignant."""
        result = await self.db.execute(
            select(TeacherModel)
            .filter(TeacherModel.id == teacher_id)
            .options(joinedload(TeacherModel.departements))
        )
        teacher = result.scalars().first()
        if not teacher:
            raise HTTPException(status_code=404, detail="Enseignant non trouvé")

        result = await self.db.execute(
            select(DepartementModel).filter(DepartementModel.id.in_(departement_ids))
        )
        departements = result.scalars().all()
        if len(departements) != len(departement_ids):
            missing_ids = set(departement_ids) - {d.id for d in departements}
            raise HTTPException(status_code=404, detail=f"IDs de départements {missing_ids} non trouvés")

        departements_to_remove = [dept for dept in departements if dept in teacher.departements]
        try:
            for dept in departements_to_remove:
                teacher.departements.remove(dept)
            await self.db.commit()
            await self.db.refresh(teacher)
            return Teacher.from_orm(teacher)
        except Exception as e:
            await self._handle_exception(e)

    async def add_cours_to_teacher(self, teacher_id: int, cours_ids: List[int]) -> Teacher:
        """Ajouter des cours à un enseignant."""
        result = await self.db.execute(
            select(TeacherModel)
            .filter(TeacherModel.id == teacher_id)
            .options(joinedload(TeacherModel.cours))
        )
        teacher = result.scalars().first()
        if not teacher:
            raise HTTPException(status_code=404, detail="Enseignant non trouvé")

        result = await self.db.execute(
            select(CoursModel).filter(CoursModel.id.in_(cours_ids))
        )
        cours = result.scalars().all()
        if len(cours) != len(cours_ids):
            missing_ids = set(cours_ids) - {c.id for c in cours}
            raise HTTPException(status_code=404, detail=f"IDs de cours {missing_ids} non trouvés")

        cours_to_add = [c for c in cours if c not in teacher.cours]
        try:
            teacher.cours.extend(cours_to_add)
            await self.db.commit()
            await self.db.refresh(teacher)
            return Teacher.from_orm(teacher)
        except Exception as e:
            await self._handle_exception(e)

    async def remove_cours_from_teacher(self, teacher_id: int, cours_ids: List[int]) -> Teacher:
        """Retirer des cours d'un enseignant."""
        result = await self.db.execute(
            select(TeacherModel)
            .filter(TeacherModel.id == teacher_id)
            .options(joinedload(TeacherModel.cours))
        )
        teacher = result.scalars().first()
        if not teacher:
            raise HTTPException(status_code=404, detail="Enseignant non trouvé")

        result = await self.db.execute(
            select(CoursModel).filter(CoursModel.id.in_(cours_ids))
        )
        cours = result.scalars().all()
        if len(cours) != len(cours_ids):
            missing_ids = set(cours_ids) - {c.id for c in cours}
            raise HTTPException(status_code=404, detail=f"IDs de cours {missing_ids} non trouvés")

        cours_to_remove = [c for c in cours if c in teacher.cours]
        try:
            for c in cours_to_remove:
                teacher.cours.remove(c)
            await self.db.commit()
            await self.db.refresh(teacher)
            return Teacher.from_orm(teacher)
        except Exception as e:
            await self._handle_exception(e)

# ============================
# TeacherAvailability Service
# ============================

class TeacherAvailabilityService:
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.teacher_service = TeacherService(db)

    async def _handle_exception(self, exception, rollback: bool = True) -> None:
        """Gestion centralisée des exceptions."""
        if rollback:
            await self.db.rollback()
        if isinstance(exception, HTTPException):
            raise exception
        if isinstance(exception, ValueError):
            raise HTTPException(status_code=400, detail=str(exception))
        raise HTTPException(status_code=500, detail=str(exception))

    async def _get_or_404(self, model, **kwargs):
        """Méthode générique pour récupérer un enregistrement ou lever une erreur 404."""
        result = await self.db.execute(select(model).filter_by(**kwargs))
        record = result.scalars().first()
        if not record:
            model_name = model.__tablename__.rstrip('s').capitalize()
            raise HTTPException(status_code=404, detail=f"{model_name} non trouvé")
        return record

    async def _validate_availability(self, teacher_id: int, date: date, start_time: time, end_time: time, exclude_id: Optional[int] = None) -> None:
        """Valider les contraintes de disponibilité."""
        if date.weekday() == 6:
            raise ValueError("La disponibilité ne peut être définie que du lundi au samedi")
        
        if not (time(8, 0) <= start_time < end_time <= time(17, 0)):
            raise ValueError("L'heure de début doit être avant l'heure de fin et les deux doivent être entre 08:00 et 17:00")

        # Vérifier les chevauchements de disponibilité
        query = select(TeacherAvailabilityModel).filter(
            TeacherAvailabilityModel.teacher_id == teacher_id,
            TeacherAvailabilityModel.date == date,
            TeacherAvailabilityModel.start_time < end_time,
            TeacherAvailabilityModel.end_time > start_time
        )
        if exclude_id:
            query = query.filter(TeacherAvailabilityModel.id != exclude_id)
        
        result = await self.db.execute(query)
        if result.scalars().first():
            raise ValueError("L'enseignant a déjà une disponibilité chevauchante à cette date")

    async def create_teacher_availability(self, availability_create: TeacherAvailabilityCreate) -> TeacherAvailability:
        """Créer une nouvelle disponibilité d'enseignant avec validation."""
        # Valider l'existence de l'enseignant
        await self.teacher_service._get_teacher_or_404(availability_create.teacher_id)

        # Valider les contraintes de disponibilité
        try:
            await self._validate_availability(
                availability_create.teacher_id,
                availability_create.date,
                availability_create.start_time,
                availability_create.end_time
            )
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

        # Créer la disponibilité
        db_avail = TeacherAvailabilityModel(**availability_create.dict())
        try:
            self.db.add(db_avail)
            await self.db.commit()
            await self.db.refresh(db_avail)
            return TeacherAvailability.from_orm(db_avail)
        except IntegrityError as e:
            await self._handle_exception(e)
        except Exception as e:
            await self._handle_exception(e)

    async def get_teacher_availability(self, availability_id: int) -> TeacherAvailability:
        """Récupérer une disponibilité d'enseignant par ID avec l'enseignant lié."""
        try:
            result = await self.db.execute(
                select(TeacherAvailabilityModel)
                .filter(TeacherAvailabilityModel.id == availability_id)
                .options(joinedload(TeacherAvailabilityModel.teacher))
            )
            availability = result.scalars().first()
            if not availability:
                raise HTTPException(status_code=404, detail="Disponibilité non trouvée")
            return TeacherAvailability.from_orm(availability)
        except HTTPException as e:
            raise e
        except Exception as e:
            await self._handle_exception(e)

    async def get_all_teacher_availabilities(self, skip: int = 0, limit: int = 100) -> List[TeacherAvailability]:
        """Récupérer toutes les disponibilités des enseignants avec pagination."""
        try:
            result = await self.db.execute(
                select(TeacherAvailabilityModel)
                .options(joinedload(TeacherAvailabilityModel.teacher))
                .offset(skip)
                .limit(limit)
            )
            availabilities = result.scalars().all()
            return [TeacherAvailability.from_orm(a) for a in availabilities]
        except Exception as e:
            await self._handle_exception(e)

    async def update_teacher_availability(self, availability_id: int, availability_update: TeacherAvailabilityUpdate) -> TeacherAvailability:
        """Mettre à jour une disponibilité d'enseignant avec validation."""
        availability = await self._get_or_404(TeacherAvailabilityModel, id=availability_id)

        # Préparer les valeurs mises à jour
        date = availability_update.date if availability_update.date else availability.date
        start_time = availability_update.start_time if availability_update.start_time else availability.start_time
        end_time = availability_update.end_time if availability_update.end_time else availability.end_time
        teacher_id = availability_update.teacher_id if availability_update.teacher_id else availability.teacher_id

        # Valider l'enseignant si modifié
        if availability_update.teacher_id:
            await self.teacher_service._get_teacher_or_404(availability_update.teacher_id)

        # Valider les contraintes de disponibilité
        try:
            await self._validate_availability(
                teacher_id,
                date,
                start_time,
                end_time,
                exclude_id=availability_id
            )
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

        try:
            # Mettre à jour les champs
            for key, value in availability_update.dict(exclude_unset=True).items():
                setattr(availability, key, value)
            await self.db.commit()
            await self.db.refresh(availability)
            return TeacherAvailability.from_orm(availability)
        except IntegrityError as e:
            await self._handle_exception(e)
        except Exception as e:
            await self._handle_exception(e)

    async def delete_teacher_availabilities(self, availability_ids: List[int]) -> None:
        """Supprimer plusieurs disponibilités d'enseignants."""
        try:
            # Récupérer les disponibilités en une seule requête
            result = await self.db.execute(
                select(TeacherAvailabilityModel)
                .filter(TeacherAvailabilityModel.id.in_(availability_ids))
            )
            availabilities = result.scalars().all()

            # Vérifier que tous les IDs existent
            if len(availabilities) != len(availability_ids):
                missing_ids = set(availability_ids) - set(avail.id for avail in availabilities)
                raise HTTPException(status_code=404, detail=f"Disponibilités avec IDs {missing_ids} non trouvées")

            # Supprimer les disponibilités
            for avail in availabilities:
                self.db.delete(avail)
            await self.db.commit()
        except HTTPException as e:
            raise e
        except Exception as e:
            await self._handle_exception(e)
            
# ============================
# Student Service
# ============================

class StudentService:
    def __init__(self, db: AsyncSession, user_service: 'UserService'):
        self.db = db
        self.user_service = user_service

    async def _handle_exception(self, exception, rollback: bool = True):
        """Gestion centralisée des exceptions."""
        if rollback:
            await self.db.rollback()
        if isinstance(exception, HTTPException):
            raise exception
        raise HTTPException(status_code=500, detail=str(exception))

    async def _get_or_404(self, model, **kwargs):
        """Méthode générique pour récupérer un enregistrement ou lever une erreur 404."""
        result = await self.db.execute(select(model).filter_by(**kwargs))
        record = result.scalars().first()
        if not record:
            model_name = model.__tablename__.rstrip('s').capitalize()
            raise HTTPException(status_code=404, detail=f"{model_name} non trouvé")
        return record

    async def _get_school_and_classe(self, school_id: int, classe_id: Optional[int] = None) -> Tuple[SchoolModel, Optional[ClasseModel]]:
        """Vérifie si l'école et la classe sont valides et appartiennent à la même école."""
        school = await self._get_or_404(SchoolModel, id=school_id)
        classe = None
        if classe_id:
            result = await self.db.execute(select(ClasseModel).filter(ClasseModel.id == classe_id))
            classe = result.scalars().first()
            if not classe:
                raise HTTPException(status_code=404, detail="Classe non trouvée")
            if classe.section.school_id != school.id:
                raise HTTPException(status_code=400, detail="La classe doit appartenir à l'école de l'étudiant")
        return school, classe

    async def create_student(self, student_data: StudentCreate, user_data: UserCreate) -> Student:
        """Créer un étudiant avec un utilisateur associé, en vérifiant l'unicité du matricule."""
        try:
            # Vérifier l'existence d'un utilisateur par email ou téléphone
            result = await self.db.execute(
                select(UserModel).filter(
                    (UserModel.email == user_data.email) | (UserModel.phone == user_data.phone)
                )
            )
            if result.scalars().first():
                raise HTTPException(status_code=400, detail="Utilisateur avec cet email ou téléphone existe déjà")

            # Vérifier l'existence du matricule si fourni
            if student_data.matricule:
                result = await self.db.execute(
                    select(StudentModel).filter(StudentModel.matricule == student_data.matricule)
                )
                if result.scalars().first():
                    raise HTTPException(status_code=400, detail="Étudiant avec ce matricule existe déjà")

            # Valider les relations entre école et classe
            await self._get_school_and_classe(student_data.school_id, student_data.classe_id)

            # Créer l'utilisateur
            user = await self.user_service.create_user(user_data)

            # Créer l'étudiant
            db_student = StudentModel(
                id=user.id,
                matricule=student_data.matricule,
                school_id=student_data.school_id,
                classe_id=student_data.classe_id
            )
            self.db.add(db_student)
            await self.db.commit()
            await self.db.refresh(db_student)
            return Student.from_orm(db_student)
        except IntegrityError as e:
            await self._handle_exception(e)
        except Exception as e:
            await self._handle_exception(e)

    async def get_student(self, student_id: int) -> Student:
        """Récupérer un étudiant par ID avec les entités liées."""
        result = await self.db.execute(
            select(StudentModel)
            .filter(StudentModel.id == student_id)
            .options(
                joinedload(StudentModel.user),
                joinedload(StudentModel.school),
                joinedload(StudentModel.classe),
                joinedload(StudentModel.cours_status)
            )
        )
        student = result.scalars().first()
        if not student:
            raise HTTPException(status_code=404, detail="Étudiant non trouvé")
        return Student.from_orm(student)

    async def get_all_students(self, skip: int = 0, limit: int = 100) -> List[Student]:
        """Récupérer tous les étudiants avec pagination et entités liées."""
        try:
            result = await self.db.execute(
                select(StudentModel)
                .options(
                    joinedload(StudentModel.user),
                    joinedload(StudentModel.school),
                    joinedload(StudentModel.classe)
                )
                .offset(skip)
                .limit(limit)
            )
            students = result.scalars().all()
            return [Student.from_orm(s) for s in students]
        except Exception as e:
            await self._handle_exception(e)

    async def update_student(self, student_id: int, student_update: StudentUpdate, user_update: Optional[UserUpdate] = None) -> Student:
        """Mettre à jour un étudiant et éventuellement son utilisateur associé."""
        student = await self._get_or_404(StudentModel, id=student_id)
        user = await self._get_or_404(UserModel, id=student.user_id)

        student_data = student_update.dict(exclude_unset=True)
        
        if "school_id" in student_data or ("classe_id" in student_data and student_data["classe_id"]):
            school_id = student_data.get("school_id", student.school_id)
            classe_id = student_data.get("classe_id", student.classe_id)
            await self._get_school_and_classe(school_id, classe_id)

        if user_update:
            try:
                await self.user_service.update_user(student.user_id, user_update)
            except Exception as e:
                await self._handle_exception(e, rollback=False)
                if "unique constraint" in str(e).lower():
                    field = str(e).split('key ')[1].split('=')[0].strip()
                    raise HTTPException(status_code=400, detail=f"Utilisateur avec ce {field} existe déjà")
                raise HTTPException(status_code=400, detail="Données de mise à jour d'utilisateur invalides")

        try:
            for key, value in student_data.items():
                setattr(student, key, value)
            await self.db.commit()
            await self.db.refresh(student)
            return Student.from_orm(student)
        except IntegrityError as e:
            await self._handle_exception(e)
        except Exception as e:
            await self._handle_exception(e)

    async def delete_students(self, student_ids: List[int]) -> None:
        """Supprimer plusieurs étudiants après vérification des statuts de cours associés."""
        try:
            result = await self.db.execute(
                select(StudentModel)
                .filter(StudentModel.id.in_(student_ids))
                .options(joinedload(StudentModel.cours_status))
            )
            students = result.scalars().all()
            
            if len(students) != len(student_ids):
                missing_ids = set(student_ids) - {student.id for student in students}
                raise HTTPException(status_code=404, detail=f"Étudiants avec IDs {missing_ids} non trouvés")
            
            for student in students:
                if student.cours_status:
                    raise HTTPException(status_code=400, detail=f"Impossible de supprimer l'étudiant ID {student.id} en raison de statuts de cours associés")
            
            for student in students:
                self.db.delete(student)
            
            await self.db.commit()
        except HTTPException as e:
            raise e
        except Exception as e:
            await self._handle_exception(e)


# ============================
# School Service
# ============================

class SchoolService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_or_404(self, model, **kwargs) -> any:
        """Méthode générique pour récupérer un enregistrement ou lever une erreur 404."""
        result = await self.db.execute(select(model).filter_by(**kwargs))
        record = result.scalars().first()
        if not record:
            model_name = model.__tablename__.rstrip('s').capitalize()
            raise HTTPException(status_code=404, detail=f"{model_name} non trouvé")
        return record

    async def _check_unique_fields(self, emails: List[str], phones: List[str], website: Optional[str] = None, exclude_school_id: Optional[int] = None) -> None:
        """Vérifier que les emails, téléphones et site web ne sont pas utilisés par d'autres écoles."""
        query = select(SchoolModel)
        if exclude_school_id:
            query = query.filter(SchoolModel.id != exclude_school_id)

        result = await self.db.execute(query)
        existing_schools = result.scalars().all()

        for school in existing_schools:
            existing_emails = set(school.get_emails())
            existing_phones = set(school.get_phones())

            if any(email in existing_emails for email in emails):
                raise HTTPException(status_code=400, detail="Un ou plusieurs emails sont déjà utilisés par une autre école")
            if any(phone in existing_phones for phone in phones):
                raise HTTPException(status_code=400, detail="Un ou plusieurs numéros de téléphone sont déjà utilisés par une autre école")
            if website and school.website == website:
                raise HTTPException(status_code=400, detail="Site web déjà utilisé par une autre école")

    async def _validate_logo(self, file: UploadFile) -> str:
        """Valider et enregistrer le fichier de logo."""
        ext = file.filename.split(".")[-1].lower()
        if ext not in settings.allowed_extensions_list:
            raise HTTPException(status_code=400, detail=f"Type de fichier de logo invalide. Types autorisés : {', '.join(settings.allowed_extensions_list)}")

        file_size_mb = len(file.file.read()) / (1024 * 1024)
        if file_size_mb > settings.MAX_UPLOAD_SIZE_MB:
            raise HTTPException(status_code=400, detail=f"La taille du logo dépasse la limite de {settings.MAX_UPLOAD_SIZE_MB} MB")
        file.file.seek(0)

        filename = f"school_logo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file.filename.split('.')[-1]}"
        upload_path = Path(settings.UPLOAD_LOGO_DIR) / filename

        with open(upload_path, "wb") as f:
            f.write(file.file.read())

        return str(upload_path)

    async def create_school(self, school_create: SchoolCreate, logo_file: Optional[UploadFile] = File(None)) -> School:
        """Créer une nouvelle école avec validation des emails, téléphones et site web uniques."""
        await self._check_unique_fields(school_create.emails, school_create.phones, school_create.website)

        logo_path = None
        if logo_file:
            logo_path = self._validate_logo(logo_file)

        db_school = SchoolModel(**school_create.dict(exclude={"phones", "emails", "logo"}))
        db_school.set_phones(school_create.phones)
        db_school.set_emails(school_create.emails)

        if logo_path:
            db_school.logo = logo_path

        try:
            self.db.add(db_school)
            await self.db.commit()
            await self.db.refresh(db_school)
            return School.from_orm(db_school)
        except IntegrityError as e:
            await self.db.rollback()
            if "unique constraint" in str(e).lower():
                field = str(e).split('key ')[1].split('=')[0].strip()
                raise HTTPException(status_code=400, detail=f"École avec ce {field} existe déjà")
            raise HTTPException(status_code=400, detail="Données fournies invalides")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    async def get_school(self, school_id: int) -> School:
        """Récupérer une école par ID avec chargement des entités liées."""
        result = await self.db.execute(
            select(SchoolModel)
            .filter(SchoolModel.id == school_id)
            .options(
                joinedload(SchoolModel.admins),
                joinedload(SchoolModel.teacher_schools),
                joinedload(SchoolModel.sections),
                joinedload(SchoolModel.departements),
                joinedload(SchoolModel.students),
                joinedload(SchoolModel.ressources),
                joinedload(SchoolModel.evenements)
            )
        )
        school = result.scalars().first()
        if not school:
            raise HTTPException(status_code=404, detail="École non trouvée")
        return School.from_orm(school)

    async def get_all_schools(self, skip: int = 0, limit: int = 100) -> List[School]:
        """Récupérer toutes les écoles avec pagination, optimisé avec chargement des relations."""
        result = await self.db.execute(
            select(SchoolModel)
            .options(
                joinedload(SchoolModel.admins),
                joinedload(SchoolModel.teacher_schools)
            )
            .offset(skip)
            .limit(limit)
        )
        schools = result.scalars().all()
        return [School.from_orm(s) for s in schools]

    async def update_school(self, school_id: int, school_update: SchoolUpdate, logo_file: Optional[UploadFile] = File(None)) -> School:
        """Mettre à jour une école, en gérant les emails, téléphones, contraintes uniques et le logo."""
        school = await self._get_or_404(SchoolModel, id=school_id)
        update_data = school_update.dict(exclude_unset=True)

        if "emails" in update_data:
            await self._check_unique_fields(update_data["emails"], school.get_phones(), school.website, exclude_school_id=school_id)
            school.set_emails(update_data.pop("emails"))
        if "phones" in update_data:
            await self._check_unique_fields(school.get_emails(), update_data["phones"], school.website, exclude_school_id=school_id)
            school.set_phones(update_data.pop("phones"))
        if "website" in update_data:
            await self._check_unique_fields(school.get_emails(), school.get_phones(), update_data["website"], exclude_school_id=school_id)
            school.website = update_data.pop("website")

        if logo_file:
            logo_path = self._validate_logo(logo_file)
            school.logo = logo_path

        try:
            for key, value in update_data.items():
                setattr(school, key, value)

            await self.db.commit()
            await self.db.refresh(school)
            return School.from_orm(school)
        except IntegrityError as e:
            await self.db.rollback()
            if "unique constraint" in str(e).lower():
                field = str(e).split('key ')[1].split('=')[0].strip()
                raise HTTPException(status_code=400, detail=f"École avec ce {field} existe déjà")
            raise HTTPException(status_code=400, detail="Données de mise à jour invalides")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    async def delete_school(self, school_id: int) -> None:
        """Supprimer une école après vérification des entités associées."""
        result = await self.db.execute(
            select(SchoolModel)
            .filter(SchoolModel.id == school_id)
            .options(
                joinedload(SchoolModel.sections),
                joinedload(SchoolModel.departements),
                joinedload(SchoolModel.students),
                joinedload(SchoolModel.ressources),
                joinedload(SchoolModel.evenements)
            )
        )
        school = result.scalars().first()
        if not school:
            raise HTTPException(status_code=404, detail="École non trouvée")

        associated_entities = [
            (school.sections, "sections"),
            (school.departements, "départements"),
            (school.students, "étudiants"),
            (school.ressources, "ressources"),
            (school.evenements, "événements")
        ]
        for entities, entity_name in associated_entities:
            if entities:
                raise HTTPException(
                    status_code=400,
                    detail=f"Impossible de supprimer l'école avec des {entity_name} associés"
                )

        try:
            self.db.delete(school)
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    async def add_teachers_to_school(self, school_id: int, user_ids: List[int]) -> School:
        """Ajouter plusieurs utilisateurs comme enseignants à une école."""
        school = await self._get_or_404(SchoolModel, id=school_id)

        result = await self.db.execute(
            select(UserModel).filter(UserModel.id.in_(user_ids))
        )
        users = result.scalars().all()

        if len(users) != len(user_ids):
            missing_ids = set(user_ids) - {user.id for user in users}
            raise HTTPException(status_code=404, detail=f"Utilisateurs avec IDs {missing_ids} non trouvés")

        existing_teachers = {user.id for user in school.teacher_schools}
        already_teachers = [user_id for user_id in user_ids if user_id in existing_teachers]
        if already_teachers:
            raise HTTPException(status_code=400, detail=f"Utilisateurs avec IDs {already_teachers} sont déjà enseignants de cette école")

        try:
            for user in users:
                school.teacher_schools.append(user)
            await self.db.commit()
            await self.db.refresh(school)
            return School.from_orm(school)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    async def remove_teachers_from_school(self, school_id: int, user_ids: List[int]) -> School:
        """Retirer plusieurs utilisateurs comme enseignants d'une école."""
        school = await self._get_or_404(SchoolModel, id=school_id)

        result = await self.db.execute(
            select(UserModel).filter(UserModel.id.in_(user_ids))
        )
        users = result.scalars().all()

        if len(users) != len(user_ids):
            missing_ids = set(user_ids) - {user.id for user in users}
            raise HTTPException(status_code=404, detail=f"Utilisateurs avec IDs {missing_ids} non trouvés")

        current_teachers = {user.id for user in school.teacher_schools}
        not_teachers = [user_id for user_id in user_ids if user_id not in current_teachers]
        if not_teachers:
            raise HTTPException(status_code=400, detail=f"Utilisateurs avec IDs {not_teachers} ne sont pas enseignants de cette école")

        try:
            school.teacher_schools = [user for user in school.teacher_schools if user.id not in user_ids]
            await self.db.commit()
            await self.db.refresh(school)
            return School.from_orm(school)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        
        
# ============================
# Section Service
# ============================

class SectionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_section_or_404(self, section_id: int) -> SectionModel:
        """Récupérer une section par ID ou lever une erreur HTTP 404 si non trouvée."""
        result = await self.db.execute(
            select(SectionModel)
            .options(
                joinedload(SectionModel.filieres),
                joinedload(SectionModel.classes)
            )
            .filter(SectionModel.id == section_id)
        )
        section = result.scalars().first()
        if not section:
            raise HTTPException(404, "Section non trouvée")
        return section

    async def _get_school_or_400(self, school_id: int) -> SchoolModel:
        """Récupérer une école par ID ou lever une erreur HTTP 400 si non trouvée."""
        result = await self.db.execute(
            select(SchoolModel).filter(SchoolModel.id == school_id)
        )
        school = result.scalars().first()
        if not school:
            raise HTTPException(400, "École n'existe pas")
        return school

    async def _get_filiere_or_400(self, filiere_id: int) -> FiliereModel:
        """Récupérer une filière par ID ou lever une erreur HTTP 400 si non trouvée."""
        result = await self.db.execute(
            select(FiliereModel).filter(FiliereModel.id == filiere_id)
        )
        filiere = result.scalars().first()
        if not filiere:
            raise HTTPException(400, f"Filière {filiere_id} n'existe pas")
        return filiere

    async def create_section(self, section_create: SectionCreate) -> Section:
        """Créer une nouvelle section, en vérifiant que l'école et les filières sont valides."""
        await self._get_school_or_400(section_create.school_id)
        filieres = [await self._get_filiere_or_400(fid) for fid in section_create.filieres or []]

        db_section = SectionModel(
            school_id=section_create.school_id,
            name=section_create.name,
            filieres=filieres
        )

        try:
            self.db.add(db_section)
            await self.db.commit()
            await self.db.refresh(db_section)
            return Section.from_orm(db_section)
        except IntegrityError as e:
            await self.db.rollback()
            raise HTTPException(400, f"Erreur d'intégrité : {str(e)}")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_section(self, section_id: int) -> Section:
        """Récupérer une section par ID avec ses filières et classes associées."""
        section = await self._get_section_or_404(section_id)
        return Section.from_orm(section)

    async def get_all_sections(self, skip: int = 0, limit: int = 100) -> List[Section]:
        """Récupérer toutes les sections avec pagination, en chargeant les filières et classes."""
        result = await self.db.execute(
            select(SectionModel)
            .options(
                joinedload(SectionModel.filieres),
                joinedload(SectionModel.classes)
            )
            .offset(skip)
            .limit(limit)
        )
        sections = result.scalars().all()
        return [Section.from_orm(s) for s in sections]

    async def update_section(self, section_id: int, section_update: SectionUpdate) -> Section:
        """Mettre à jour une section existante, en vérifiant que les filières sont valides."""
        section = await self._get_section_or_404(section_id)
        update_data = section_update.dict(exclude_unset=True)

        if "filieres" in update_data:
            filieres = [await self._get_filiere_or_400(fid) for fid in update_data["filieres"]]
            section.filieres = filieres
            del update_data["filieres"]

        try:
            for key, value in update_data.items():
                setattr(section, key, value)

            await self.db.commit()
            await self.db.refresh(section)
            return Section.from_orm(section)
        except IntegrityError as e:
            await self.db.rollback()
            raise HTTPException(400, f"Erreur d'intégrité : {str(e)}")
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_sections(self, section_ids: List[int]) -> List[str]:
        """Supprimer plusieurs sections, en signalant celles qui ne peuvent pas être supprimées."""
        failed_deletions = []

        for section_id in section_ids:
            try:
                section = await self._get_section_or_404(section_id)
                
                if section.classes:
                    failed_deletions.append(f"La section {section_id} ne peut pas être supprimée (a des classes associées).")
                    continue
                
                self.db.delete(section)
                await self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"La section {section_id} ne peut pas être supprimée : {str(e)}")
                continue
            except Exception as e:
                await self.db.rollback()
                failed_deletions.append(f"La section {section_id} ne peut pas être supprimée en raison d'une erreur : {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Certaines sections n'ont pas pu être supprimées : " + ", ".join(failed_deletions))

        return []

    async def add_filieres_to_section(self, section_id: int, filiere_ids: List[int]) -> Section:
        """Ajouter une ou plusieurs filières à une section, en vérifiant qu'elles ne sont pas déjà ajoutées."""
        section = await self._get_section_or_404(section_id)

        result = await self.db.execute(
            select(FiliereModel).filter(FiliereModel.id.in_(filiere_ids))
        )
        filieres = result.scalars().all()

        missing_filier_ids = set(filiere_ids) - {filiere.id for filiere in filieres}
        if missing_filier_ids:
            raise HTTPException(status_code=404, detail=f"Filière(s) avec IDs {missing_filier_ids} non trouvée(s)")

        filieres_to_add = [filiere for filiere in filieres if filiere not in section.filieres]
        if not filieres_to_add:
            raise HTTPException(400, "Toutes les filières fournies sont déjà assignées à cette section")

        try:
            section.filieres.extend(filieres_to_add)
            await self.db.commit()
            await self.db.refresh(section)
            return Section.from_orm(section)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_filieres_from_section(self, section_id: int, filiere_ids: List[int] = None, filiere_id: int = None) -> Section:
        """Retirer une ou plusieurs filières d'une section."""
        section = await self._get_section_or_404(section_id)

        if filiere_id is not None:
            filiere_ids = [filiere_id]

        result = await self.db.execute(
            select(FiliereModel).filter(FiliereModel.id.in_(filiere_ids))
        )
        filieres = result.scalars().all()

        missing_filier_ids = set(filiere_ids) - {filiere.id for filiere in filieres}
        if missing_filier_ids:
            raise HTTPException(status_code=404, detail=f"Filière(s) avec IDs {missing_filier_ids} non trouvée(s)")

        filieres_to_remove = [filiere for filiere in filieres if filiere in section.filieres]
        if not filieres_to_remove:
            raise HTTPException(400, "Aucune des filières fournies n'est associée à cette section")

        try:
            for filiere in filieres_to_remove:
                section.filieres.remove(filiere)
            await self.db.commit()
            await self.db.refresh(section)
            return Section.from_orm(section)
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(500, str(e))

# ============================
# Filiere Service
# ============================

class FiliereService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_filiere_or_404(self, filiere_id: int) -> FiliereModel:
        """Retrieve a filiere by ID or raise HTTP 404 if not found."""
        filiere = self.db.query(FiliereModel).options(
            joinedload(FiliereModel.sections),
            joinedload(FiliereModel.specialites),
            joinedload(FiliereModel.classes),
            joinedload(FiliereModel.cours)
        ).filter(FiliereModel.id == filiere_id).first()
        if not filiere:
            raise HTTPException(404, "Filiere not found")
        return filiere

    async def _get_section_or_400(self, section_id: int) -> SectionModel:
        """Retrieve a section by ID or raise HTTP 400 if not found."""
        section = self.db.query(SectionModel).filter(SectionModel.id == section_id).first()
        if not section:
            raise HTTPException(400, f"Section {section_id} does not exist")
        return section

    async def _check_filiere_name_unique(self, name: str, exclude_filiere_id: int = None) -> None:
        """Check if the filiere name is unique."""
        query = self.db.query(FiliereModel).filter(FiliereModel.name == name)
        if exclude_filiere_id:
            query = query.filter(FiliereModel.id != exclude_filiere_id)
        if query.first():
            raise HTTPException(400, "Filiere with this name already exists")

    async def create_filiere(self, filiere_create: FiliereCreate) -> Filiere:
        """Create a new filiere with validation for unique name and sections."""
        self._check_filiere_name_unique(filiere_create.name)

        sections = [self._get_section_or_400(sid) for sid in filiere_create.sections or []]
        db_filiere = FiliereModel(name=filiere_create.name, sections=sections)

        try:
            self.db.add(db_filiere)
            self.db.commit()
            self.db.refresh(db_filiere)
            return Filiere.from_orm(db_filiere)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Filiere with this name already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_filiere(self, filiere_id: int) -> Filiere:
        """Retrieve a filiere by ID with its associated sections."""
        return Filiere.from_orm(self._get_filiere_or_404(filiere_id))

    async def get_all_filieres(self, skip=0, limit=100) -> List[Filiere]:
        """Retrieve all filieres with pagination, optimized with eager loading of relations."""
        filieres = self.db.query(FiliereModel).options(
            joinedload(FiliereModel.sections),
            joinedload(FiliereModel.specialites),
            joinedload(FiliereModel.classes),
            joinedload(FiliereModel.cours)
        ).offset(skip).limit(limit).all()
        return [Filiere.from_orm(f) for f in filieres]

    async def update_filiere(self, filiere_id: int, filiere_update: FiliereUpdate) -> Filiere:
        """Update an existing filiere, ensuring name uniqueness and handling sections."""
        filiere = self._get_filiere_or_404(filiere_id)
        update_data = filiere_update.dict(exclude_unset=True)

        if "name" in update_data:
            self._check_filiere_name_unique(update_data["name"], exclude_filiere_id=filiere_id)
            filiere.name = update_data.pop("name")

        if "sections" in update_data:
            sections = [self._get_section_or_400(sid) for sid in update_data["sections"]]
            filiere.sections = sections
            del update_data["sections"]

        try:
            for key, value in update_data.items():
                setattr(filiere, key, value)

            self.db.commit()
            self.db.refresh(filiere)
            return Filiere.from_orm(filiere)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_filieres(self, filiere_ids: List[int]) -> List[str]:
        """Delete multiple filieres, reporting which ones couldn't be deleted."""
        failed_deletions = []

        for filiere_id in filiere_ids:
            try:
                filiere = self._get_filiere_or_404(filiere_id)
                
                # Check if the filiere has associated entities like specialites, classes, or cours
                if filiere.specialites or filiere.classes or filiere.cours:
                    failed_deletions.append(f"Filiere {filiere_id} could not be deleted (has associated entities).")
                    continue  # Skip to the next filiere
                
                self.db.delete(filiere)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Filiere {filiere_id} could not be deleted: {str(e)}")
                continue  # Skip to the next filiere
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Filiere {filiere_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some filieres could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

    async def add_section_to_filiere(self, filiere_id: int, section_ids: List[int]) -> Filiere:
        """Add one or more sections to a filiere."""
        filiere = self._get_filiere_or_404(filiere_id)
        sections = [self._get_section_or_400(sid) for sid in section_ids]

        # Validate sections are not already associated with the filiere
        sections_to_add = [section for section in sections if section not in filiere.sections]
        if not sections_to_add:
            raise HTTPException(400, "All provided sections are already assigned to this filiere")

        try:
            filiere.sections.extend(sections_to_add)
            self.db.commit()
            self.db.refresh(filiere)
            return Filiere.from_orm(filiere)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_section_from_filiere(self, filiere_id: int, section_ids: List[int]) -> Filiere:
        """Remove one or more sections from a filiere."""
        filiere = self._get_filiere_or_404(filiere_id)
        sections = [self._get_section_or_400(sid) for sid in section_ids]

        # Validate sections exist in the filiere
        sections_to_remove = [section for section in sections if section in filiere.sections]
        if not sections_to_remove:
            raise HTTPException(400, "None of the provided sections are assigned to this filiere")

        try:
            for section in sections_to_remove:
                filiere.sections.remove(section)
            self.db.commit()
            self.db.refresh(filiere)
            return Filiere.from_orm(filiere)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))


# ============================
# Specialite Service
# ============================

class SpecialiteService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_specialite_or_404(self, specialite_id: int) -> SpecialiteModel:
        """Retrieve a specialite by ID or raise HTTP 404 if not found, with related cycles."""
        specialite = self.db.query(SpecialiteModel).options(
            joinedload(SpecialiteModel.cycles)  # Load cycles relationship
        ).filter(SpecialiteModel.id == specialite_id).first()
        if not specialite:
            raise HTTPException(404, "Specialite not found")
        return specialite

    async def _get_filiere_or_400(self, filiere_id: int) -> FiliereModel:
        """Retrieve a filiere by ID or raise HTTP 400 if not found."""
        filiere = self.db.query(FiliereModel).filter(FiliereModel.id == filiere_id).first()
        if not filiere:
            raise HTTPException(400, f"Filiere {filiere_id} does not exist")
        return filiere

    async def _get_cycle_or_400(self, cycle_id: int) -> CycleModel:
        """Retrieve a cycle by ID or raise HTTP 400 if not found."""
        cycle = self.db.query(CycleModel).filter(CycleModel.id == cycle_id).first()
        if not cycle:
            raise HTTPException(400, f"Cycle {cycle_id} does not exist")
        return cycle

    async def _check_specialite_name_unique(self, name: str, exclude_specialite_id: int = None) -> None:
        """Check if the specialite name is unique."""
        query = self.db.query(SpecialiteModel).filter(SpecialiteModel.name == name)
        if exclude_specialite_id:
            query = query.filter(SpecialiteModel.id != exclude_specialite_id)
        if query.first():
            raise HTTPException(400, "Specialite with this name already exists")

    async def create_specialite(self, specialite_create: SpecialiteCreate) -> Specialite:
        """Create a new specialite with validation for unique name and associated cycles."""
        self._check_specialite_name_unique(specialite_create.name)

        self._get_filiere_or_400(specialite_create.filiere_id)
        cycles = [self._get_cycle_or_400(cid) for cid in specialite_create.cycles or []]

        db_specialite = SpecialiteModel(
            filiere_id=specialite_create.filiere_id,
            name=specialite_create.name,
            cycles=cycles
        )

        try:
            self.db.add(db_specialite)
            self.db.commit()
            self.db.refresh(db_specialite)
            return Specialite.from_orm(db_specialite)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Specialite with this name already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_specialite(self, specialite_id: int) -> Specialite:
        """Retrieve a specialite by ID with its associated cycles."""
        return Specialite.from_orm(self._get_specialite_or_404(specialite_id))

    async def get_all_specialites(self, skip=0, limit=100) -> List[Specialite]:
        """Retrieve all specialites with pagination, optimized with eager loading of relations."""
        specialites = self.db.query(SpecialiteModel).options(
            joinedload(SpecialiteModel.cycles)
        ).offset(skip).limit(limit).all()
        return [Specialite.from_orm(s) for s in specialites]

    async def update_specialite(self, specialite_id: int, specialite_update: SpecialiteUpdate) -> Specialite:
        """Update an existing specialite, ensuring name uniqueness and handling cycles."""
        specialite = self._get_specialite_or_404(specialite_id)
        update_data = specialite_update.dict(exclude_unset=True)

        if "name" in update_data:
            self._check_specialite_name_unique(update_data["name"], exclude_specialite_id=specialite_id)
            specialite.name = update_data.pop("name")

        if "cycles" in update_data:
            cycles = [self._get_cycle_or_400(cid) for cid in update_data["cycles"]]
            specialite.cycles = cycles
            del update_data["cycles"]

        try:
            for key, value in update_data.items():
                setattr(specialite, key, value)

            self.db.commit()
            self.db.refresh(specialite)
            return Specialite.from_orm(specialite)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_specialites(self, specialite_ids: List[int]) -> List[str]:
        """Delete multiple specialites, reporting which ones couldn't be deleted due to associated entities."""
        failed_deletions = []

        for specialite_id in specialite_ids:
            try:
                specialite = self._get_specialite_or_404(specialite_id)

                # Check if the specialite has associated entities like classes or cours
                if specialite.classes or specialite.cours:
                    failed_deletions.append(f"Specialite {specialite_id} could not be deleted (has associated entities).")
                    continue  # Skip to the next specialite
                
                self.db.delete(specialite)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Specialite {specialite_id} could not be deleted: {str(e)}")
                continue  # Skip to the next specialite
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Specialite {specialite_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some specialites could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

    async def add_cycle_to_specialite(self, specialite_id: int, cycle_ids: List[int]) -> Specialite:
        """Add one or more cycles to a specialite."""
        specialite = self._get_specialite_or_404(specialite_id)
        cycles = [self._get_cycle_or_400(cycle_id) for cycle_id in cycle_ids]

        # Validate cycles are not already associated with the specialite
        cycles_to_add = [cycle for cycle in cycles if cycle not in specialite.cycles]
        if not cycles_to_add:
            raise HTTPException(400, "All provided cycles are already assigned to this specialite")

        try:
            specialite.cycles.extend(cycles_to_add)
            self.db.commit()
            self.db.refresh(specialite)
            return Specialite.from_orm(specialite)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_cycle_from_specialite(self, specialite_id: int, cycle_ids: List[int]) -> Specialite:
        """Remove one or more cycles from a specialite."""
        specialite = self._get_specialite_or_404(specialite_id)
        cycles = [self._get_cycle_or_400(cycle_id) for cycle_id in cycle_ids]

        # Validate cycles exist in the specialite
        cycles_to_remove = [cycle for cycle in cycles if cycle in specialite.cycles]
        if not cycles_to_remove:
            raise HTTPException(400, "None of the provided cycles are assigned to this specialite")

        try:
            for cycle in cycles_to_remove:
                specialite.cycles.remove(cycle)
            self.db.commit()
            self.db.refresh(specialite)
            return Specialite.from_orm(specialite)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))


# ============================
# Cycle Service
# ============================

class CycleService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_cycle_or_404(self, cycle_id: int) -> CycleModel:
        """Retrieve a cycle by ID or raise HTTP 404 if not found, with related specialites."""
        cycle = self.db.query(CycleModel).options(
            joinedload(CycleModel.specialites),  # Load specialites relationship
            joinedload(CycleModel.classes)  # Load classes relationship
        ).filter(CycleModel.id == cycle_id).first()
        if not cycle:
            raise HTTPException(404, "Cycle not found")
        return cycle

    async def _get_specialite_or_400(self, specialite_id: int) -> SpecialiteModel:
        """Retrieve a specialite by ID or raise HTTP 400 if not found."""
        specialite = self.db.query(SpecialiteModel).filter(SpecialiteModel.id == specialite_id).first()
        if not specialite:
            raise HTTPException(400, f"Specialite {specialite_id} does not exist")
        return specialite

    async def _check_cycle_name_unique(self, name: str, exclude_cycle_id: int = None) -> None:
        """Check if the cycle name is unique."""
        query = self.db.query(CycleModel).filter(CycleModel.name == name)
        if exclude_cycle_id:
            query = query.filter(CycleModel.id != exclude_cycle_id)
        if query.first():
            raise HTTPException(400, "Cycle with this name already exists")

    async def create_cycle(self, cycle_create: CycleCreate) -> Cycle:
        """Create a new cycle with validation for unique name and associated specialites."""
        self._check_cycle_name_unique(cycle_create.name)

        specialites = [self._get_specialite_or_400(sid) for sid in cycle_create.specialites or []]
        db_cycle = CycleModel(name=cycle_create.name, specialites=specialites)

        try:
            self.db.add(db_cycle)
            self.db.commit()
            self.db.refresh(db_cycle)
            return Cycle.from_orm(db_cycle)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Cycle with this name already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_cycle(self, cycle_id: int) -> Cycle:
        """Retrieve a cycle by ID with its associated specialites."""
        return Cycle.from_orm(self._get_cycle_or_404(cycle_id))

    async def get_all_cycles(self, skip=0, limit=100) -> List[Cycle]:
        """Retrieve all cycles with pagination, optimized with eager loading of relations."""
        cycles = self.db.query(CycleModel).options(
            joinedload(CycleModel.specialites),
            joinedload(CycleModel.classes)
        ).offset(skip).limit(limit).all()
        return [Cycle.from_orm(c) for c in cycles]

    async def update_cycle(self, cycle_id: int, cycle_update: CycleUpdate) -> Cycle:
        """Update an existing cycle, ensuring name uniqueness and handling specialites."""
        cycle = self._get_cycle_or_404(cycle_id)
        update_data = cycle_update.dict(exclude_unset=True)

        if "name" in update_data:
            self._check_cycle_name_unique(update_data["name"], exclude_cycle_id=cycle_id)
            cycle.name = update_data.pop("name")

        if "specialites" in update_data:
            specialites = [self._get_specialite_or_400(sid) for sid in update_data["specialites"]]
            cycle.specialites = specialites
            del update_data["specialites"]

        try:
            for key, value in update_data.items():
                setattr(cycle, key, value)

            self.db.commit()
            self.db.refresh(cycle)
            return Cycle.from_orm(cycle)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_cycles(self, cycle_ids: List[int]) -> List[str]:
        """Delete multiple cycles, reporting which ones couldn't be deleted due to associated entities."""
        failed_deletions = []

        for cycle_id in cycle_ids:
            try:
                cycle = self._get_cycle_or_404(cycle_id)

                # Check if the cycle has associated classes
                if cycle.classes:
                    failed_deletions.append(f"Cycle {cycle_id} could not be deleted (has associated classes).")
                    continue  # Skip to the next cycle
                
                self.db.delete(cycle)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Cycle {cycle_id} could not be deleted: {str(e)}")
                continue  # Skip to the next cycle
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Cycle {cycle_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some cycles could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

    async def delete_cycles(self, cycle_ids: List[int]) -> List[str]:
        """Delete multiple cycles, reporting which ones couldn't be deleted."""
        failed_deletions = []

        for cycle_id in cycle_ids:
            try:
                cycle = self._get_cycle_or_404(cycle_id)

                # Check if the cycle has associated classes
                if cycle.classes:
                    failed_deletions.append(f"Cycle {cycle_id} could not be deleted (has associated classes).")
                    continue  # Skip to the next cycle

                self.db.delete(cycle)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Cycle {cycle_id} could not be deleted: {str(e)}")
                continue  # Skip to the next cycle
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Cycle {cycle_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some cycles could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

    async def add_specialites_to_cycle(self, cycle_id: int, specialite_ids: List[int]) -> Cycle:
        """Add multiple specialites to a cycle."""
        cycle = self._get_cycle_or_404(cycle_id)
        specialites = [self._get_specialite_or_400(sid) for sid in specialite_ids]

        # Validate specialites are not already associated with the cycle
        specialites_to_add = [specialite for specialite in specialites if specialite not in cycle.specialites]
        if not specialites_to_add:
            raise HTTPException(400, "All provided specialites are already assigned to this cycle")

        try:
            cycle.specialites.extend(specialites_to_add)
            self.db.commit()
            self.db.refresh(cycle)
            return Cycle.from_orm(cycle)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_specialites_from_cycle(self, cycle_id: int, specialite_ids: List[int]) -> Cycle:
        """Remove multiple specialites from a cycle."""
        cycle = self._get_cycle_or_404(cycle_id)
        specialites = [self._get_specialite_or_400(sid) for sid in specialite_ids]

        # Validate specialites exist in the cycle
        specialites_to_remove = [specialite for specialite in specialites if specialite in cycle.specialites]
        if not specialites_to_remove:
            raise HTTPException(400, "None of the provided specialites are assigned to this cycle")

        try:
            for specialite in specialites_to_remove:
                cycle.specialites.remove(specialite)
            self.db.commit()
            self.db.refresh(cycle)
            return Cycle.from_orm(cycle)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))


# ============================
# Cours Service
# ============================

class CoursService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_cours_or_404(self, cours_id: int) -> CoursModel:
        """Retrieve a course by ID or raise HTTP 404 if not found, with related entities."""
        cours = self.db.query(CoursModel).options(
            joinedload(CoursModel.filiere),
            joinedload(CoursModel.specialite),
            joinedload(CoursModel.teachers),
            joinedload(CoursModel.classes),
            joinedload(CoursModel.ressources)
        ).filter(CoursModel.id == cours_id).first()
        if not cours:
            raise HTTPException(404, "Cours not found")
        return cours

    async def _get_filiere_or_400(self, filiere_id: int) -> FiliereModel:
        """Retrieve a filiere by ID or raise HTTP 400 if not found."""
        filiere = self.db.query(FiliereModel).filter(FiliereModel.id == filiere_id).first()
        if not filiere:
            raise HTTPException(400, "Filiere does not exist")
        return filiere

    async def _get_specialite_or_400(self, specialite_id: int) -> SpecialiteModel:
        """Retrieve a specialite by ID or raise HTTP 400 if not found."""
        specialite = self.db.query(SpecialiteModel).filter(SpecialiteModel.id == specialite_id).first()
        if not specialite:
            raise HTTPException(400, "Specialite does not exist")
        return specialite

    async def _get_teacher_or_400(self, teacher_id: int) -> TeacherModel:
        """Retrieve a teacher by ID or raise HTTP 400 if not found."""
        teacher = self.db.query(TeacherModel).filter(TeacherModel.id == teacher_id).first()
        if not teacher:
            raise HTTPException(400, f"Teacher {teacher_id} does not exist")
        return teacher

    async def _get_classe_or_400(self, classe_id: int) -> ClasseModel:
        """Retrieve a classe by ID or raise HTTP 400 if not found."""
        classe = self.db.query(ClasseModel).filter(ClasseModel.id == classe_id).first()
        if not classe:
            raise HTTPException(400, f"Classe {classe_id} does not exist")
        return classe

    async def _get_resource_or_400(self, resource_id: int) -> RessourceModel:
        """Retrieve a resource by ID or raise HTTP 400 if not found."""
        resource = self.db.query(RessourceModel).filter(RessourceModel.id == resource_id).first()
        if not resource:
            raise HTTPException(400, f"Resource {resource_id} does not exist")
        return resource

    async def _check_cours_name_unique(self, name: str, exclude_cours_id: int = None) -> None:
        """Check if the course name is unique."""
        query = self.db.query(CoursModel).filter(CoursModel.name == name)
        if exclude_cours_id:
            query = query.filter(CoursModel.id != exclude_cours_id)
        if query.first():
            raise HTTPException(400, "Cours with this name already exists")

    async def _generate_course_code(self) -> str:
        """Generate a unique course code in the format COURSES-*****-*****-annee_en_cours"""
        year = str(datetime.now().year)
        code = f"COURSES-{random.randint(10000, 99999)}-{random.randint(10000, 99999)}-{year}"
        return code

    async def _generate_dark_color(self) -> str:
        """Generate a random dark hex color code."""
        color = "#{:02x}{:02x}{:02x}".format(random.randint(0, 50), random.randint(0, 50), random.randint(0, 50))
        return color

    async def create_course(self, course_create: CoursCreate) -> Cours:
        """Create a new course with validation for unique name and automatic code generation."""
        self._check_cours_name_unique(course_create.name)

        filiere = self._get_filiere_or_400(course_create.filiere_id)
        if course_create.specialite_id:
            specialite = self._get_specialite_or_400(course_create.specialite_id)
            if specialite.filiere_id != course_create.filiere_id:
                raise HTTPException(400, "Specialite must belong to the selected filiere")

        teachers = [self._get_teacher_or_400(tid) for tid in course_create.teachers or []]
        classes = [self._get_classe_or_400(cid) for cid in course_create.classes or []]
        resources = [self._get_resource_or_400(rid) for rid in course_create.ressources or []]

        # Generate course code and color
        course_code = self._generate_course_code()
        color = self._generate_dark_color()

        db_course = CoursModel(
            **course_create.dict(exclude={"teachers", "classes", "ressources"}),
            code=course_code,
            color=color,
            teachers=teachers,
            classes=classes,
            ressources=resources
        )

        try:
            self.db.add(db_course)
            self.db.commit()
            self.db.refresh(db_course)
            return Cours.from_orm(db_course)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Course with this name or code already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_course(self, course_id: int) -> Cours:
        """Retrieve a course by ID with its associated entities."""
        return Cours.from_orm(self._get_cours_or_404(course_id))

    async def get_all_courses(self, skip=0, limit=100) -> List[Cours]:
        """Retrieve all courses with pagination, optimized with eager loading of relations."""
        courses = (
            self.db.query(CoursModel)
            .options(
                joinedload(CoursModel.filiere),       # Load filiere relationship
                joinedload(CoursModel.specialite),     # Load specialite relationship
                joinedload(CoursModel.teachers),       # Load teachers relationship
                joinedload(CoursModel.classes),        # Load classes relationship
                joinedload(CoursModel.ressources)      # Load ressources relationship
            )
            .offset(skip)
            .limit(limit)
            .all()
        )
        return [Cours.from_orm(c) for c in courses]

    async def update_course(self, course_id: int, course_update: CoursUpdate) -> Cours:
        """Update an existing course, ensuring name uniqueness and handling related entities."""
        db_course = self.db.query(CoursModel).filter(CoursModel.id == course_id).first()
        if not db_course:
            raise HTTPException(404, "Course not found")

        update_data = course_update.dict(exclude_unset=True)

        if "filiere_id" in update_data and update_data["filiere_id"]:
            self._get_filiere_or_400(update_data["filiere_id"])

        if "specialite_id" in update_data and update_data["specialite_id"]:
            specialite = self._get_specialite_or_400(update_data["specialite_id"])
            filiere_id = update_data.get("filiere_id", db_course.filiere_id)
            if specialite.filiere_id != filiere_id:
                raise HTTPException(400, "Specialite must match the filiere")

        if "teachers" in update_data:
            teachers = [self._get_teacher_or_400(tid) for tid in update_data["teachers"]]
            db_course.teachers = teachers

        if "classes" in update_data:
            classes = [self._get_classe_or_400(cid) for cid in update_data["classes"]]
            db_course.classes = classes

        if "resources" in update_data:
            resources = [self._get_resource_or_400(rid) for rid in update_data["resources"]]
            db_course.ressources = resources

        for k, v in update_data.items():
            if k not in {"teachers", "classes", "resources"}:
                setattr(db_course, k, v)

        try:
            self.db.commit()
            self.db.refresh(db_course)
            return Cours.from_orm(db_course)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_courses(self, course_ids: List[int]) -> List[str]:
        """Delete multiple courses, reporting which ones couldn't be deleted due to associated entities."""
        failed_deletions = []

        for course_id in course_ids:
            try:
                db_course = self.db.query(CoursModel).filter(CoursModel.id == course_id).first()
                if not db_course:
                    failed_deletions.append(f"Course {course_id} not found.")
                    continue  # Skip to the next course

                # Check if the course has associated entities like classes, teachers, etc.
                if db_course.classes or db_course.teachers or db_course.ressources:
                    failed_deletions.append(f"Course {course_id} could not be deleted (has associated entities).")
                    continue  # Skip to the next course

                self.db.delete(db_course)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Course {course_id} could not be deleted: {str(e)}")
                continue  # Skip to the next course
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Course {course_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some courses could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list
        
        
# ============================
# Classe Service
# ============================

class ClasseService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_classe_or_404(self, classe_id: int) -> ClasseModel:
        """Retrieve a classe by ID or raise HTTP 404 if not found, with related entities."""
        classe = self.db.query(ClasseModel).options(
            joinedload(ClasseModel.cours)  # Load cours relationship
        ).filter(ClasseModel.id == classe_id).first()
        if not classe:
            raise HTTPException(404, "Classe not found")
        return classe

    async def _get_filiere_or_400(self, filiere_id: int) -> FiliereModel:
        """Retrieve a filiere by ID or raise HTTP 400 if not found."""
        filiere = self.db.query(FiliereModel).filter(FiliereModel.id == filiere_id).first()
        if not filiere:
            raise HTTPException(400, "Filiere does not exist")
        return filiere

    async def _get_specialite_or_400(self, specialite_id: int) -> SpecialiteModel:
        """Retrieve a specialite by ID or raise HTTP 400 if not found."""
        specialite = self.db.query(SpecialiteModel).filter(SpecialiteModel.id == specialite_id).first()
        if not specialite:
            raise HTTPException(400, "Specialite does not exist")
        return specialite

    async def _get_cycle_or_400(self, cycle_id: int) -> CycleModel:
        """Retrieve a cycle by ID or raise HTTP 400 if not found."""
        cycle = self.db.query(CycleModel).filter(CycleModel.id == cycle_id).first()
        if not cycle:
            raise HTTPException(400, "Cycle does not exist")
        return cycle

    async def _get_cours_or_400(self, cours_id: int) -> CoursModel:
        """Retrieve a cours by ID or raise HTTP 400 if not found."""
        cours = self.db.query(CoursModel).filter(CoursModel.id == cours_id).first()
        if not cours:
            raise HTTPException(400, f"Cours {cours_id} does not exist")
        return cours

    async def create_classe(self, classe_create: ClasseCreate) -> Classe:
        """Create a new classe with validation for associated filiere, specialite, cycle, and cours."""
        self._get_filiere_or_400(classe_create.filiere_id)
        specialite = self._get_specialite_or_400(classe_create.specialite_id)
        if specialite.filiere_id != classe_create.filiere_id:
            raise HTTPException(400, "Specialite must belong to the filiere")
        cycle = self._get_cycle_or_400(classe_create.cycle_id)
        if specialite not in cycle.specialites:
            raise HTTPException(400, "Cycle must be associated with the specialite")

        if not (1 <= classe_create.level <= 5):
            raise HTTPException(400, "Level must be between 1 and 5")

        cours = [self._get_cours_or_400(cid) for cid in classe_create.cours or []]
        for c in cours:
            if c.filiere_id and c.filiere_id != classe_create.filiere_id:
                raise HTTPException(400, "Cours must match the filiere")

        db_classe = ClasseModel(**classe_create.dict(exclude={"cours"}), cours=cours)

        try:
            self.db.add(db_classe)
            self.db.commit()
            self.db.refresh(db_classe)
            return Classe.from_orm(db_classe)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Classe with this name or code already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_classe(self, classe_id: int) -> Classe:
        """Retrieve a classe by ID with its related entities."""
        return Classe.from_orm(self._get_classe_or_404(classe_id))

    async def get_all_classes(self, skip=0, limit=100) -> List[Classe]:
        """Retrieve all classes with pagination, optimized with eager loading of related entities."""
        classes = self.db.query(ClasseModel).options(
            joinedload(ClasseModel.cours)
        ).offset(skip).limit(limit).all()
        return [Classe.from_orm(c) for c in classes]

    async def update_classe(self, classe_id: int, classe_update: ClasseUpdate) -> Classe:
        """Update an existing classe, ensuring that associated entities are valid."""
        db_classe = self.db.query(ClasseModel).filter(ClasseModel.id == classe_id).first()
        if not db_classe:
            raise HTTPException(404, "Classe not found")

        update_data = classe_update.dict(exclude_unset=True)

        if "section_id" in update_data:
            self._get_section_or_400(update_data["section_id"])

        if "filiere_id" in update_data:
            self._get_filiere_or_400(update_data["filiere_id"])

        if "specialite_id" in update_data:
            specialite = self._get_specialite_or_400(update_data["specialite_id"])
            filiere_id = update_data.get("filiere_id", db_classe.filiere_id)
            if specialite.filiere_id != filiere_id:
                raise HTTPException(400, "Specialite must belong to the filiere")

        if "cycle_id" in update_data:
            cycle = self._get_cycle_or_400(update_data["cycle_id"])
            specialite_id = update_data.get("specialite_id", db_classe.specialite_id)
            specialite = self.db.query(SpecialiteModel).filter(SpecialiteModel.id == specialite_id).first()
            if specialite and specialite not in cycle.specialites:
                raise HTTPException(400, "Cycle must be associated with the specialite")

        if "level" in update_data and not (1 <= update_data["level"] <= 5):
            raise HTTPException(400, "Level must be between 1 and 5")

        if "cours" in update_data:
            cours = [self._get_cours_or_400(cid) for cid in update_data["cours"]]
            filiere_id = update_data.get("filiere_id", db_classe.filiere_id)
            for c in cours:
                if c.filiere_id and c.filiere_id != filiere_id:
                    raise HTTPException(400, "Cours must match the filiere")
            db_classe.cours = cours

        for k, v in update_data.items():
            if k != "cours":
                setattr(db_classe, k, v)

        try:
            self.db.commit()
            self.db.refresh(db_classe)
            return Classe.from_orm(db_classe)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_classes(self, classe_ids: List[int]) -> List[str]:
        """Delete multiple classes, reporting which ones couldn't be deleted."""
        failed_deletions = []
        failed_classe_ids = set()  # Keep track of IDs already in the failed_deletions

        for classe_id in classe_ids:
            if classe_id in failed_classe_ids:
                continue  # Skip this class if already failed
            
            try:
                db_classe = self.db.query(ClasseModel).filter(ClasseModel.id == classe_id).first()
                if not db_classe:
                    failed_deletions.append(f"Classe {classe_id} not found.")
                    failed_classe_ids.add(classe_id)
                    continue  # Skip to the next classe

                if db_classe.students or db_classe.occupations:
                    failed_deletions.append(f"Classe {classe_id} could not be deleted (has associated students or occupations).")
                    failed_classe_ids.add(classe_id)
                    continue  # Skip to the next classe

                self.db.delete(db_classe)
                self.db.commit()
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Classe {classe_id} could not be deleted due to an error: {str(e)}")
                failed_classe_ids.add(classe_id)

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some classes could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

    async def add_cours_to_classe(self, classe_id: int, cours_ids: List[int]) -> Classe:
        """Add multiple courses to a classe, ensuring they are not already added and they match the filiere."""
        db_classe = self.db.query(ClasseModel).filter(ClasseModel.id == classe_id).first()
        if not db_classe:
            raise HTTPException(404, "Classe not found")

        # Fetch all the courses in one query
        cours = [self._get_cours_or_400(cours_id) for cours_id in cours_ids]

        # Validate that the courses are not already assigned to the classe and match the filiere
        courses_to_add = []
        for c in cours:
            if c in db_classe.cours:
                raise HTTPException(400, f"Cours {c.id} already assigned to classe")
            if c.filiere_id and c.filiere_id != db_classe.filiere_id:
                raise HTTPException(400, f"Cours {c.id} must match the filiere")
            courses_to_add.append(c)

        try:
            db_classe.cours.extend(courses_to_add)
            self.db.commit()
            self.db.refresh(db_classe)
            return Classe.from_orm(db_classe)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def remove_cours_from_classe(self, classe_id: int, cours_ids: List[int]) -> Classe:
        """Remove multiple courses from a classe."""
        db_classe = self.db.query(ClasseModel).filter(ClasseModel.id == classe_id).first()
        if not db_classe:
            raise HTTPException(404, "Classe not found")

        # Fetch all the courses in one query
        cours = [self._get_cours_or_400(cours_id) for cours_id in cours_ids]

        # Validate that the courses are assigned to the classe
        courses_to_remove = []
        for c in cours:
            if c not in db_classe.cours:
                raise HTTPException(400, f"Cours {c.id} not assigned to this classe")
            courses_to_remove.append(c)

        try:
            for course in courses_to_remove:
                db_classe.cours.remove(course)
            self.db.commit()
            self.db.refresh(db_classe)
            return Classe.from_orm(db_classe)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

# ============================
# Salle Service
# ============================

class SalleService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_salle_or_404(self, salle_id: int) -> SalleModel:
        """Retrieve a salle by ID or raise HTTP 404 if not found, with related occupations and reservations."""
        salle = self.db.query(SalleModel).options(
            joinedload(SalleModel.occupations),  # Load occupations relationship
            joinedload(SalleModel.reservations)  # Load reservations relationship
        ).filter(SalleModel.id == salle_id).first()
        if not salle:
            raise HTTPException(404, "Salle not found")
        return salle

    async def _validate_capacity(self, capacity: int) -> None:
        """Validate that the capacity is strictly positive."""
        if capacity <= 0:
            raise HTTPException(400, "Capacity must be strictly positive")

    async def create_salle(self, salle_create: SalleCreate) -> Salle:
        """Create a new salle, ensuring the capacity is valid and handling unique constraints."""
        self._validate_capacity(salle_create.capacity)
        
        # Check for any existing salle with the same name or code
        existing_salle = self.db.query(SalleModel).filter(SalleModel.name == salle_create.name).first()
        if existing_salle:
            raise HTTPException(400, "Salle with this name already exists")

        db_salle = SalleModel(**salle_create.dict())

        try:
            self.db.add(db_salle)
            self.db.commit()
            self.db.refresh(db_salle)
            return Salle.from_orm(db_salle)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Salle with this name or code already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_salle(self, salle_id: int) -> Salle:
        """Retrieve a salle by ID with its related occupations and reservations."""
        return Salle.from_orm(self._get_salle_or_404(salle_id))

    async def get_all_salles(self, skip=0, limit=100) -> List[Salle]:
        """Retrieve all salles with pagination, optimized with eager loading of relations."""
        salles = self.db.query(SalleModel).options(
            joinedload(SalleModel.occupations),
            joinedload(SalleModel.reservations)
        ).offset(skip).limit(limit).all()
        return [Salle.from_orm(s) for s in salles]

    async def update_salle(self, salle_id: int, salle_update: SalleUpdate) -> Salle:
        """Update an existing salle, ensuring capacity is valid."""
        db_salle = self._get_salle_or_404(salle_id)
        update_data = salle_update.dict(exclude_unset=True)

        if "capacity" in update_data:
            self._validate_capacity(update_data["capacity"])

        try:
            for key, value in update_data.items():
                setattr(db_salle, key, value)

            self.db.commit()
            self.db.refresh(db_salle)
            return Salle.from_orm(db_salle)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_salles(self, salle_ids: List[int]) -> List[str]:
        """Delete multiple salles, reporting which ones couldn't be deleted due to associated entities."""
        failed_deletions = []
        failed_salle_ids = set()  # Keep track of IDs already in the failed_deletions list

        for salle_id in salle_ids:
            if salle_id in failed_salle_ids:
                continue  # Skip this salle if already failed

            try:
                db_salle = self._get_salle_or_404(salle_id)

                # Check if the salle has associated occupations or reservations
                if db_salle.occupations or db_salle.reservations:
                    failed_deletions.append(f"Salle {salle_id} could not be deleted (has associated occupations or reservations).")
                    failed_salle_ids.add(salle_id)
                    continue  # Skip to the next salle

                self.db.delete(db_salle)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Salle {salle_id} could not be deleted: {str(e)}")
                failed_salle_ids.add(salle_id)
                continue  # Skip to the next salle
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Salle {salle_id} could not be deleted due to an error: {str(e)}")
                failed_salle_ids.add(salle_id)

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some salles could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

# ============================
# Occupation Service
# ============================

class OccupationService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_or_404(self, model, model_id: int, name: str):
        """Retrieve an instance by ID or raise HTTP 404 if not found."""
        instance = self.db.query(model).filter(model.id == model_id).first()
        if not instance:
            raise HTTPException(404, f"{name} not found")
        return instance

    async def _validate_teacher_course_relation(self, teacher_id: int, cours_id: int):
        """Ensure that a teacher is associated with the given course."""
        relation = self.db.query(teacher_cours).filter(
            and_(
                teacher_cours.c.teacher_id == teacher_id,
                teacher_cours.c.cours_id == cours_id
            )
        ).first()
        if not relation:
            raise HTTPException(400, "Teacher must be associated with the course")

    async def _validate_time_range(self, start: time, end: time):
        """Ensure the time range is valid (08:00 to 17:00) and end time is after start time."""
        if not (time(8, 0) <= start < end <= time(17, 0)):
            raise HTTPException(400, "Times must be between 08:00 and 17:00, and end time must be after start time")

    async def _validate_teacher_availability(self, teacher_id: int, jour, heure_debut: time, heure_fin: time):
        """Check if a teacher is available at the specified time."""
        availability = self.db.query(TeacherAvailabilityModel).filter(
            and_(
                TeacherAvailabilityModel.teacher_id == teacher_id,
                TeacherAvailabilityModel.date == jour,
                TeacherAvailabilityModel.start_time <= heure_debut,
                TeacherAvailabilityModel.end_time >= heure_fin
            )
        ).first()
        if not availability:
            raise HTTPException(400, "Teacher is not available at the specified time")

    async def _validate_resources_reserved(self, occupation_id: int, cours_id: int, jour, heure_debut: time, heure_fin: time):
        """Ensure that all required resources for the course are reserved."""
        required_resources = self.db.query(cours_ressources).filter(cours_ressources.c.cours_id == cours_id).all()
        if not required_resources:
            return
        reservation = self.db.query(ReservationModel).filter(
            and_(
                ReservationModel.occupation_id == occupation_id,
                ReservationModel.status == ReservationStatusEnum.APPROVED
            )
        ).first()
        if not reservation:
            raise HTTPException(400, "Approved reservation for required resources is missing")
        reserved_ids = {r.id for r in reservation.ressources}
        required_ids = {r.ressource_id for r in required_resources}
        if not required_ids.issubset(reserved_ids):
            raise HTTPException(400, "All required resources must be reserved")

    async def create_occupation(self, occupation: OccupationCreate) -> Occupation:
        """Create a new occupation, ensuring the constraints and relations are valid."""
        salle = self._get_or_404(SalleModel, occupation.salle_id, "Salle")
        classe = self._get_or_404(ClasseModel, occupation.classe_id, "Classe")
        cours = self._get_or_404(CoursModel, occupation.cours_id, "Cours")

        if cours not in classe.cours:
            raise HTTPException(400, "Cours must be associated with the classe")

        teacher = self._get_or_404(TeacherModel, occupation.teacher_id, "Teacher")
        self._validate_teacher_course_relation(occupation.teacher_id, occupation.cours_id)
        self._validate_time_range(occupation.heure_debut, occupation.heure_fin)
        self._validate_teacher_availability(occupation.teacher_id, occupation.jour, occupation.heure_debut, occupation.heure_fin)

        # Check resources reservation only if there are required resources
        self._validate_resources_reserved(occupation_id=None, cours_id=occupation.cours_id,
                                          jour=occupation.jour,
                                          heure_debut=occupation.heure_debut,
                                          heure_fin=occupation.heure_fin)

        db_occupation = OccupationModel(**occupation.dict())
        try:
            self.db.add(db_occupation)
            self.db.commit()
            self.db.refresh(db_occupation)
            return Occupation.from_orm(db_occupation)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid occupation data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_occupation(self, occupation_id: int) -> Occupation:
        """Retrieve a single occupation by ID."""
        occupation = self._get_or_404(OccupationModel, occupation_id, "Occupation")
        return Occupation.from_orm(occupation)

    async def get_all_occupations(self, skip=0, limit=100) -> List[Occupation]:
        """Retrieve all occupations with pagination."""
        occupations = self.db.query(OccupationModel).offset(skip).limit(limit).all()
        return [Occupation.from_orm(o) for o in occupations]

    async def update_occupation(self, occupation_id: int, occupation_update: OccupationUpdate) -> Occupation:
        """Update an existing occupation."""
        db_occupation = self._get_or_404(OccupationModel, occupation_id, "Occupation")
        update_data = occupation_update.dict(exclude_unset=True)

        if "salle_id" in update_data:
            self._get_or_404(SalleModel, update_data["salle_id"], "Salle")

        if "classe_id" in update_data:
            self._get_or_404(ClasseModel, update_data["classe_id"], "Classe")

        if "cours_id" in update_data:
            cours = self._get_or_404(CoursModel, update_data["cours_id"], "Cours")
            classe_id = update_data.get("classe_id", db_occupation.classe_id)
            classe = self._get_or_404(ClasseModel, classe_id, "Classe")
            if cours not in classe.cours:
                raise HTTPException(400, "Cours must be associated with the classe")

        if "teacher_id" in update_data:
            teacher = self._get_or_404(TeacherModel, update_data["teacher_id"], "Teacher")
            cours_id = update_data.get("cours_id", db_occupation.cours_id)
            self._validate_teacher_course_relation(update_data["teacher_id"], cours_id)

        if any(k in update_data for k in ["jour", "heure_debut", "heure_fin", "teacher_id"]):
            teacher_id = update_data.get("teacher_id", db_occupation.teacher_id)
            jour = update_data.get("jour", db_occupation.jour)
            heure_debut = update_data.get("heure_debut", db_occupation.heure_debut)
            heure_fin = update_data.get("heure_fin", db_occupation.heure_fin)
            self._validate_time_range(heure_debut, heure_fin)
            self._validate_teacher_availability(teacher_id, jour, heure_debut, heure_fin)

        if "cours_id" in update_data:
            self._validate_resources_reserved(
                occupation_id=occupation_id,
                cours_id=update_data["cours_id"],
                jour=update_data.get("jour", db_occupation.jour),
                heure_debut=update_data.get("heure_debut", db_occupation.heure_debut),
                heure_fin=update_data.get("heure_fin", db_occupation.heure_fin),
            )

        try:
            for key, value in update_data.items():
                setattr(db_occupation, key, value)
            self.db.commit()
            self.db.refresh(db_occupation)
            return Occupation.from_orm(db_occupation)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_occupations(self, occupation_ids: List[int]) -> List[str]:
        """Delete multiple occupations, reporting which ones couldn't be deleted."""
        failed_deletions = []

        for occupation_id in occupation_ids:
            try:
                db_occupation = self._get_or_404(OccupationModel, occupation_id, "Occupation")
                if db_occupation.reservations:
                    failed_deletions.append(f"Occupation {occupation_id} could not be deleted (has associated reservations).")
                    continue  # Skip to the next occupation

                self.db.delete(db_occupation)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Occupation {occupation_id} could not be deleted: {str(e)}")
                continue  # Skip to the next occupation
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Occupation {occupation_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some occupations could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

# ============================
# Ressource Service
# ============================

class RessourceService:
    VALID_STATUSES = {"neuf", "usagé", "endommagé", "en réparation"}

    def __init__(self, db: Session):
        self.db = db

    async def _get_school_or_400(self, school_id: int) -> SchoolModel:
        """Retrieve a school by ID or raise HTTP 400 if not found."""
        school = self.db.query(SchoolModel).filter(SchoolModel.id == school_id).first()
        if not school:
            raise HTTPException(400, "School does not exist")
        return school

    async def _get_ressource_or_404(self, ressource_id: int) -> RessourceModel:
        """Retrieve a ressource by ID or raise HTTP 404 if not found, with related courses and reservations."""
        ressource = self.db.query(RessourceModel).options(
            joinedload(RessourceModel.cours),  # Load related courses
            joinedload(RessourceModel.reservations)  # Load related reservations
        ).filter(RessourceModel.id == ressource_id).first()
        if not ressource:
            raise HTTPException(404, "Ressource not found")
        return ressource

    async def _get_cours_or_404(self, cours_id: int) -> CoursModel:
        """Retrieve a cours by ID or raise HTTP 404 if not found."""
        cours = self.db.query(CoursModel).filter(CoursModel.id == cours_id).first()
        if not cours:
            raise HTTPException(404, "Cours not found")
        return cours

    async def _validate_status(self, status: Optional[str]) -> None:
        """Validate that the status is one of the valid statuses."""
        if status and status.lower() not in self.VALID_STATUSES:
            raise HTTPException(
                400,
                f"Status must be one of {sorted(self.VALID_STATUSES)}"
            )

    async def create_ressource(self, ressource_data: RessourceCreate) -> Ressource:
        """Create a new ressource, ensuring the capacity is valid and handling unique constraints."""
        self._get_school_or_400(ressource_data.school_id)
        if ressource_data.quantity < 0:
            raise HTTPException(400, "Quantity cannot be negative")
        self._validate_status(ressource_data.status)

        # Check for any existing ressource with the same code
        existing_ressource = self.db.query(RessourceModel).filter(RessourceModel.code == ressource_data.code).first()
        if existing_ressource:
            raise HTTPException(400, "Ressource with this code already exists")

        db_ressource = RessourceModel(**ressource_data.dict())

        try:
            self.db.add(db_ressource)
            self.db.commit()
            self.db.refresh(db_ressource)
            return Ressource.from_orm(db_ressource)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Ressource with this code already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_ressource(self, ressource_id: int) -> Ressource:
        """Retrieve a ressource by ID with its related courses and reservations."""
        return Ressource.from_orm(self._get_ressource_or_404(ressource_id))

    async def get_all_ressources(self, skip=0, limit=100) -> List[Ressource]:
        """Retrieve all ressources with pagination, optimized with eager loading of relations."""
        ressources = self.db.query(RessourceModel).options(
            joinedload(RessourceModel.cours),
            joinedload(RessourceModel.reservations)
        ).offset(skip).limit(limit).all()
        return [Ressource.from_orm(r) for r in ressources]

    async def update_ressource(self, ressource_id: int, update_data: RessourceUpdate) -> Ressource:
        """Update an existing ressource, ensuring that constraints are met."""
        db_ressource = self._get_ressource_or_404(ressource_id)
        data = update_data.dict(exclude_unset=True)

        if "school_id" in data:
            self._get_school_or_400(data["school_id"])
        if "quantity" in data and data["quantity"] < 0:
            raise HTTPException(400, "Quantity cannot be negative")
        if "status" in data:
            self._validate_status(data["status"])

        try:
            for key, value in data.items():
                setattr(db_ressource, key, value)

            self.db.commit()
            self.db.refresh(db_ressource)
            return Ressource.from_orm(db_ressource)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_ressources(self, ressource_ids: List[int]) -> List[str]:
        """Delete multiple ressources, reporting which ones couldn't be deleted due to associated entities."""
        failed_deletions = []

        for ressource_id in ressource_ids:
            try:
                db_ressource = self._get_ressource_or_404(ressource_id)
                if db_ressource.cours or db_ressource.reservations:
                    failed_deletions.append(f"Ressource {ressource_id} could not be deleted (has associated courses or reservations).")
                    continue  # Skip to the next ressource

                self.db.delete(db_ressource)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Ressource {ressource_id} could not be deleted: {str(e)}")
                continue  # Skip to the next ressource
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Ressource {ressource_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some ressources could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list

    async def add_cours_to_ressource(self, ressource_id: int, cours_id: int) -> Ressource:
        """Add a course to a ressource, ensuring it is not already added."""
        db_ressource = self._get_ressource_or_404(ressource_id)
        cours = self._get_cours_or_404(cours_id)

        if cours in db_ressource.cours:
            raise HTTPException(400, "Cours already assigned to ressource")
        try:
            db_ressource.cours.append(cours)
            self.db.commit()
            self.db.refresh(db_ressource)
            return Ressource.from_orm(db_ressource)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))


# ============================
# Evenement Service
# ============================

class EvenementService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_school_or_400(self, school_id: int) -> SchoolModel:
        """Retrieve a school by ID or raise HTTP 400 if not found."""
        school = self.db.query(SchoolModel).filter(SchoolModel.id == school_id).first()
        if not school:
            raise HTTPException(400, "School does not exist")
        return school

    async def _get_evenement_or_404(self, evenement_id: int) -> EvenementModel:
        """Retrieve an evenement by ID or raise HTTP 404 if not found, with related reservations."""
        evenement = self.db.query(EvenementModel).options(
            joinedload(EvenementModel.reservations)  # Load related reservations
        ).filter(EvenementModel.id == evenement_id).first()
        if not evenement:
            raise HTTPException(404, "Evenement not found")
        return evenement

    async def _validate_datetime(self, start_datetime: datetime, end_datetime: datetime) -> None:
        """Ensure the end datetime is after the start datetime."""
        if end_datetime <= start_datetime:
            raise HTTPException(400, "End datetime must be after start datetime")

    async def _check_for_datetime_conflicts(self, start_datetime: datetime, end_datetime: datetime) -> None:
        """Ensure there are no conflicting events in the system."""
        conflicting_event = self.db.query(EvenementModel).filter(
            EvenementModel.start_datetime < end_datetime,
            EvenementModel.end_datetime > start_datetime
        ).first()
        if conflicting_event:
            raise HTTPException(400, "The event time conflicts with an existing event.")

    async def create_evenement(self, evenement_data: EvenementCreate) -> Evenement:
        """Create a new evenement with validation for datetime and relations."""
        self._get_school_or_400(evenement_data.school_id)
        self._validate_datetime(evenement_data.start_datetime, evenement_data.end_datetime)
        self._check_for_datetime_conflicts(evenement_data.start_datetime, evenement_data.end_datetime)

        # Check for existing evenement with the same code
        existing_evenement = self.db.query(EvenementModel).filter(EvenementModel.code == evenement_data.code).first()
        if existing_evenement:
            raise HTTPException(400, "Evenement with this code already exists")

        db_evenement = EvenementModel(**evenement_data.dict())

        try:
            self.db.add(db_evenement)
            self.db.commit()
            self.db.refresh(db_evenement)
            return Evenement.from_orm(db_evenement)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Evenement with this code already exists")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_evenement(self, evenement_id: int) -> Evenement:
        """Retrieve a single evenement by ID with its related reservations."""
        return Evenement.from_orm(self._get_evenement_or_404(evenement_id))

    async def get_all_evenements(self, skip=0, limit=100) -> List[Evenement]:
        """Retrieve all evenements with pagination, optimized with eager loading of relations."""
        evenements = self.db.query(EvenementModel).options(
            joinedload(EvenementModel.reservations)  # Load related reservations
        ).offset(skip).limit(limit).all()
        return [Evenement.from_orm(ev) for ev in evenements]

    async def update_evenement(self, evenement_id: int, evenement_update: EvenementUpdate) -> Evenement:
        """Update an existing evenement with validation for datetime and relations."""
        db_evenement = self._get_evenement_or_404(evenement_id)
        update_data = evenement_update.dict(exclude_unset=True)

        if "start_datetime" in update_data and "end_datetime" in update_data:
            self._validate_datetime(update_data["start_datetime"], update_data["end_datetime"])
            self._check_for_datetime_conflicts(update_data["start_datetime"], update_data["end_datetime"])

        try:
            for k, v in update_data.items():
                setattr(db_evenement, k, v)

            self.db.commit()
            self.db.refresh(db_evenement)
            return Evenement.from_orm(db_evenement)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_evenements(self, evenement_ids: List[int]) -> List[str]:
        """Delete multiple evenements, reporting which ones couldn't be deleted."""
        failed_deletions = []

        for evenement_id in evenement_ids:
            try:
                db_evenement = self._get_evenement_or_404(evenement_id)
                if db_evenement.reservations:
                    failed_deletions.append(f"Evenement {evenement_id} could not be deleted (has associated reservations).")
                    continue  # Skip to the next evenement

                self.db.delete(db_evenement)
                self.db.commit()
            except HTTPException as e:
                failed_deletions.append(f"Evenement {evenement_id} could not be deleted: {str(e)}")
                continue  # Skip to the next evenement
            except Exception as e:
                self.db.rollback()
                failed_deletions.append(f"Evenement {evenement_id} could not be deleted due to an error: {str(e)}")

        if failed_deletions:
            raise HTTPException(status_code=400, detail="Some evenements could not be deleted: " + ", ".join(failed_deletions))

        return []  # If all deletions succeed, return an empty list


# ============================
# Reservation Service
# ============================

class ReservationService:
    def __init__(self, db: Session):
        self.db = db

    async def _get_user_or_400(self, user_id: int) -> UserModel:
        user = self.db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(400, "User does not exist")
        return user

    async def _get_occupation_or_400(self, occupation_id: int) -> OccupationModel:
        occupation = self.db.query(OccupationModel).filter(OccupationModel.id == occupation_id).first()
        if not occupation:
            raise HTTPException(400, "Occupation does not exist")
        return occupation

    async def _get_evenement_or_400(self, evenement_id: int) -> EvenementModel:
        evenement = self.db.query(EvenementModel).filter(EvenementModel.id == evenement_id).first()
        if not evenement:
            raise HTTPException(400, "Evenement does not exist")
        return evenement

    async def _get_salle_or_400(self, salle_id: int) -> SalleModel:
        salle = self.db.query(SalleModel).filter(SalleModel.id == salle_id).first()
        if not salle:
            raise HTTPException(400, "Salle does not exist")
        return salle

    async def _get_admin_or_400(self, admin_id: int) -> UserModel:
        admin = self.db.query(UserModel).filter(UserModel.id == admin_id).first()
        if not admin:
            raise HTTPException(400, "Admin does not exist")
        return admin

    async def _check_admin_belongs_to_school(self, admin_id: int, school_ids: set):
        is_admin = self.db.query(school_admins).filter(
            and_(
                school_admins.c.user_id == admin_id,
                school_admins.c.school_id.in_(school_ids)
            )
        ).first()
        if not is_admin:
            raise HTTPException(400, "Admin must belong to the school of the resource or salle")

    async def _update_ressource_stock(self, ressource_id: int, quantity_reserved: int):
        """Update the stock of the resource when it's reserved."""
        ressource = self.db.query(RessourceModel).filter(RessourceModel.id == ressource_id).first()
        if not ressource:
            raise HTTPException(400, f"Resource {ressource_id} does not exist")

        if ressource.quantity < quantity_reserved:
            raise HTTPException(400, "Not enough stock available")
        
        # Decrease the stock
        ressource.quantity -= quantity_reserved
        self.db.commit()

    async def _reset_ressource_stock(self, ressource_id: int, quantity_reserved: int):
        """Reset the resource stock after reservation period ends."""
        ressource = self.db.query(RessourceModel).filter(RessourceModel.id == ressource_id).first()
        if ressource:
            ressource.quantity += quantity_reserved
            self.db.commit()

    async def create_reservation(self, reservation: ReservationCreate) -> Reservation:
        user = self._get_user_or_400(reservation.user_id)

        # Ensure only one of occupation_id or evenement_id is provided
        if reservation.occupation_id and reservation.evenement_id:
            raise HTTPException(400, "Reservation cannot be linked to both occupation and evenement")

        occupation = None
        if reservation.occupation_id:
            occupation = self._get_occupation_or_400(reservation.occupation_id)

        evenement = None
        if reservation.evenement_id:
            evenement = self._get_evenement_or_400(reservation.evenement_id)

        salle = None
        if reservation.salle_id:
            salle = self._get_salle_or_400(reservation.salle_id)

            # Check for conflicting reservations for the same salle
            conflict_reservation = self.db.query(ReservationModel).filter(
                and_(
                    ReservationModel.salle_id == reservation.salle_id,
                    ReservationModel.status == ReservationStatusEnum.APPROVED,
                    ReservationModel.start_datetime < reservation.end_datetime,
                    ReservationModel.end_datetime > reservation.start_datetime
                )
            ).first()
            if conflict_reservation:
                raise HTTPException(400, "Salle is already reserved for this time period")

            # Check for conflicting occupations
            if reservation.start_datetime and reservation.end_datetime:
                conflict_occupation = self.db.query(OccupationModel).filter(
                    and_(
                        OccupationModel.salle_id == reservation.salle_id,
                        OccupationModel.date == reservation.start_datetime.date(),
                        or_(
                            and_(
                                OccupationModel.heure_debut >= reservation.start_datetime.time(),
                                OccupationModel.heure_debut < reservation.end_datetime.time()
                            ),
                            and_(
                                OccupationModel.heure_fin > reservation.start_datetime.time(),
                                OccupationModel.heure_fin <= reservation.end_datetime.time()
                            )
                        )
                    )
                ).first()
                if conflict_occupation:
                    raise HTTPException(400, "Salle is already occupied for this time period")

        admin = None
        if reservation.admin_id:
            admin = self._get_admin_or_400(reservation.admin_id)

            # Determine schools related to this reservation
            school_ids = set()
            if salle:
                if occupation and occupation.classe:
                    school_ids.add(occupation.classe.section.section.school_id)
                elif evenement:
                    school_ids.add(evenement.school_id)  # Assuming Evenement has school_id

            for resource_id in reservation.resources or []:
                resource = self.db.query(RessourceModel).filter(RessourceModel.id == resource_id).first()
                if resource:
                    school_ids.add(resource.school_id)

            self._check_admin_belongs_to_school(reservation.admin_id, school_ids)

        if reservation.quantity_reserved <= 0:
            raise HTTPException(400, "Quantity reserved must be positive")

        # Reserve the resources and update stock
        ressources = []
        for ressource_id in reservation.resources or []:
            self._update_ressource_stock(ressource_id, reservation.quantity_reserved)
            resource = self.db.query(RessourceModel).filter(RessourceModel.id == ressource_id).first()
            if not resource:
                raise HTTPException(400, f"Resource {ressource_id} does not exist")
            ressources.append(resource)

        if reservation.end_datetime <= reservation.start_datetime:
            raise HTTPException(400, "End datetime must be after start datetime")

        db_reservation = ReservationModel(
            **reservation.dict(exclude={"resources"}),
            resources=ressources,
            status=ReservationStatusEnum.PENDING  # Set status to PENDING when created
        )

        if reservation.status != ReservationStatusEnum.PENDING and reservation.admin_id:
            db_reservation.processed_at = func.now()

        try:
            self.db.add(db_reservation)
            self.db.commit()
            self.db.refresh(db_reservation)
            return Reservation.from_orm(db_reservation)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid reservation data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def get_reservation(self, reservation_id: int) -> Reservation:
        reservation = self.db.query(ReservationModel).filter(ReservationModel.id == reservation_id).first()
        if not reservation:
            raise HTTPException(404, "Reservation not found")
        return Reservation.from_orm(reservation)

    async def get_all_reservations(self, skip=0, limit=100) -> List[Reservation]:
        reservations = self.db.query(ReservationModel).offset(skip).limit(limit).all()
        return [Reservation.from_orm(r) for r in reservations]

    async def update_reservation(self, reservation_id: int, reservation_update: ReservationUpdate) -> Reservation:
        db_reservation = self.db.query(ReservationModel).filter(ReservationModel.id == reservation_id).first()
        if not db_reservation:
            raise HTTPException(404, "Reservation not found")

        update_data = reservation_update.dict(exclude_unset=True)

        # Validation for occupation_id and evenement_id
        if "occupation_id" in update_data and "evenement_id" in update_data:
            if update_data["occupation_id"] and update_data["evenement_id"]:
                raise HTTPException(400, "Reservation cannot be linked to both occupation and evenement")

        # Handle salle_id updates
        if "salle_id" in update_data:
            salle = self._get_salle_or_400(update_data["salle_id"])

            start_datetime = update_data.get("start_datetime", db_reservation.start_datetime)
            end_datetime = update_data.get("end_datetime", db_reservation.end_datetime)

            # Validate no conflicts for the updated salle
            conflict_reservation = self.db.query(ReservationModel).filter(
                and_(
                    ReservationModel.salle_id == update_data["salle_id"],
                    ReservationModel.id != reservation_id,
                    ReservationModel.status == ReservationStatusEnum.APPROVED,
                    ReservationModel.start_datetime < end_datetime,
                    ReservationModel.end_datetime > start_datetime,
                )
            ).first()
            if conflict_reservation:
                raise HTTPException(400, "Salle is already reserved for this time period")

            # Check for conflicting occupation for the updated salle
            conflict_occupation = self.db.query(OccupationModel).filter(
                and_(
                    OccupationModel.salle_id == update_data["salle_id"],
                    OccupationModel.date == start_datetime.date(),
                    or_(
                        and_(
                            OccupationModel.heure_debut >= start_datetime.time(),
                            OccupationModel.heure_debut < end_datetime.time()
                        ),
                        and_(
                            OccupationModel.heure_fin > start_datetime.time(),
                            OccupationModel.heure_fin <= end_datetime.time()
                        )
                    )
                )
            ).first()
            if conflict_occupation:
                raise HTTPException(400, "Salle is already occupied for this time period")

        # Update resources and stock
        if "resources" in update_data:
            resources = []
            for resource_id in update_data["resources"]:
                resource = self.db.query(RessourceModel).filter(RessourceModel.id == resource_id).first()
                if not resource:
                    raise HTTPException(400, f"Resource {resource_id} does not exist")
                resources.append(resource)
            db_reservation.resources = resources
            # Update stock after resource change
            for res in resources:
                self._update_ressource_stock(res.id, db_reservation.quantity_reserved)

        try:
            for key, value in update_data.items():
                if key != "resources":
                    setattr(db_reservation, key, value)
            self.db.commit()
            self.db.refresh(db_reservation)
            return Reservation.from_orm(db_reservation)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Invalid update data")
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def delete_reservation(self, reservation_id: int):
        db_reservation = self.db.query(ReservationModel).filter(ReservationModel.id == reservation_id).first()
        if not db_reservation:
            raise HTTPException(404, "Reservation not found")

        # Reset resources before deleting reservation if not yet ended
        if db_reservation.end_datetime > datetime.now():
            for resource in db_reservation.resources:
                self._reset_ressource_stock(resource.id, db_reservation.quantity_reserved)

        try:
            self.db.delete(db_reservation)
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))

    async def add_ressources_to_reservation(self, reservation_id: int, ressources_quantities: List[RessourceQuantity]) -> Reservation:
        """Add multiple resources with specified quantities to a reservation, ensuring each resource is valid and not already added."""
        db_reservation = self.db.query(ReservationModel).filter(ReservationModel.id == reservation_id).first()
        if not db_reservation:
            raise HTTPException(404, "Reservation not found")

        # Fetch all resources and validate quantities
        ressources = []
        for item in ressources_quantities:
            ressource_id = item.ressource_id
            quantity = item.quantity
            
            # Fetch the resource
            ressource = self.db.query(RessourceModel).filter(RessourceModel.id == ressource_id).first()
            if not ressource:
                raise HTTPException(404, f"Resource {ressource_id} not found")
            
            # Check if the requested quantity is available
            if ressource.quantity < quantity:
                raise HTTPException(400, f"Not enough stock for resource {ressource_id}. Available: {ressource.quantity}, Requested: {quantity}")
            
            # Check if the resource is already assigned to the reservation
            if ressource in db_reservation.resources:
                raise HTTPException(400, f"Resource {ressource_id} already assigned to reservation")
            
            ressources.append((ressource, quantity))

        school_ids = set()
        if db_reservation.salle_id:
            if db_reservation.occupation and db_reservation.occupation.classe:
                school_ids.add(db_reservation.occupation.classe.section.section.school_id)
            elif db_reservation.evenement:
                school_ids.add(db_reservation.evenement.school_id)

        # Validate if admin belongs to the school of the resources
        for ressource, _ in ressources:
            school_ids.add(ressource.school_id)

        if db_reservation.admin_id:
            is_admin = self.db.query(school_admins).filter(
                and_(
                    school_admins.c.user_id == db_reservation.admin_id,
                    school_admins.c.school_id.in_(school_ids)
                )
            ).first()
            if not is_admin:
                raise HTTPException(400, "Admin must belong to the school of the resource")

        # Update stock for each resource and add them to the reservation
        try:
            for ressource, quantity in ressources:
                ressource.quantity -= quantity  # Decrease stock by the quantity being reserved
                db_reservation.resources.append(ressource)

            # Commit the changes to the database
            self.db.commit()
            self.db.refresh(db_reservation)
            return Reservation.from_orm(db_reservation)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(500, str(e))
        
        


# ============================
# Planning Service
# ============================

class PlanningService:
    def __init__(self, db: Session):
        self.db = db
        self.time_slots = [
            (time(8, 0), time(9, 0)), (time(9, 0), time(10, 0)), (time(10, 0), time(11, 0)),
            (time(11, 0), time(12, 0)), (time(13, 0), time(14, 0)), (time(14, 0), time(15, 0)),
            (time(15, 0), time(16, 0)), (time(16, 0), time(17, 0)),
        ]
        self.days = list(WeekdayEnum)
        self.day_offset = {day: i for i, day in enumerate(self.days)}

    async def get_start_of_week(self, input_date: date) -> date:
        """Retourne le lundi de la semaine."""
        return input_date - timedelta(days=input_date.weekday())

    async def generate_current_week_planning(self, admin_id: int, school_id: int, required_hours_dict: Dict[Tuple[int, int], float]) -> PlanningModel:
        """Génère le planning pour la semaine en cours avec un clic."""
        today = date.today()
        start_date = self.get_start_of_week(today)
        return self.generate_and_apply_planning_for_week(start_date, admin_id, school_id, required_hours_dict)

    async def generate_and_apply_planning_for_week(
        self, start_date: date, admin_id: int, school_id: int, required_hours_dict: Dict[Tuple[int, int], float]
    ) -> PlanningModel:
        """Génère et applique un planning pour une semaine donnée."""
        existing = self.db.query(PlanningModel).filter(PlanningModel.start_date == start_date).first()
        if existing:
            raise ValueError("Un planning existe déjà pour cette semaine")

        proposals = self.generate_schedules(school_id=school_id, week_start_date=start_date, required_hours_dict=required_hours_dict)
        best_proposal = proposals[0]  # Choisir le meilleur (premier après tri par fitness)
        return self.apply_selected_planning(best_proposal, admin_id, start_date)

    async def get_planning_for_date(self, input_date: date) -> PlanningModel:
        """Récupère le planning contenant la date donnée."""
        planning = self.db.query(PlanningModel).filter(
            PlanningModel.start_date <= input_date,
            PlanningModel.end_date >= input_date
        ).first()
        if not planning:
            raise ValueError("Aucun planning trouvé pour cette date")
        return planning

    async def get_current_planning(self) -> PlanningModel:
        """Récupère le planning de la semaine en cours."""
        return self.get_planning_for_date(date.today())

    async def get_historical_plannings(self, limit: int = 10) -> List[PlanningModel]:
        """Récupère les anciens plannings."""
        return self.db.query(PlanningModel).order_by(PlanningModel.start_date.desc()).limit(limit).all()

    async def generate_schedules(
        self, school_id: int = None, classe_id: int = None, filiere_id: int = None,
        week_start_date: date = None, required_hours_dict: Dict[Tuple[int, int], float] = None,
        num_proposals: int = 5, population_size: int = 50, generations: int = 100
    ) -> List[Dict[int, List[Dict]]]:
        """Génère des propositions de plannings avec un algorithme génétique."""
        if not week_start_date or not required_hours_dict:
            raise ValueError("week_start_date et required_hours_dict sont requis")

        # Déterminer les classes à planifier
        if classe_id:
            classes_ids = [classe_id]
        elif filiere_id:
            classes_ids = [c.id for c in self.db.query(ClasseModel).filter(ClasseModel.filiere_id == filiere_id).all()]
        elif school_id:
            classes_ids = [c.id for c in self.db.query(ClasseModel).join(SectionModel).filter(SectionModel.school_id == school_id).all()]
        else:
            raise ValueError("Fournir classe_id, filiere_id ou school_id")

        # Récupérer les données nécessaires
        cours_per_classe = {cid: [cc.cours_id for cc in self.db.query(classe_cours).filter(classe_cours.c.classe_id == cid).all()] for cid in classes_ids}
        teachers_per_cours = {cours_id: [tc.teacher_id for tc in self.db.query(teacher_cours).filter(teacher_cours.c.cours_id == cours_id).all()] 
                            for cid in classes_ids for cours_id in cours_per_classe[cid]}
        salles = self.db.query(SalleModel).all()

        # Précalculer les priorités des cours
        priorities = self.precompute_priorities(classes_ids, week_start_date, required_hours_dict, cours_per_classe)

        # Précalculer les événements approuvés dans une structure efficace
        approved_events = self.db.query(ReservationModel).filter(
            ReservationModel.status == ReservationStatusEnum.APPROVED,
            ReservationModel.evenement_id.isnot(None),
            ReservationModel.start_datetime >= week_start_date,
            ReservationModel.end_datetime < week_start_date + timedelta(days=7)
        ).all()
        event_dict = defaultdict(list)
        for event in approved_events:
            salle_id = event.salle_id
            event_date = event.start_datetime.date()
            start_time = event.start_datetime.time()
            end_time = event.end_datetime.time()
            event_dict[(salle_id, event_date)].append((start_time, end_time))

        async def is_slot_occupied(salle_id, slot_date, start_time, end_time):
            """Vérifie si un créneau est occupé par un événement."""
            events = event_dict.get((salle_id, slot_date), [])
            for event_start, event_end in events:
                if start_time < event_end and end_time > event_start:
                    return True
            return False

        async def generate_random_occupation(classe_id):
            """Génère une occupation aléatoire."""
            cours_id = random.choice(cours_per_classe[classe_id])
            teacher_id = random.choice(teachers_per_cours[cours_id])
            salle = random.choice(salles)
            jour = random.choice(self.days)
            duration = random.choice([1, 2])
            start_slot = random.randint(0, len(self.time_slots) - duration)
            start_time, _ = self.time_slots[start_slot]
            _, end_time = self.time_slots[start_slot + duration - 1]
            return {
                'cours_id': cours_id, 'teacher_id': teacher_id, 'salle_id': salle.id,
                'classe_id': classe_id, 'jour': jour, 'heure_debut': start_time, 'heure_fin': end_time
            }

        async def generate_initial_population():
            """Génère une population initiale de plannings."""
            population = []
            for _ in range(population_size):
                planning = {cid: [generate_random_occupation(cid) for _ in range(10)] for cid in classes_ids}
                population.append(planning)
            return population

        async def calculate_fitness(planning):
            """Calcule le score de fitness d'un planning."""
            score = 0
            conflicts = 0

            # Calculer les heures programmées
            scheduled_hours = defaultdict(float)
            all_occupations = [occ for cid in classes_ids for occ in planning[cid]]
            for occ in all_occupations:
                key = (occ['classe_id'], occ['cours_id'])
                duration = (occ['heure_fin'].hour - occ['heure_debut'].hour) + \
                        (occ['heure_fin'].minute - occ['heure_debut'].minute) / 60
                scheduled_hours[key] += duration

            # Priorité des cours
            for (cid, cours_id), hours in scheduled_hours.items():
                priority = priorities.get((cid, cours_id), 1.0)
                score += priority * hours

            # Vérifier les conflits de salle
            occupations_by_room_day = defaultdict(list)
            for occ in all_occupations:
                key = (occ['salle_id'], occ['jour'])
                occupations_by_room_day[key].append(occ)
            for key, room_day_occupations in occupations_by_room_day.items():
                room_day_occupations.sort(key=lambda x: x['heure_debut'])
                for i in range(len(room_day_occupations)):
                    occ1 = room_day_occupations[i]
                    for j in range(i + 1, len(room_day_occupations)):
                        occ2 = room_day_occupations[j]
                        if occ1['heure_fin'] <= occ2['heure_debut']:
                            break
                        if occ1['heure_debut'] < occ2['heure_fin'] and occ1['heure_fin'] > occ2['heure_debut']:
                            conflicts += 1000

            # Vérifier les conflits d'enseignant
            occupations_by_teacher_day = defaultdict(list)
            for occ in all_occupations:
                key = (occ['teacher_id'], occ['jour'])
                occupations_by_teacher_day[key].append(occ)
            for key, teacher_day_occupations in occupations_by_teacher_day.items():
                teacher_day_occupations.sort(key=lambda x: x['heure_debut'])
                for i in range(len(teacher_day_occupations)):
                    occ1 = teacher_day_occupations[i]
                    for j in range(i + 1, len(teacher_day_occupations)):
                        occ2 = teacher_day_occupations[j]
                        if occ1['heure_fin'] <= occ2['heure_debut']:
                            break
                        if occ1['heure_debut'] < occ2['heure_fin'] and occ1['heure_fin'] > occ2['heure_debut']:
                            conflicts += 1000

            # Vérifier les conflits avec les événements
            for occ in all_occupations:
                slot_date = week_start_date + timedelta(days=self.day_offset[occ['jour']])
                if is_slot_occupied(occ['salle_id'], slot_date, occ['heure_debut'], occ['heure_fin']):
                    conflicts += 1000

            return score - conflicts

        async def select(population, fitness_scores):
            """Sélectionne les meilleurs plannings."""
            sorted_pairs = sorted(zip(fitness_scores, population), reverse=True)
            return [p for _, p in sorted_pairs[:population_size // 2]]

        async def crossover(parent1, parent2):
            """Effectue un croisement entre deux plannings."""
            child = {}
            for cid in classes_ids:
                split = len(parent1[cid]) // 2
                child[cid] = parent1[cid][:split] + parent2[cid][split:]
            return child

        async def mutate(planning):
            """Applique une mutation aléatoire."""
            for cid in classes_ids:
                if random.random() < 0.05:
                    idx = random.randint(0, len(planning[cid]) - 1)
                    planning[cid][idx] = generate_random_occupation(cid)
            return planning

        # Exécuter l'algorithme génétique
        population = generate_initial_population()
        for _ in range(generations):
            fitness_scores = [calculate_fitness(p) for p in population]
            selected = select(population, fitness_scores)
            offspring = []
            while len(offspring) < population_size - len(selected):
                parent1, parent2 = random.sample(selected, 2)
                child = crossover(parent1, parent2)
                child = mutate(child)
                offspring.append(child)
            population = selected + offspring

        fitness_scores = [calculate_fitness(p) for p in population]
        sorted_pairs = sorted(zip(fitness_scores, population), reverse=True)
        return [p for _, p in sorted_pairs[:num_proposals]]
    
    async def get_cours_ids_per_classe(db: Session, classe_id: int) -> List[int]:
        classe = db.query(ClasseModel).filter(ClasseModel.id == classe_id).first()
        if not classe:
            raise HTTPException(status_code=404, detail="Classe non trouvée")
        return [c.id for c in classe.cours]


    async def precompute_priorities(
        db: Session,
        classes_ids: List[int],
        week_start_date: date,
        required_hours_dict: Dict[Tuple[int, int], float]
    ) -> Dict[Tuple[int, int], float]:
        """Précalcule les priorités des cours pour toutes les classes."""
        priorities = {}

        # Précharger tous les cours par classe
        classe_cours_map = {
            cl.id: [c.id for c in cl.cours]
            for cl in db.query(ClasseModel).filter(ClasseModel.id.in_(classes_ids)).all()
        }

        all_cours_ids = list({cid for cids in classe_cours_map.values() for cid in cids})

        # Précharger les données nécessaires
        cours_data = {c.id: c for c in db.query(CoursModel).filter(CoursModel.id.in_(all_cours_ids)).all()}

        total_hours_data = {
            (cc.classe_id, cc.cours_id): cc.total_hours
            for cc in db.query(classe_cours).filter(classe_cours.c.classe_id.in_(classes_ids)).all()
        }

        student_counts = {
            cours_id: db.query(func.count()).select_from(student_cours_status).filter(
                and_(
                    student_cours_status.c.cours_id == cours_id,
                    student_cours_status.c.status == StudentCoursStatusEnum.INSCRIT
                )
            ).scalar() or 1
            for cours_id in all_cours_ids
        }

        teachers_per_cours = {
            cours_id: [tc.teacher_id for tc in db.query(teacher_cours).filter(teacher_cours.c.cours_id == cours_id).all()]
            for cours_id in all_cours_ids
        }

        teacher_availability = {}
        for teacher_id in {t for cl in teachers_per_cours.values() for t in cl}:
            available_slots = db.query(TeacherAvailabilityModel).filter(
                and_(
                    TeacherAvailabilityModel.teacher_id == teacher_id,
                    TeacherAvailabilityModel.date >= week_start_date,
                    TeacherAvailabilityModel.date < week_start_date + timedelta(days=6)
                )
            ).count()
            teacher_availability[teacher_id] = available_slots

        resources_per_cours = {
            cours_id: [
                r.quantity for r in db.query(RessourceModel).join(cours_ressources).filter(
                    cours_ressources.c.cours_id == cours_id
                ).all()
            ]
            for cours_id in all_cours_ids
        }

        for classe_id in classes_ids:
            for cours_id in classe_cours_map.get(classe_id, []):
                cours = cours_data[cours_id]
                total_hours = total_hours_data.get((classe_id, cours_id), 0)
                required_hours = required_hours_dict.get((classe_id, cours_id), 30)
                hours_remaining_ratio = (required_hours - total_hours) / required_hours if required_hours > 0 else 0

                type_priority = {
                    TypeCourEnum.COURS_MAGISTRAL: 0.5,
                    TypeCourEnum.SEMINAIRE: 0.6,
                    TypeCourEnum.TD: 0.7,
                    TypeCourEnum.TP: 0.7,
                    TypeCourEnum.COURS_EN_LIGNE: 1.0,
                    TypeCourEnum.FORMATION_CONTINUE: 0.9,
                    TypeCourEnum.DEVELOPPEMENT_PERSONNEL: 1.2,
                    TypeCourEnum.CERTIFICATIONS_PROFESSIONNELLES: 0.8,
                    TypeCourEnum.E_LEARNING: 1.0,
                    TypeCourEnum.WEBINAIRE: 1.1,
                    TypeCourEnum.COURS_EN_STREAMING: 1.0,
                    TypeCourEnum.PREPARATION_EXAMEN: 0.6,
                    TypeCourEnum.COURS_PRATIQUES: 0.7,
                    TypeCourEnum.REMISE_A_NIVEAU: 0.9,
                    TypeCourEnum.ALTERNANCE: 0.8,
                    TypeCourEnum.SOUTIEN_SCOLAIRE: 0.9,
                    TypeCourEnum.EVEIL: 1.2,
                    TypeCourEnum.COURS_DE_LANGUES: 0.7,
                    TypeCourEnum.COURS_INTENSIFS: 0.6,
                    TypeCourEnum.BOOTCAMP: 0.6,
                    TypeCourEnum.IMMERSION: 0.7,
                    TypeCourEnum.COURS_PARTICULIERS: 1.0,
                    TypeCourEnum.COACHING: 1.1
                }.get(cours.type_cours, 1.0)

                student_count = student_counts.get(cours_id, 1)
                student_factor = 1 / (student_count + 1)

                teachers = teachers_per_cours.get(cours_id, [])
                teacher_availability_score = sum(
                    1 / (teacher_availability.get(t, 0) + 1) for t in teachers
                ) / len(teachers) if teachers else 1

                resources = resources_per_cours.get(cours_id, [1])
                resource_score = sum(1 / (r + 1) for r in resources) / len(resources)

                priority = (
                    hours_remaining_ratio * 0.4 +
                    type_priority * 0.2 +
                    student_factor * 0.1 +
                    teacher_availability_score * 0.2 +
                    resource_score * 0.1
                )
                priorities[(classe_id, cours_id)] = priority

        return priorities

    async def apply_selected_planning(self, selected_planning: Dict[int, List[Dict]], admin_id: int, week_start_date: date) -> PlanningModel:
        """Applique un planning sélectionné."""
        try:
            planning = PlanningModel(
                start_date=week_start_date,
                end_date=week_start_date + timedelta(days=6)
            )
            self.db.add(planning)
            self.db.flush()

            created_occupations = []
            duration_updates = defaultdict(float)

            for classe_id, occupations in selected_planning.items():
                for occ in occupations:
                    occupation = OccupationModel(
                        planning_id=planning.id,
                        salle_id=occ['salle_id'],
                        classe_id=classe_id,
                        cours_id=occ['cours_id'],
                        teacher_id=occ['teacher_id'],
                        jour=occ['jour'],
                        heure_debut=occ['heure_debut'],
                        heure_fin=occ['heure_fin']
                    )
                    self.db.add(occupation)
                    self.db.flush()
                    created_occupations.append(occupation)

                    duration = (occ['heure_fin'].hour - occ['heure_debut'].hour) + \
                               (occ['heure_fin'].minute - occ['heure_debut'].minute) / 60
                    duration_updates[(classe_id, occ['cours_id'])] += duration

                    resources = self.db.query(cours_ressources).filter(cours_ressources.c.cours_id == occ['cours_id']).all()
                    if resources:
                        slot_date = week_start_date + timedelta(days=self.day_offset[occ['jour']])
                        reservation = ReservationModel(
                            occupation_id=occupation.id,
                            user_id=admin_id,
                            salle_id=occ['salle_id'],
                            quantity_reserved=len(resources),
                            status=ReservationStatusEnum.PENDING,
                            start_datetime=datetime.combine(slot_date, occ['heure_debut']),
                            end_datetime=datetime.combine(slot_date, occ['heure_fin'])
                        )
                        self.db.add(reservation)
                        self.db.flush()
                        for res in resources:
                            self.db.execute(reservation_ressources.insert().values(
                                reservation_id=reservation.id, ressource_id=res.ressource_id
                            ))

            # Mettre à jour total_hours en batch
            for (classe_id, cours_id), total_duration in duration_updates.items():
                self.db.execute(
                    classe_cours.update()
                    .where(and_(classe_cours.c.classe_id == classe_id, classe_cours.c.cours_id == cours_id))
                    .values(total_hours=classe_cours.c.total_hours + total_duration)
                )

            # Approuver les réservations
            self.db.query(ReservationModel).filter(
                ReservationModel.occupation_id.in_([o.id for o in created_occupations]),
                ReservationModel.status == ReservationStatusEnum.PENDING
            ).update({
                ReservationModel.status: ReservationStatusEnum.APPROVED,
                ReservationModel.admin_id: admin_id,
                ReservationModel.processed_at: func.now()
            }, synchronize_session=False)

            self.db.commit()
            return planning
        except Exception as e:
            self.db.rollback()
            raise ValueError(f"Échec de l'application du planning : {str(e)}")
        
      
        


# ============================
# Enum Service
# ============================

class EnumService:
    async def enum_to_list(enum_class: Enum) -> List[Dict[str, str]]:
        return [{"key": item.name, "value": item.value} for item in enum_class]