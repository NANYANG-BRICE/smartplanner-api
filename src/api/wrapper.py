from fastapi import Form
from pydantic import EmailStr, HttpUrl
from typing import List, Optional
from datetime import date

from api.schemas import SchoolCreate

class SchoolCreateForm:
    def __init__(
        self,
        name: str = Form(...),
        sigle: str = Form(...),
        address: str = Form(...),
        creation_date: date = Form(...),
        establishment_type: str = Form(...),
        description: Optional[str] = Form(None),
        website: HttpUrl = Form(...),
        phones: List[str] = Form(...),
        emails: List[EmailStr] = Form(...)
    ):
        self.name = name
        self.sigle = sigle
        self.address = address
        self.creation_date = creation_date
        self.establishment_type = establishment_type
        self.description = description
        self.website = website
        self.phones = phones
        self.emails = emails

    def to_schema(self) -> SchoolCreate:
        return SchoolCreate(
            name=self.name,
            sigle=self.sigle,
            address=self.address,
            creation_date=self.creation_date,
            establishment_type=self.establishment_type,
            description=self.description,
            website=self.website,
            phones=self.phones,
            emails=self.emails,
            logo=None
        )
