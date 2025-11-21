"""
Database Schemas for AgroVault (MongoDB collections)

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user"
- Warehouse -> "warehouse"
- Croptype -> "croptype"
- Receipt -> "receipt"
- Loan -> "loan"
- Farmerprofile -> "farmerprofile"
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal, List
from datetime import datetime

class User(BaseModel):
    name: str
    email: str
    phone: str
    passwordHash: str
    role: Literal["farmer", "operator", "banker", "admin"]
    is_active: bool = True

class FarmerProfile(BaseModel):
    userId: str
    village: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    govIdOptional: Optional[str] = None

class Warehouse(BaseModel):
    name: str
    locationText: str
    contactPerson: str
    phone: str
    operatorId: Optional[str] = None  # link operator user

class CropType(BaseModel):
    name: str
    varietyOptional: Optional[str] = None

class Receipt(BaseModel):
    receiptCode: str
    farmerId: str
    warehouseId: str
    cropTypeId: str
    quantity: float
    grade: str
    status: Literal["stored", "pledged", "partially_sold", "sold", "released"] = "stored"
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None
    history: Optional[List[dict]] = []

class Loan(BaseModel):
    receiptId: str
    bankerId: str
    principalAmount: float
    interestRate: float
    status: Literal["active", "repaid", "defaulted"] = "active"
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None
