import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db

# JWT / Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "devsecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Keep OAuth2PasswordBearer for dependency extraction, but do not use the form-based login
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="AgroVault API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------- DB helpers -------------------------

def to_oid(val):
    try:
        return ObjectId(str(val))
    except Exception:
        return None


def insert_with_id(collection, doc: dict) -> str:
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    res = db[collection].insert_one(doc)
    oid = str(res.inserted_id)
    db[collection].update_one({"_id": res.inserted_id}, {"$set": {"id": oid}})
    return oid


def get_by_id(collection: str, id_str: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    oid = to_oid(id_str)
    q = {"$or": ([{"_id": oid}] if oid else []) + [{"id": id_str}]}
    return db[collection].find_one(q)


def list_many(collection: str, query: dict = None, sort: Optional[list] = None, limit: Optional[int] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    cursor = db[collection].find(query or {})
    if sort:
        cursor = cursor.sort(sort)
    if limit:
        cursor = cursor.limit(limit)
    res = []
    for d in cursor:
        d["id"] = str(d.get("_id")) if not d.get("id") else d["id"]
        res.append(d)
    return res

# ------------------------- Auth utils -------------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Dependency: get current user from token

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_by_id("user", user_id) or db["user"].find_one({"email": user_id})
    if not user:
        raise credentials_exception
    user["id"] = user.get("id") or str(user.get("_id"))
    return user


def require_roles(*roles):
    def wrapper(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")
        return user
    return wrapper

# ------------------------- Auth endpoints -------------------------

class RegisterBody(BaseModel):
    name: str
    email: str
    phone: str
    password: str
    role: str


@app.post("/auth/register")
def register(body: RegisterBody):
    role = body.role
    if role not in ["farmer", "operator", "banker", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = db["user"].find_one({"$or": [{"email": body.email}, {"phone": body.phone}]})
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    user_doc = {
        "name": body.name,
        "email": body.email,
        "phone": body.phone,
        "passwordHash": get_password_hash(body.password),
        "role": role,
        "is_active": True,
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc),
    }
    user_id = insert_with_id("user", user_doc)
    if role == "farmer":
        insert_with_id("farmerprofile", {"userId": user_id})
    return {"id": user_id}


@app.post("/auth/login")
async def login_json(payload: dict = Body(...)):
    identifier = payload.get("username") or payload.get("email") or payload.get("phone")
    password = payload.get("password")
    if not identifier or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    user = db["user"].find_one({"$or": [{"email": identifier}, {"phone": identifier}]})
    if not user or not verify_password(password, user.get("passwordHash", "")):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": str(user.get("_id")), "role": user.get("role")})
    return Token(access_token=token)

# ------------------------- Admin -------------------------

class WarehouseIn(BaseModel):
    name: str
    locationText: str
    contactPerson: str
    phone: str


@app.post("/admin/warehouses")
def create_warehouse(body: WarehouseIn, user=Depends(require_roles("admin"))):
    wid = insert_with_id("warehouse", {**body.dict()})
    return {"id": wid}


@app.get("/admin/warehouses")
def list_warehouses(user=Depends(require_roles("admin", "operator", "banker"))):
    return list_many("warehouse")


class CropTypeIn(BaseModel):
    name: str
    varietyOptional: Optional[str] = None


@app.post("/admin/crops")
def create_crop(body: CropTypeIn, user=Depends(require_roles("admin"))):
    cid = insert_with_id("croptype", {**body.dict()})
    return {"id": cid}


@app.get("/admin/crops")
def list_crops(user=Depends(require_roles("admin", "operator", "banker", "farmer"))):
    return list_many("croptype")


@app.get("/admin/users")
def list_users(user=Depends(require_roles("admin"))):
    users = list_many("user")
    for u in users:
        u.pop("passwordHash", None)
    return users

# ------------------------- Operator -------------------------

class ReceiptIn(BaseModel):
    farmerId: str
    warehouseId: str
    cropTypeId: str
    quantity: float
    grade: str


from qrcode import QRCode
import io
import base64


def generate_receipt_code():
    year = datetime.now().year
    count = db["receipt"].count_documents({"receiptCode": {"$regex": f"^AV-{year}-"}})
    return f"AV-{year}-{count+1:04d}"


@app.post("/operator/receipts")
def create_receipt(body: ReceiptIn, user=Depends(require_roles("operator", "admin"))):
    receipt_code = generate_receipt_code()
    now = datetime.now(timezone.utc)
    doc = {
        "receiptCode": receipt_code,
        "farmerId": body.farmerId,
        "warehouseId": body.warehouseId,
        "cropTypeId": body.cropTypeId,
        "quantity": body.quantity,
        "grade": body.grade,
        "status": "stored",
        "createdAt": now,
        "updatedAt": now,
        "history": [{"at": now.isoformat(), "event": "Created", "by": user.get("id")}],
    }
    rid = insert_with_id("receipt", doc)

    qr = QRCode(box_size=4, border=2)
    deep_link = f"/receipts/{rid}"
    qr.add_data(deep_link)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    qr_b64 = base64.b64encode(bio.getvalue()).decode("utf-8")

    return {"id": rid, "receiptCode": receipt_code, "qr": f"data:image/png;base64,{qr_b64}"}


@app.get("/operator/receipts")
def list_operator_receipts(user=Depends(require_roles("operator", "admin"))):
    recs = list_many("receipt", sort=[("createdAt", -1)], limit=200)
    return recs


class StatusUpdateIn(BaseModel):
    status: str


@app.post("/operator/receipts/{receipt_id}/status")
def update_receipt_status(receipt_id: str, body: StatusUpdateIn, user=Depends(require_roles("operator", "admin"))):
    if body.status not in ["stored", "partially_sold", "sold", "released", "pledged"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    rec = get_by_id("receipt", receipt_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Receipt not found")
    db["receipt"].update_one({"id": rec["id"]}, {"$set": {"status": body.status, "updatedAt": datetime.now(timezone.utc)}, "$push": {"history": {"at": datetime.now(timezone.utc).isoformat(), "event": f"Status changed to {body.status}", "by": user.get("id")}}})
    return {"ok": True}

# ------------------------- Banker -------------------------

class LoanIn(BaseModel):
    principalAmount: float
    interestRate: float


@app.get("/banker/receipts/search")
def search_receipts(receiptCode: Optional[str] = None, farmerPhone: Optional[str] = None, user=Depends(require_roles("banker", "admin"))):
    query = {}
    if receiptCode:
        query["receiptCode"] = receiptCode
    if farmerPhone:
        farmer = db["user"].find_one({"phone": farmerPhone, "role": "farmer"})
        if not farmer:
            return []
        query["farmerId"] = str(farmer.get("_id"))
    recs = list_many("receipt", query)
    result = []
    for r in recs:
        farmer = get_by_id("user", r.get("farmerId")) or {}
        wh = get_by_id("warehouse", r.get("warehouseId")) or {}
        crop = get_by_id("croptype", r.get("cropTypeId")) or {}
        loan = db["loan"].find_one({"receiptId": r.get("id"), "status": "active"})
        result.append({
            "id": r.get("id"),
            "receiptCode": r.get("receiptCode"),
            "status": r.get("status"),
            "farmerName": farmer.get("name"),
            "warehouse": wh.get("name"),
            "crop": crop.get("name"),
            "quantity": r.get("quantity"),
            "pledged": bool(loan)
        })
    return result


@app.post("/banker/receipts/{receipt_id}/loan")
def create_loan(receipt_id: str, body: LoanIn, user=Depends(require_roles("banker", "admin"))):
    rec = get_by_id("receipt", receipt_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Receipt not found")
    if rec.get("status") in ["sold", "released"]:
        raise HTTPException(status_code=400, detail="Cannot pledge a sold or released receipt")
    existing = db["loan"].find_one({"receiptId": rec.get("id"), "status": "active"})
    if existing:
        raise HTTPException(status_code=400, detail="Receipt already pledged to an active loan")
    now = datetime.now(timezone.utc)
    loan_doc = {
        "receiptId": rec.get("id"),
        "bankerId": user.get("id"),
        "principalAmount": body.principalAmount,
        "interestRate": body.interestRate,
        "status": "active",
        "createdAt": now,
        "updatedAt": now,
    }
    lid = insert_with_id("loan", loan_doc)
    db["receipt"].update_one({"id": rec["id"]}, {"$set": {"status": "pledged", "updatedAt": now}, "$push": {"history": {"at": now.isoformat(), "event": f"Pledged to banker {user.get('name', user.get('id'))}", "by": user.get("id")}}})
    return {"id": lid}


@app.post("/banker/loans/{loan_id}/repay")
def repay_loan(loan_id: str, user=Depends(require_roles("banker", "admin"))):
    loan = get_by_id("loan", loan_id)
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    if loan.get("status") != "active":
        raise HTTPException(status_code=400, detail="Loan is not active")
    now = datetime.now(timezone.utc)
    db["loan"].update_one({"id": loan["id"]}, {"$set": {"status": "repaid", "updatedAt": now}})
    rec = get_by_id("receipt", loan.get("receiptId"))
    if rec:
        new_status = rec.get("status")
        if new_status == "pledged":
            new_status = "stored"
        db["receipt"].update_one({"id": rec["id"]}, {"$set": {"status": new_status, "updatedAt": now}, "$push": {"history": {"at": now.isoformat(), "event": "Loan repaid", "by": user.get("id")}}})
    return {"ok": True}

# ------------------------- Farmer -------------------------

@app.get("/farmer/receipts")
def farmer_receipts(user=Depends(require_roles("farmer", "admin"))):
    recs = list_many("receipt", {"farmerId": user.get("id")}, sort=[("createdAt", -1)])
    results = []
    for r in recs:
        loan = db["loan"].find_one({"receiptId": r.get("id"), "status": "active"})
        crop = get_by_id("croptype", r.get("cropTypeId")) or {}
        results.append({
            "id": r.get("id"),
            "receiptCode": r.get("receiptCode"),
            "crop": crop.get("name"),
            "quantity": r.get("quantity"),
            "status": r.get("status"),
            "linkedLoan": bool(loan)
        })
    return results

# ------------------------- Shared -------------------------

@app.get("/receipts/{receipt_id}")
def receipt_detail(receipt_id: str, user=Depends(get_current_user)):
    r = get_by_id("receipt", receipt_id)
    if not r:
        raise HTTPException(status_code=404, detail="Receipt not found")
    farmer = get_by_id("user", r.get("farmerId")) or {}
    wh = get_by_id("warehouse", r.get("warehouseId")) or {}
    crop = get_by_id("croptype", r.get("cropTypeId")) or {}
    loan = db["loan"].find_one({"receiptId": r.get("id"), "status": "active"})
    return {
        "id": r.get("id"),
        "receiptCode": r.get("receiptCode"),
        "farmer": {"name": farmer.get("name"), "phone": farmer.get("phone")},
        "warehouse": {"name": wh.get("name"), "locationText": wh.get("locationText")},
        "crop": {"name": crop.get("name"), "variety": crop.get("varietyOptional")},
        "quantity": r.get("quantity"),
        "grade": r.get("grade"),
        "status": r.get("status"),
        "loan": loan and {"id": str(loan.get("id", loan.get("_id"))), "principalAmount": loan.get("principalAmount"), "interestRate": loan.get("interestRate"), "status": loan.get("status")},
        "history": r.get("history", [])
    }

# ------------------------- Analytics & Demo -------------------------

@app.get("/admin/analytics")
def admin_analytics(user=Depends(require_roles("admin"))):
    total_receipts = db["receipt"].count_documents({})
    pledged = db["receipt"].count_documents({"status": "pledged"})
    total_loan_amount = 0.0
    for l in list_many("loan", {"status": "active"}):
        total_loan_amount += float(l.get("principalAmount", 0))
    return {"totalReceipts": total_receipts, "totalPledged": pledged, "totalLoanAmount": total_loan_amount}


@app.post("/admin/reset-demo")
def reset_demo(user=Depends(require_roles("admin"))):
    for col in ["user", "farmerprofile", "warehouse", "croptype", "receipt", "loan"]:
        db[col].delete_many({})

    def add_user(name, email, phone, password, role):
        return insert_with_id("user", {"name": name, "email": email, "phone": phone, "passwordHash": get_password_hash(password), "role": role, "is_active": True})

    farmer_id = add_user("Demo Farmer", "farmer@example.com", "9000000001", "password", "farmer")
    operator_id = add_user("Demo Operator", "operator@example.com", "9000000002", "password", "operator")
    banker_id = add_user("Demo Banker", "banker@example.com", "9000000003", "password", "banker")
    admin_id = add_user("Admin", "admin@example.com", "9000000004", "adminpass", "admin")

    insert_with_id("farmerprofile", {"userId": farmer_id, "village": "Rampur", "district": "Kanpur", "state": "UP"})

    w1 = insert_with_id("warehouse", {"name": "GreenStore Warehouse", "locationText": "NH-27, Kanpur", "contactPerson": "Mr. Rao", "phone": "9998887771", "operatorId": operator_id})
    insert_with_id("warehouse", {"name": "AgriHold Depot", "locationText": "Ring Road, Indore", "contactPerson": "Ms. Asha", "phone": "9998887772", "operatorId": operator_id})

    c1 = insert_with_id("croptype", {"name": "Wheat"})
    insert_with_id("croptype", {"name": "Rice"})
    insert_with_id("croptype", {"name": "Maize"})

    now = datetime.now(timezone.utc)
    insert_with_id("receipt", {
        "receiptCode": "AV-2025-0001",
        "farmerId": farmer_id,
        "warehouseId": w1,
        "cropTypeId": c1,
        "quantity": 50,
        "grade": "A",
        "status": "stored",
        "createdAt": now,
        "updatedAt": now,
        "history": [{"at": now.isoformat(), "event": "Created", "by": admin_id}],
    })

    return {"ok": True}

# Root and health
@app.get("/")
def read_root():
    return {"message": "AgroVault API running"}

@app.get("/test")
def test_database():
    response = {"backend": "✅ Running", "database": "❌ Not Available"}
    try:
        if db is not None:
            db.list_collection_names()
            response["database"] = "✅ Connected"
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
