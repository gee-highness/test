# app/models/core.py
from typing import Optional, List, Dict, Any
from pydantic import Field, BaseModel, EmailStr, ConfigDict, validator
from datetime import datetime, date
import math
from .base import MongoModel, PyObjectId
from .response import COMMON_ENCODERS


# Payment Attempt Model
class PaymentAttempt(MongoModel):
    order_id: str
    payment_gateway: str
    amount: float
    reference: str
    status: str
    payment_data: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    cancellation_reason: Optional[str] = None

# Recipe model for embedded recipes
class RecipeItem(MongoModel):
    id: Optional[str] = None
    food_id: str
    inventory_product_id: str
    quantity_used: float
    unit_of_measure: str
    
    def to_response_dict(self) -> dict:
        """Convert RecipeItem to dictionary for response"""
        return {
            "id": self.id,
            "food_id": self.food_id,
            "inventory_product_id": self.inventory_product_id,
            "quantity_used": self.quantity_used,
            "unit_of_measure": self.unit_of_measure,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

class Food(MongoModel):
    name: str
    description: str
    price: float
    category_id: str
    image_urls: Optional[List[str]] = [] 
    preparation_time: Optional[int] = None
    allergens: Optional[List[str]] = []
    tenant_id: str
    recipes: Optional[List[RecipeItem]] = []
    store_id: Optional[str] = None
    is_available: Optional[bool] = True

    def to_response_dict(self) -> dict:
        """Convert Food to dictionary for response with proper recipe handling"""
        data = self.model_dump()
        
        # Convert RecipeItem objects to dictionaries
        if self.recipes:
            data['recipes'] = [recipe.to_response_dict() if hasattr(recipe, 'to_response_dict') 
                             else recipe for recipe in self.recipes]
        
        return data

class StoreFood(MongoModel):
    food_id: str
    store_id: str
    is_available: bool = True

class OrderItem(MongoModel):
    id: Optional[str] = None  # Make this truly optional
    order_id: Optional[str] = None  # CHANGE from str to Optional[str]
    food_id: str
    quantity: int
    price: float
    sub_total: float
    notes: Optional[str] = None
    name: str
    price_at_sale: float

    # Optional: Add a class method to help with response
    def to_response_dict(self) -> dict:
        """Convert OrderItem to dictionary for response"""
        data = self.model_dump()
        # Ensure id is included
        if not data.get('id'):
            data['id'] = str(ObjectId())
        return data

class Order(MongoModel):
    store_id: Optional[str] = None
    table_id: Optional[str] = None
    customer_id: Optional[str] = None
    total_amount: float
    status: str
    notes: str
    items: List[OrderItem] = []
    subtotal_amount: float
    tax_amount: float
    discount_amount: float
    employee_id: Optional[str] = None
    order_type: Optional[str] = None
    payment_status: Optional[str] = None
    payment_method: Optional[str] = None
    stock_warnings: Optional[List[Dict[str, Any]]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    cancellation_reason: Optional[str] = None
    payment_reference: Optional[str] = None
    transaction_id: Optional[str] = None
    payment_details: Optional[Dict[str, Any]] = None
    
    # Optional: Add validation to ensure items have order_id after creation
    @validator('items', always=True)
    def validate_items_order_id(cls, v, values):
        """Validate that items have order_id (should be set by backend)"""
        order_id = values.get('id')
        if order_id:
            for item in v:
                if not item.order_id:
                    item.order_id = order_id
        return v
    
    @classmethod
    def from_mongo(cls, data):
        """Override from_mongo to handle datetime conversion"""
        if data is None:
            return None
        
        data_dict = dict(data)
        data_dict['id'] = str(data_dict.pop('_id'))
        
        # Handle datetime fields
        for field in ['created_at', 'updated_at']:
            if field in data_dict and data_dict[field]:
                # If it's already a datetime, keep it
                if isinstance(data_dict[field], str):
                    try:
                        # Try to parse string to datetime
                        data_dict[field] = datetime.fromisoformat(data_dict[field].replace('Z', '+00:00'))
                    except:
                        # If parsing fails, leave as string
                        pass
        
        return cls(**data_dict)
    
    def to_response_dict(self) -> dict:
        """Convert Order to dictionary for response with proper handling"""
        data = self.model_dump()
        
        # Convert datetime fields to ISO strings
        for field in ['created_at', 'updated_at']:
            if field in data and data[field] and isinstance(data[field], datetime):
                data[field] = data[field].isoformat()
        
        # Convert OrderItem objects to dictionaries
        if self.items:
            data['items'] = [
                {
                    "id": item.id,
                    "order_id": item.order_id,
                    "food_id": item.food_id,
                    "quantity": item.quantity,
                    "price": item.price,
                    "sub_total": item.sub_total,
                    "notes": item.notes,
                    "name": item.name,
                    "price_at_sale": item.price_at_sale
                } for item in self.items
            ]
        
        return data

class Category(MongoModel):
    name: str
    description: Optional[str] = None
    store_id: Optional[str] = None
    image_url: Optional[str] = None  # ADD THIS LINE for category images

class InvCategory(MongoModel):
    name: str
    description: Optional[str] = None
    store_id: Optional[str] = None

class Customer(MongoModel):
    first_name: str
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    loyalty_points: Optional[int] = 0
    store_id: str

class Table(MongoModel):
    name: str
    capacity: int
    location: str
    status: str
    current_order_id: Optional[str] = None
    store_id: str

class Store(MongoModel):
    name: str
    address: str
    phone: str
    email: str
    tenant_id: str
    location: Optional[str] = None
    manager_id: Optional[str] = None
    kiosk_user_id: Optional[str] = None

class PurchaseOrderItem(MongoModel):
    inventory_product_id: str
    quantity: float
    unit_of_measure: str
    unit_cost: float
    total_cost: float
    notes: Optional[str] = None

class PurchaseOrder(MongoModel):
    po_number: str
    supplier_id: str
    site_id: str
    status: str
    order_date: str
    expected_delivery_date: str
    total_amount: float
    ordered_by: str
    notes: Optional[str] = None
    items: List[PurchaseOrderItem] = []

class GoodsReceiptItem(MongoModel):
    inventory_product_id: str
    purchase_order_id: str
    received_quantity: float
    unit_of_measure: str
    condition: str
    notes: Optional[str] = None

class GoodsReceipt(MongoModel):
    receipt_number: str
    purchase_order_id: str
    store_id: str
    receipt_date: str
    received_by: str
    items: List[GoodsReceiptItem] = []
    receiving_bin_id: Optional[str] = None
    status: Optional[str] = None
    received_items: Optional[List[Dict]] = None

class User(MongoModel):
    email: EmailStr
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    password: Optional[str] = None  # Make password optional
    email_verified_at: Optional[datetime] = None
    remember_token: Optional[str] = None
    password_changed: Optional[bool] = False
    cashAccounts: Optional[List[Any]] = []
    cardAccounts: Optional[List[Any]] = []
    onlineAccounts: Optional[List[Any]] = []
    gpayAccounts: Optional[List[Any]] = []
    phonepeAccounts: Optional[List[Any]] = []
    amazonpayAccounts: Optional[List[Any]] = []
    locations: Optional[List[Any]] = []

    def to_dict(self, **kwargs) -> dict:
        """Convert model to dictionary with proper handling for all fields"""
        data = super().to_dict(**kwargs)
        # Ensure all optional lists are included
        for field in ['cashAccounts', 'cardAccounts', 'onlineAccounts', 'gpayAccounts', 'phonepeAccounts', 'amazonpayAccounts', 'locations']:
            if field not in data or data[field] is None:
                data[field] = []
        return data

class Payment(MongoModel):
    order_id: str
    payment_method_id: str
    amount: float
    payment_date: str
    transaction_id: Optional[str] = None
    status: str

class Tax(MongoModel):
    name: str
    percentage: float
    is_active: bool = True

class PaymentMethod(MongoModel):
    name: str
    description: str
    is_active: bool = True

class Brand(MongoModel):
    name: str
    description: Optional[str] = None

class ContactMessage(MongoModel):
    name: str
    email: str
    subject: str
    message: str

class Report(MongoModel):
    user_id: str
    user_name: str
    user_role: str
    attempted_path: str
    attempts: int
    last_attempt_at: str
    created_at: Optional[str] = None

class Reservation(MongoModel):
    customer_id: str
    table_id: Optional[str] = None
    date_time: str
    number_of_guests: int
    status: str
    notes: Optional[str] = None
    store_id: str

class Domain(MongoModel):
    tenant_id: str
    domain: str
    is_primary: bool = False

class Job(MongoModel):
    queue: str
    payload: str
    attempts: int
    reserved_at: Optional[int] = None
    available_at: int
    created_at: int

class FailedJob(MongoModel):
    uuid: str
    connection: str
    queue: str
    payload: str
    exception: str
    failed_at: str

class PasswordReset(MongoModel):
    email: str
    token: str
    created_at: str

class Tenant(MongoModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders=COMMON_ENCODERS
    )
    
    name: str
    email: str
    password: str
    remember_token: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    customer_page_settings: Optional[dict] = Field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_response_dict(self) -> dict:
        """Convert Tenant to dictionary for response"""
        data = self.model_dump(exclude={'password'})
        
        # Ensure customer_page_settings exists
        if 'customer_page_settings' not in data or data['customer_page_settings'] is None:
            data['customer_page_settings'] = {}
            
        return data

class Site(MongoModel):
    name: str
    address: str
    type: str
    store_id: Optional[str] = None

class Stock(MongoModel):
    food_id: str
    quantity: int
    unit_id: str
    supplier_id: str
    last_restock_date: str
    expiration_date: Optional[str] = None

class StockAdjustment(MongoModel):
    stock_id: str
    quantity_change: int
    reason: str
    adjustment_date: str
