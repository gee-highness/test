# app/models/hr.py
from typing import Optional, List, Dict, Any, Literal
from pydantic import Field, EmailStr
from datetime import datetime, timedelta, date
import asyncio
from .base import MongoModel

class Department(MongoModel):
    name: str
    store_id: str

class PersonalDetails(MongoModel):
    citizenship: Optional[str] = None
    gender: Optional[str] = None
    birth_date: Optional[str] = None
    age: Optional[str] = None
    
    def to_response_dict(self) -> dict:
        """Convert PersonalDetails to dictionary for response"""
        return {
            "citizenship": self.citizenship,
            "gender": self.gender,
            "birth_date": self.birth_date,
            "age": self.age
        }

class ContactDetails(MongoModel):
    cell_phone: Optional[str] = None
    whatsapp_number: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    
    def to_response_dict(self) -> dict:
        """Convert ContactDetails to dictionary for response"""
        return {
            "cell_phone": self.cell_phone,
            "whatsapp_number": self.whatsapp_number,
            "email": self.email,
            "address": self.address
        }

class EmploymentDetails(MongoModel):
    job_title: Optional[str] = None
    team: Optional[str] = None
    employment_type: Optional[str] = None
    location: Optional[str] = None
    
    def to_response_dict(self) -> dict:
        """Convert EmploymentDetails to dictionary for response"""
        return {
            "job_title": self.job_title,
            "team": self.team,
            "employment_type": self.employment_type,
            "location": self.location
        }

class EmployeeStatus(MongoModel):
    current_status: str
    on_leave_since: Optional[str] = None
    termination_date: Optional[str] = None
    termination_reason: Optional[str] = None
    
    def to_response_dict(self) -> dict:
        """Convert EmployeeStatus to dictionary for response"""
        return {
            "current_status": self.current_status,
            "on_leave_since": self.on_leave_since,
            "termination_date": self.termination_date,
            "termination_reason": self.termination_reason
        }

class Employee(MongoModel):
    user_id: str
    job_title_id: str
    access_role_ids: List[str]
    tenant_id: str
    store_id: str
    main_access_role_id: str
    hire_date: datetime  
    salary: float
    first_name: str
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    
    # Frontend-specific fields
    employee_id: Optional[str] = None
    full_name: Optional[str] = None
    middle_name: Optional[str] = None
    suffix: Optional[str] = None
    profile_photo_url: Optional[str] = None
    
    personal_details: Optional[PersonalDetails] = None
    contact_details: Optional[ContactDetails] = None
    employment_details: Optional[EmploymentDetails] = None
    status: Optional[EmployeeStatus] = None

    # NEW: email used for user creation/lookup (not stored in employee document)
    email: Optional[str] = None
    
    def to_response_dict(self) -> dict:
        """Convert Employee to dictionary for response with proper nested object handling"""
        data = self.model_dump()
        
        # Convert nested objects to dictionaries
        if self.personal_details:
            data['personal_details'] = self.personal_details.to_response_dict() if hasattr(self.personal_details, 'to_response_dict') else self.personal_details
            
        if self.contact_details:
            data['contact_details'] = self.contact_details.to_response_dict() if hasattr(self.contact_details, 'to_response_dict') else self.contact_details
            
        if self.employment_details:
            data['employment_details'] = self.employment_details.to_response_dict() if hasattr(self.employment_details, 'to_response_dict') else self.employment_details
            
        if self.status:
            data['status'] = self.status.to_response_dict() if hasattr(self.status, 'to_response_dict') else self.status
            
        return data

class AccessRole(MongoModel):
    name: str
    description: str
    permissions: List[str]
    landing_page: str

class JobTitle(MongoModel):
    title: str
    description: Optional[str] = None
    department: str
    store_id: str

class Shift(MongoModel):
    employee_id: str
    start: datetime  # Changed from str to datetime
    end: datetime    # Changed from str to datetime
    title: Optional[str] = None
    employee_name: Optional[str] = None
    color: Optional[str] = None
    active: Optional[bool] = True
    recurring: Optional[bool] = False
    recurring_day: Optional[int] = None
    recurrence_end_date: Optional[datetime] = None
    # created_at and updated_at are inherited from MongoModel as datetime

class TimesheetEntry(MongoModel):
    employee_id: str
    clock_in: datetime  # Changed from str to datetime
    clock_out: Optional[datetime] = None  # Changed from str to datetime
    duration_minutes: Optional[int] = 0
    store_id: str
    # created_at and updated_at are inherited from MongoModel as datetime

class PayrollDeduction(MongoModel):
    id: Optional[str] = None
    payroll_id: str
    type: str  # "tax" | "insurance" | "retirement" | "other"
    description: str
    amount: float
    
    def to_response_dict(self) -> dict:
        """Convert PayrollDeduction to dictionary for response"""
        return {
            "id": self.id,
            "payroll_id": self.payroll_id,
            "type": self.type,
            "description": self.description,
            "amount": self.amount,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

# In your backend PayrollSettings model, add these fields:
class PayrollSettings(MongoModel):
    store_id: str
    default_payment_cycle: Literal["weekly", "bi-weekly", "monthly"] = "bi-weekly"
    tax_rate: float = 0.20
    overtime_multiplier: float = 1.5
    overtime_threshold: float = 40  # hours per week
    pay_day: Optional[int] = 15  # Day of month for monthly payments
    auto_process: bool = False
    include_benefits: bool = False
    benefits_rate: float = 0.05

class Payroll(MongoModel):
    employee_id: str
    pay_period_start: datetime  # This should be datetime
    pay_period_end: datetime    # This should be datetime
    payment_cycle: str  # "weekly" | "bi-weekly" | "monthly"
    gross_pay: float
    tax_deductions: float
    net_pay: float
    status: str  # "pending" | "processing" | "paid" | "failed"
    hours_worked: float
    overtime_hours: float
    overtime_rate: float
    deductions: Optional[List[PayrollDeduction]] = []
    store_id: str
    
    def to_response_dict(self) -> dict:
        """Convert Payroll to dictionary for response with proper nested handling"""
        data = self.model_dump()
        
        # Convert deductions to dictionaries
        if self.deductions:
            data['deductions'] = [
                deduction.to_response_dict() if hasattr(deduction, 'to_response_dict') 
                else deduction for deduction in self.deductions
            ]
        
        return data

class Company(MongoModel):
    company_id: str
    name: str
    country: str
    tax_details: Dict[str, Any]
    metrics: Dict[str, Any]

class Timesheet(MongoModel):
    timesheet_id: str
    employee_id: str
    start_date: str
    end_date: str
    daily_hours: Dict[str, str]
    total_weekly_hours: str

class TaxDetails(MongoModel):
    tax_year: str
    efiling_admin: str
    related_docs: str

class CompanyMetrics(MongoModel):
    total_employees: int
    active_employees: int
    employees_on_leave: int
    terminated_employees: int
    full_time_employees: int
    part_time_employees: int
    contract_employees: int
    employee_invites: Dict[str, int]

class EmployeeInvites(MongoModel):
    sent: int
    active: int
    require_attention: int
