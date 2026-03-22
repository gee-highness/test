# app/routes/hr.py - COMPLETELY UPDATED
from fastapi import APIRouter, HTTPException, Query, status, Body
from typing import List, Optional, Any  # Add Any to the imports
from app.database import get_collection
from app.models.hr import Employee, Shift, TimesheetEntry, Payroll, AccessRole, JobTitle, PayrollSettings, Timesheet, Department
from app.models.response import (
    StandardResponse, EmployeeResponse, ShiftResponse, TimesheetEntryResponse, PayrollResponse, 
    AccessRoleResponse, JobTitleResponse, PayrollSettingsResponse, TimesheetResponse,
    DepartmentResponse, PayrollPreviewResponse
)
from app.utils.response_helpers import success_response, error_response, handle_http_exception, handle_generic_exception
from app.utils.mongo_helpers import to_mongo_dict, to_mongo_update_dict
from bson import ObjectId
from datetime import datetime, timedelta
import asyncio


RECURRENCE_WEEKS = 52 # Create shifts for one year

async def _process_shift_recurrence(shift_data: dict, original_shift_id: ObjectId):
    """
    Helper to process recurring shifts by creating future shift instances.
    """
    if not shift_data.get("recurring"):
        return

    # Use the original shift's ID as the series ID to link all instances
    recurring_series_id = str(original_shift_id)
    
    # Extract and parse dates
    try:
        # Note: The 'start' and 'end' from MongoDB will be ISO-formatted strings
        start_dt = datetime.fromisoformat(shift_data["start"])
        end_dt = datetime.fromisoformat(shift_data["end"])
    except:
        # Failsafe for incorrect date format
        return

    duration = end_dt - start_dt
    shifts_collection = get_collection("shifts")
    
    # Generate future shifts (starting from the week *after* the original shift)
    for i in range(1, RECURRENCE_WEEKS + 1):
        new_start_dt = start_dt + timedelta(weeks=i)
        new_end_dt = new_start_dt + duration
        
        # Check against an optional recurrence_end_date
        recurrence_end_date_str = shift_data.get("recurrence_end_date")
        if recurrence_end_date_str:
             try:
                recurrence_end_date = datetime.fromisoformat(recurrence_end_date_str)
                # Stop if the new shift starts after the recurrence end date
                if new_start_dt.date() > recurrence_end_date.date():
                    break
             except:
                pass # Continue if end date is invalid
        
        # Create new shift data
        new_shift_data = shift_data.copy()
        new_shift_data["start"] = new_start_dt.isoformat()
        new_shift_data["end"] = new_end_dt.isoformat()
        
        # Link to the series
        new_shift_data["recurring"] = True
        new_shift_data["recurring_series_id"] = recurring_series_id
        new_shift_data.pop("_id", None)
        new_shift_data.pop("id", None)
        
        # Create a new Shift model instance and get the dict for MongoDB insertion
        new_shift_instance = Shift(**new_shift_data)
        new_shift_mongo_dict = to_mongo_dict(new_shift_instance)
        
        # Insert the new recurring shift
        await shifts_collection.insert_one(new_shift_mongo_dict)



router = APIRouter(prefix="/api", tags=["hr"])

# -----------------
# Department endpoints
# -----------------
@router.get("/departments", response_model=StandardResponse[List[DepartmentResponse]])
async def get_departments(store_id: Optional[str] = Query(None)):
    """Retrieve a list of departments, optionally filtered by store_id."""
    try:
        departments_collection = get_collection("departments")
        query = {"store_id": store_id} if store_id else {}
        departments = []
        # FIXED: Use await and iterate
        dept_docs = await departments_collection.find(query)
        for department in dept_docs:
            departments.append(Department.from_mongo(department))
        return success_response(data=departments)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/departments/{department_id}", response_model=StandardResponse[DepartmentResponse])
async def get_department(department_id: str):
    """Retrieve a single department by ID."""
    try:
        departments_collection = get_collection("departments")
        department = await departments_collection.find_one({"_id": ObjectId(department_id)})
        if department:
            return success_response(data=Department.from_mongo(department))
        return error_response(message="Department not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for department", code=400)

@router.post("/departments", response_model=StandardResponse[DepartmentResponse])
async def create_department(department: Department):
    """Create a new department."""
    try:
        departments_collection = get_collection("departments")
        department_dict = to_mongo_dict(department)
        
        result = await departments_collection.insert_one(department_dict)
        new_department = await departments_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=Department.from_mongo(new_department),
            message="Department created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/departments/{department_id}", response_model=StandardResponse[DepartmentResponse])
async def update_department(department_id: str, department: Department):
    """Update an existing department."""
    try:
        departments_collection = get_collection("departments")
        department_dict = to_mongo_update_dict(department, exclude_unset=True)
        
        result = await departments_collection.update_one(
            {"_id": ObjectId(department_id)}, {"$set": department_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Department not found", code=404)
        
        updated_department = await departments_collection.find_one({"_id": ObjectId(department_id)})
        return success_response(
            data=Department.from_mongo(updated_department),
            message="Department updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for department", code=400)

@router.delete("/departments/{department_id}", response_model=StandardResponse[dict])
async def delete_department(department_id: str):
    """Delete a department."""
    try:
        departments_collection = get_collection("departments")
        result = await departments_collection.delete_one({"_id": ObjectId(department_id)})
        if result.deleted_count == 0:
            return error_response(message="Department not found", code=404)
        return success_response(
            data=None,
            message="Department deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for department", code=400)

# -----------------
# Employees endpoints
# -----------------
@router.get("/employees", response_model=StandardResponse[List[EmployeeResponse]])
async def get_employees(store_id: Optional[str] = Query(None)):
    """Retrieve a list of employees, optionally filtered by store_id."""
    try:
        employees_collection = get_collection("employees")
        query = {"store_id": store_id} if store_id else {}
        employees = []
        # FIXED: Use await and iterate
        employee_docs = await employees_collection.find(query)
        for employee in employee_docs:
            employees.append(Employee.from_mongo(employee))
        return success_response(data=employees)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/employees/{employee_id}", response_model=StandardResponse[EmployeeResponse])
async def get_employee(employee_id: str):
    """Retrieve a single employee by ID."""
    try:
        employees_collection = get_collection("employees")
        employee = await employees_collection.find_one({"_id": ObjectId(employee_id)})
        if employee:
            return success_response(data=Employee.from_mongo(employee))
        return error_response(message="Employee not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for employee", code=400)

@router.post("/employees", response_model=StandardResponse[EmployeeResponse])
async def create_employee(employee: Employee):
    """Create a new employee record."""
    try:
        employees_collection = get_collection("employees")
        employee_dict = to_mongo_dict(employee)
        
        result = await employees_collection.insert_one(employee_dict)
        new_employee = await employees_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=Employee.from_mongo(new_employee),
            message="Employee created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/employees/{employee_id}", response_model=StandardResponse[EmployeeResponse])
async def update_employee(employee_id: str, employee: Employee):
    """Update an existing employee record by ID."""
    try:
        employees_collection = get_collection("employees")
        employee_dict = to_mongo_update_dict(employee, exclude_unset=True)
        
        result = await employees_collection.update_one(
            {"_id": ObjectId(employee_id)}, {"$set": employee_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Employee not found", code=404)
        
        updated_employee = await employees_collection.find_one({"_id": ObjectId(employee_id)})
        return success_response(
            data=Employee.from_mongo(updated_employee),
            message="Employee updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for employee", code=400)

@router.delete("/employees/{employee_id}", response_model=StandardResponse[dict])
async def delete_employee(employee_id: str):
    """Delete an employee record by ID."""
    try:
        employees_collection = get_collection("employees")
        result = await employees_collection.delete_one({"_id": ObjectId(employee_id)})
        if result.deleted_count == 0:
            return error_response(message="Employee not found", code=404)
        return success_response(
            data=None,
            message="Employee deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for employee", code=400)

# -----------------
# Access Roles endpoints
# -----------------
@router.get("/access_roles", response_model=StandardResponse[List[AccessRoleResponse]])
async def get_access_roles():
    """Retrieve all defined access roles."""
    try:
        access_roles_collection = get_collection("access_roles")
        roles = []
        # FIXED: Use await and iterate
        role_docs = await access_roles_collection.find()
        for role in role_docs:
            roles.append(AccessRole.from_mongo(role))
        return success_response(data=roles)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/access_roles/{role_id}", response_model=StandardResponse[AccessRoleResponse])
async def get_access_role(role_id: str):
    """Retrieve a single access role by ID."""
    try:
        access_roles_collection = get_collection("access_roles")
        role = await access_roles_collection.find_one({"_id": ObjectId(role_id)})
        if role:
            return success_response(data=AccessRole.from_mongo(role))
        return error_response(message="Access role not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for access role", code=400)

@router.post("/access_roles", response_model=StandardResponse[AccessRoleResponse])
async def create_access_role(role: AccessRole):
    """Create a new access role."""
    try:
        access_roles_collection = get_collection("access_roles")
        role_dict = to_mongo_dict(role)
        
        result = await access_roles_collection.insert_one(role_dict)
        new_role = await access_roles_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=AccessRole.from_mongo(new_role),
            message="Access role created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/access_roles/{role_id}", response_model=StandardResponse[AccessRoleResponse])
async def update_access_role(role_id: str, role: AccessRole):
    """Update an existing access role by ID."""
    try:
        access_roles_collection = get_collection("access_roles")
        role_dict = to_mongo_update_dict(role, exclude_unset=True)
        
        result = await access_roles_collection.update_one(
            {"_id": ObjectId(role_id)}, {"$set": role_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Access role not found", code=404)
        
        updated_role = await access_roles_collection.find_one({"_id": ObjectId(role_id)})
        return success_response(
            data=AccessRole.from_mongo(updated_role),
            message="Access role updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for access role", code=400)

@router.delete("/access_roles/{role_id}", response_model=StandardResponse[dict])
async def delete_access_role(role_id: str):
    """Delete an access role by ID."""
    try:
        access_roles_collection = get_collection("access_roles")
        result = await access_roles_collection.delete_one({"_id": ObjectId(role_id)})
        if result.deleted_count == 0:
            return error_response(message="Access role not found", code=404)
        return success_response(
            data=None,
            message="Access role deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for access role", code=400)

# -----------------
# Job Titles endpoints
# -----------------
@router.get("/job_titles", response_model=StandardResponse[List[JobTitleResponse]])
async def get_job_titles(store_id: Optional[str] = Query(None)):
    """Retrieve a list of job titles, optionally filtered by store_id."""
    try:
        job_titles_collection = get_collection("job_titles")
        query = {"store_id": store_id} if store_id else {}
        titles = []
        # FIXED: Use await and iterate
        title_docs = await job_titles_collection.find(query)
        for title in title_docs:
            titles.append(JobTitle.from_mongo(title))
        return success_response(data=titles)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/job_titles/{title_id}", response_model=StandardResponse[JobTitleResponse])
async def get_job_title(title_id: str):
    """Retrieve a single job title by ID."""
    try:
        job_titles_collection = get_collection("job_titles")
        title = await job_titles_collection.find_one({"_id": ObjectId(title_id)})
        if title:
            return success_response(data=JobTitle.from_mongo(title))
        return error_response(message="Job title not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for job title", code=400)

@router.post("/job_titles", response_model=StandardResponse[JobTitleResponse])
async def create_job_title(title: JobTitle):
    """Create a new job title."""
    try:
        job_titles_collection = get_collection("job_titles")
        title_dict = to_mongo_dict(title)
        
        result = await job_titles_collection.insert_one(title_dict)
        new_title = await job_titles_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=JobTitle.from_mongo(new_title),
            message="Job title created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/job_titles/{title_id}", response_model=StandardResponse[JobTitleResponse])
async def update_job_title(title_id: str, title: JobTitle):
    """Update an existing job title by ID."""
    try:
        job_titles_collection = get_collection("job_titles")
        title_dict = to_mongo_update_dict(title, exclude_unset=True)
        
        result = await job_titles_collection.update_one(
            {"_id": ObjectId(title_id)}, {"$set": title_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Job title not found", code=404)
        
        updated_title = await job_titles_collection.find_one({"_id": ObjectId(title_id)})
        return success_response(
            data=JobTitle.from_mongo(updated_title),
            message="Job title updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for job title", code=400)

@router.delete("/job_titles/{title_id}", response_model=StandardResponse[dict])
async def delete_job_title(title_id: str):
    """Delete a job title by ID."""
    try:
        job_titles_collection = get_collection("job_titles")
        result = await job_titles_collection.delete_one({"_id": ObjectId(title_id)})
        if result.deleted_count == 0:
            return error_response(message="Job title not found", code=404)
        return success_response(
            data=None,
            message="Job title deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for job title", code=400)

# -----------------
# Shifts endpoints
# -----------------
@router.get("/shifts", response_model=StandardResponse[List[ShiftResponse]])
async def get_shifts(employee_id: Optional[str] = Query(None), active: Optional[bool] = Query(None)):
    """Retrieve a list of shifts, optionally filtered by employee_id or active status."""
    try:
        shifts_collection = get_collection("shifts")
        query = {}
        if employee_id:
            query["employee_id"] = employee_id
        if active is not None:
            query["active"] = active
            
        shifts = []
        # FIXED: Use await and iterate
        shift_docs = await shifts_collection.find(query)
        for shift in shift_docs:
            shifts.append(Shift.from_mongo(shift))
        return success_response(data=shifts)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/shifts/{shift_id}", response_model=StandardResponse[ShiftResponse])
async def get_shift(shift_id: str):
    """Retrieve a single shift by ID."""
    try:
        shifts_collection = get_collection("shifts")
        shift = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
        if shift:
            return success_response(data=Shift.from_mongo(shift))
        return error_response(message="Shift not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for shift", code=400)

async def _create_item(collection_name: str, item: Any, response_model: Any):
    """Generic helper to create items in collections."""
    try:
        collection = get_collection(collection_name)
        item_dict = to_mongo_dict(item)
        
        print(f"🔍 [Backend] Inserting into {collection_name}: {item_dict}")
        
        result = await collection.insert_one(item_dict)
        new_item = await collection.find_one({"_id": result.inserted_id})
        
        print(f"🔍 [Backend] Inserted item: {new_item}")
        
        # For shifts, we need special handling for recurrence
        if collection_name == "shifts" and new_item.get("recurring"):
            shift_id = result.inserted_id
            
            # Set recurring_series_id for the original shift
            await collection.update_one(
                {"_id": shift_id},
                {"$set": {"recurring_series_id": str(shift_id)}}
            )
            
            # Fetch updated document
            new_item = await collection.find_one({"_id": shift_id})
            
            # Process recurrence for future shifts
            await _process_shift_recurrence(new_item, shift_id)
            
            # Fetch final document
            new_item = await collection.find_one({"_id": shift_id})
        
        return success_response(
            data=response_model.from_mongo(new_item),
            message=f"{collection_name[:-1].title()} created successfully",
            code=201
        )
    except Exception as e:
        print(f"❌ [Backend] Error in _create_item: {str(e)}")
        return handle_generic_exception(e)

async def _delete_item(collection_name: str, item_id: str):
    """Generic helper to delete items from collections."""
    try:
        collection = get_collection(collection_name)
        result = await collection.delete_one({"_id": ObjectId(item_id)})
        if result.deleted_count == 0:
            return error_response(message=f"{collection_name[:-1].title()} not found", code=404)
        return success_response(
            data=None,
            message=f"{collection_name[:-1].title()} deleted successfully"
        )
    except Exception:
        return error_response(message=f"Invalid ID format for {collection_name[:-1]}", code=400)

async def _delete_item(collection_name: str, item_id: str):
    """Generic helper to delete items from collections."""
    try:
        collection = get_collection(collection_name)
        result = await collection.delete_one({"_id": ObjectId(item_id)})
        if result.deleted_count == 0:
            return error_response(message=f"{collection_name[:-1].title()} not found", code=404)
        return success_response(
            data=None,
            message=f"{collection_name[:-1].title()} deleted successfully"
        )
    except Exception:
        return error_response(message=f"Invalid ID format for {collection_name[:-1]}", code=400)

@router.post("/shifts", response_model=StandardResponse[ShiftResponse])
async def create_shift(shift: Shift):
    """Create a new shift, including recurrence logic."""
    try:
        # 1. Standard creation
        shifts_collection = get_collection("shifts")
        shift_dict = to_mongo_dict(shift)
        
        print(f"🔍 [Backend] Inserting shift: {shift_dict}")
        
        result = await shifts_collection.insert_one(shift_dict)
        new_shift_doc = await shifts_collection.find_one({"_id": result.inserted_id})
        
        # Convert to Shift model for response
        new_shift = Shift.from_mongo(new_shift_doc)
        
        print(f"🔍 [Backend] Created shift: {new_shift}")
        
        # 2. Update original shift with its own id as recurring_series_id and process recurrence
        if new_shift.recurring:
            original_shift_id = result.inserted_id
            
            # Set the series ID on the original shift
            await shifts_collection.update_one(
                {"_id": original_shift_id},
                {"$set": {"recurring_series_id": str(original_shift_id)}}
            )
            
            # Fetch the updated doc with the correct 'created_at' and 'updated_at' for recurrence
            updated_doc = await shifts_collection.find_one({"_id": original_shift_id})
            
            # Process recurrence
            await _process_shift_recurrence(updated_doc, original_shift_id)
            
            # Re-fetch the shift to get the updated data
            new_shift_doc = await shifts_collection.find_one({"_id": result.inserted_id})
            new_shift = Shift.from_mongo(new_shift_doc)

        # Return the shift data in the standard response format
        return success_response(
            data=new_shift,
            message="Shift created successfully",
            code=201
        )
    except Exception as e:
        print(f"❌ [Backend] Error creating shift: {str(e)}")
        return handle_generic_exception(e)

# app/routes/hr.py

# PUT /api/shifts/{shift_id} - Update a shift
@router.put("/shifts/{shift_id}", response_model=StandardResponse[ShiftResponse])
async def update_shift(shift_id: str, shift: Shift):
    """Update an existing shift, and handle recurrence updates."""
    try:
        shifts_collection = get_collection("shifts")
        
        # Check if shift exists
        old_shift_doc = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
        if not old_shift_doc:
            return error_response(message="Shift not found", code=404)
            
        old_shift = Shift.from_mongo(old_shift_doc)
        update_data = to_mongo_update_dict(shift)

        print(f"🔍 [Backend] Updating shift {shift_id} with data: {update_data}")

        # 1. Perform the update on the specific shift instance
        result = await shifts_collection.update_one(
            {"_id": ObjectId(shift_id)},
            {"$set": update_data}
        )

        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Shift not found", code=404)

        # 2. Handle Recurrence Logic Changes
        updated_doc = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
        series_id = updated_doc.get("recurring_series_id") or shift_id
        
        # A. If recurrence is kept or newly added, re-process future shifts
        if updated_doc.get("recurring"):
            # Ensure the recurring_series_id is set if it was a new recurrence
            if not updated_doc.get("recurring_series_id"):
                 await shifts_collection.update_one(
                    {"_id": ObjectId(shift_id)},
                    {"$set": {"recurring_series_id": shift_id}}
                )
                 updated_doc = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
                 series_id = shift_id

            # Delete all *future* recurring shifts in the series
            await shifts_collection.delete_many({
                "recurring_series_id": series_id,
                "start": {"$gt": old_shift_doc.get("start")} 
            })
            
            # Re-create future shifts based on the new, updated shift data
            await _process_shift_recurrence(updated_doc, ObjectId(series_id))
            
        # B. If recurrence was removed
        elif old_shift.recurring and not updated_doc.get("recurring"):
            # Delete all future recurring shifts in the series
            await shifts_collection.delete_many({
                "recurring_series_id": series_id,
                "start": {"$gt": old_shift_doc.get("start")}
            })
            
        # 3. Retrieve and return the FINAL updated shift
        final_doc = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
        
        if not final_doc:
            return error_response(message="Shift not found after update", code=404)
            
        # Convert to Shift model and return in standard response
        final_shift = Shift.from_mongo(final_doc)
        
        return success_response(
            data=final_shift,
            message="Shift updated successfully"
        )
    except Exception as e:
        print(f"❌ [Backend] Error updating shift: {str(e)}")
        return handle_generic_exception(e)
@router.put("/shifts/{shift_id}/status", response_model=StandardResponse[ShiftResponse])
async def update_shift_status(shift_id: str, active: bool):
    """Update the active status of a shift by ID."""
    try:
        shifts_collection = get_collection("shifts")
        result = await shifts_collection.update_one(
            {"_id": ObjectId(shift_id)}, 
            {"$set": {"active": active, "updated_at": datetime.utcnow().isoformat()}}
        )
        if result.modified_count == 0:
            return error_response(message="Shift not found", code=404)
        
        updated_shift = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
        return success_response(
            data=Shift.from_mongo(updated_shift),
            message="Shift status updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for shift", code=400)

# app/routes/hr.py

# DELETE /api/shifts/{shift_id} - Delete a shift
@router.delete("/shifts/{shift_id}", response_model=StandardResponse[dict])
async def delete_shift(shift_id: str, delete_all: bool = Query(False, description="If true, deletes all future shifts in the recurring series.")):
    """Delete a single shift (and optionally its future recurring instances)."""
    
    shifts_collection = get_collection("shifts")
    shift_doc = await shifts_collection.find_one({"_id": ObjectId(shift_id)})
    
    if not shift_doc:
        return error_response(message="Shift not found", code=404)
        
    is_recurring = shift_doc.get("recurring", False)
    series_id = shift_doc.get("recurring_series_id")
    
    # If it's a recurring shift and the user specifies delete_all (or is deleting the original shift), delete the series
    if is_recurring and delete_all:
        print(f"Deleting all future recurring shifts for series: {series_id or shift_id}")
        await shifts_collection.delete_many({
            "recurring_series_id": series_id,
            "start": {"$gt": shift_doc.get("start")}
        })
    
    # Delete the specific shift instance
    return await _delete_item("shifts", shift_id)

# -----------------
# Timesheet Entries endpoints
# -----------------
@router.get("/timesheet_entries", response_model=StandardResponse[List[TimesheetEntryResponse]])
async def get_timesheet_entries(
    employee_id: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None)
):
    """Retrieve timesheet entries, optionally filtered by employee_id or date range."""
    try:
        ts_collection = get_collection("timesheet_entries")
        query = {}
        if employee_id:
            query["employee_id"] = employee_id
        
        if date_from and date_to:
            try:
                start_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                query["clock_in"] = {
                    "$gte": start_dt.isoformat(),
                    "$lte": end_dt.isoformat()
                }
            except ValueError:
                return error_response(message="Invalid date format. Use ISO 8601 format.", code=400)
        
        entries = []
        # FIXED: Use await and iterate
        entry_docs = await ts_collection.find(query)
        for entry in entry_docs:
            entries.append(TimesheetEntry.from_mongo(entry))
        return success_response(data=entries)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/timesheet_entries/{entry_id}", response_model=StandardResponse[TimesheetEntryResponse])
async def get_timesheet_entry(entry_id: str):
    """Retrieve a single timesheet entry by ID."""
    try:
        ts_collection = get_collection("timesheet_entries")
        entry = await ts_collection.find_one({"_id": ObjectId(entry_id)})
        if entry:
            return success_response(data=TimesheetEntry.from_mongo(entry))
        return error_response(message="Timesheet entry not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for timesheet entry", code=400)

@router.post("/timesheet_entries", response_model=StandardResponse[TimesheetEntryResponse])
async def create_timesheet_entry(entry: TimesheetEntry):
    """Create a new timesheet entry."""
    try:
        ts_collection = get_collection("timesheet_entries")
        entry_dict = to_mongo_dict(entry)
        
        result = await ts_collection.insert_one(entry_dict)
        new_entry = await ts_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=TimesheetEntry.from_mongo(new_entry),
            message="Timesheet entry created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/timesheet_entries/{entry_id}", response_model=StandardResponse[TimesheetEntryResponse])
async def update_timesheet_entry(entry_id: str, entry: TimesheetEntry):
    """Update an existing timesheet entry by ID."""
    try:
        ts_collection = get_collection("timesheet_entries")
        entry_dict = to_mongo_update_dict(entry, exclude_unset=True)
        
        # Calculate duration if clock_out is provided
        if entry.clock_out and entry.clock_in:
            try:
                clock_in = datetime.fromisoformat(entry.clock_in.replace('Z', '+00:00'))
                clock_out = datetime.fromisoformat(entry.clock_out.replace('Z', '+00:00'))
                duration = int((clock_out - clock_in).total_seconds() / 60)
                entry_dict["duration_minutes"] = duration
            except (ValueError, TypeError):
                entry_dict["duration_minutes"] = 0
        
        result = await ts_collection.update_one(
            {"_id": ObjectId(entry_id)}, {"$set": entry_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Timesheet entry not found", code=404)
        
        updated_entry = await ts_collection.find_one({"_id": ObjectId(entry_id)})
        return success_response(
            data=TimesheetEntry.from_mongo(updated_entry),
            message="Timesheet entry updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for timesheet entry", code=400)

@router.delete("/timesheet_entries/{entry_id}", response_model=StandardResponse[dict])
async def delete_timesheet_entry(entry_id: str):
    """Delete a timesheet entry by ID."""
    try:
        ts_collection = get_collection("timesheet_entries")
        result = await ts_collection.delete_one({"_id": ObjectId(entry_id)})
        if result.deleted_count == 0:
            return error_response(message="Timesheet entry not found", code=404)
        return success_response(
            data=None,
            message="Timesheet entry deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for timesheet entry", code=400)

# Clock in/out endpoints
@router.post("/timesheet_entries/clock-in", response_model=StandardResponse[TimesheetEntryResponse])
async def clock_in(employee_id: str, store_id: str):
    """Records a clock-in event for an employee."""
    try:
        ts_collection = get_collection("timesheet_entries")
        
        # Check if employee already clocked in
        existing_entry = await ts_collection.find_one({
            "employee_id": employee_id,
            "clock_out": None
        })
        
        if existing_entry:
            return error_response(message="Employee is already clocked in", code=400)
        
        clock_in_time = datetime.utcnow().isoformat()
        entry_dict = {
            "employee_id": employee_id,
            "store_id": store_id,
            "clock_in": clock_in_time,
            "clock_out": None,
            "duration_minutes": 0,
            "created_at": clock_in_time,
            "updated_at": clock_in_time
        }
        
        result = await ts_collection.insert_one(entry_dict)
        new_entry = await ts_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=TimesheetEntry.from_mongo(new_entry),
            message="Clock in successful",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/timesheet_entries/{entry_id}/clock-out", response_model=StandardResponse[TimesheetEntryResponse])
async def clock_out(entry_id: str):
    """Records a clock-out event for an active timesheet entry."""
    try:
        ts_collection = get_collection("timesheet_entries")
        entry = await ts_collection.find_one({"_id": ObjectId(entry_id)})
        
        if not entry:
            return error_response(message="Timesheet entry not found", code=404)
            
        if entry.get("clock_out") is not None:
            return error_response(message="Timesheet entry is already clocked out", code=400)
        
        clock_out_time = datetime.utcnow().isoformat()
        clock_in_time = entry.get("clock_in")
        
        # Calculate duration
        duration = 0
        try:
            if isinstance(clock_in_time, str):
                clock_in_dt = datetime.fromisoformat(clock_in_time.replace('Z', '+00:00'))
            else:
                clock_in_dt = clock_in_time 
                
            clock_out_dt = datetime.utcnow()
            duration = int((clock_out_dt - clock_in_dt).total_seconds() / 60)
        except (ValueError, TypeError):
            duration = 0
    
        update_data = {
            "clock_out": clock_out_time,
            "duration_minutes": duration,
            "updated_at": datetime.utcnow().isoformat()
        }

        result = await ts_collection.update_one(
            {"_id": ObjectId(entry_id)},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            return error_response(message="Timesheet entry not found or no changes made", code=404)
        
        updated_entry = await ts_collection.find_one({"_id": ObjectId(entry_id)})
        return success_response(
            data=TimesheetEntry.from_mongo(updated_entry),
            message="Clock out successful"
        )
    except Exception:
        return error_response(message="Invalid ID format for timesheet entry", code=400)

# -----------------
# Payroll endpoints
# -----------------
@router.get("/payroll", response_model=StandardResponse[List[PayrollResponse]])
async def get_payroll_entries(
    employee_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None)
):
    """Retrieve payroll entries, optionally filtered by employee_id or status."""
    try:
        payroll_collection = get_collection("payroll")
        query = {"store_id": store_id} if store_id else {}
        
        payroll_list = []
        # FIXED: Use async for loop instead of to_list()
        async for payroll in payroll_collection.find(query):
            payroll_list.append(Payroll.from_mongo(payroll))
            
        return success_response(data=entries)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/payroll/{payroll_id}", response_model=StandardResponse[PayrollResponse])
async def get_payroll_entry(payroll_id: str):
    """Retrieve a single payroll entry by ID."""
    try:
        payroll_collection = get_collection("payroll")
        entry = await payroll_collection.find_one({"_id": ObjectId(payroll_id)})
        if entry:
            payroll_model = Payroll.from_mongo(entry)
            return success_response(data=payroll_model)
        return error_response(message="Payroll entry not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for payroll entry", code=400)

@router.post("/payroll", response_model=StandardResponse[PayrollResponse])
async def create_payroll_entry(entry: Payroll):
    """Create a new payroll entry."""
    try:
        payroll_collection = get_collection("payroll")
        entry_dict = to_mongo_dict(entry)
        
        result = await payroll_collection.insert_one(entry_dict)
        new_entry = await payroll_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=Payroll.from_mongo(new_entry),
            message="Payroll entry created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/payroll/{payroll_id}", response_model=StandardResponse[PayrollResponse])
async def update_payroll_entry(payroll_id: str, entry: Payroll):
    """Update an existing payroll entry by ID."""
    try:
        payroll_collection = get_collection("payroll")
        entry_dict = to_mongo_update_dict(entry, exclude_unset=True)
        
        result = await payroll_collection.update_one(
            {"_id": ObjectId(payroll_id)}, {"$set": entry_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Payroll entry not found", code=404)
        
        updated_entry = await payroll_collection.find_one({"_id": ObjectId(payroll_id)})
        return success_response(
            data=Payroll.from_mongo(updated_entry),
            message="Payroll entry updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for payroll entry", code=400)

@router.post("/payroll/{payroll_id}/process", response_model=StandardResponse[PayrollResponse])
async def process_payroll(payroll_id: str):
    """Simulate the processing of a payroll entry."""
    try:
        payroll_collection = get_collection("payroll")
        
        # Update status to processing
        await payroll_collection.update_one(
            {"_id": ObjectId(payroll_id)},
            {"$set": {"status": "processing", "updated_at": datetime.utcnow().isoformat()}}
        )
    
        # Simulate processing delay
        await asyncio.sleep(2)
    
        # Update status to paid
        result = await payroll_collection.update_one(
            {"_id": ObjectId(payroll_id)},
            {"$set": {"status": "paid", "updated_at": datetime.utcnow().isoformat()}}
        )
        
        if result.modified_count == 0:
            if await payroll_collection.find_one({"_id": ObjectId(payroll_id)}):
                pass
            else:
                return error_response(message="Payroll entry not found", code=404)
        
        updated_entry = await payroll_collection.find_one({"_id": ObjectId(payroll_id)})
        return success_response(
            data=Payroll.from_mongo(updated_entry),
            message="Payroll processed successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for payroll entry", code=400)

@router.delete("/payroll/{payroll_id}", response_model=StandardResponse[dict])
async def delete_payroll_entry(payroll_id: str):
    """Delete a payroll entry by ID."""
    try:
        payroll_collection = get_collection("payroll")
        result = await payroll_collection.delete_one({"_id": ObjectId(payroll_id)})
        if result.deleted_count == 0:
            return error_response(message="Payroll entry not found", code=404)
        return success_response(
            data=None,
            message="Payroll entry deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for payroll entry", code=400)

# -----------------
# Payroll settings endpoints
# -----------------
@router.get("/payroll_settings", response_model=StandardResponse[PayrollSettingsResponse])
async def get_payroll_settings(store_id: Optional[str] = Query(None)):
    """Retrieve payroll settings for a store or default settings."""
    try:
        settings_collection = get_collection("payroll_settings")
        query = {"store_id": store_id} if store_id else {"store_id": "default"}
        
        settings = await settings_collection.find_one(query)
        if not settings:
            # Create default settings with ALL fields
            default_settings = PayrollSettings(
                store_id=store_id or "default",
                default_payment_cycle="bi-weekly",
                tax_rate=0.20,
                overtime_multiplier=1.5,
                overtime_threshold=40,
                pay_day=15,
                auto_process=False,
                include_benefits=False,
                benefits_rate=0.05
            )
            return success_response(data=default_settings)
        return success_response(data=PayrollSettings.from_mongo(settings))
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/payroll_settings", response_model=StandardResponse[PayrollSettingsResponse])
async def create_payroll_settings(settings: PayrollSettings):
    """Create or overwrite payroll settings for a store."""
    try:
        settings_collection = get_collection("payroll_settings")
        settings_dict = to_mongo_dict(settings)
        
        # Ensure all fields are present with defaults
        complete_settings = PayrollSettings(**settings.model_dump())
        settings_dict = to_mongo_dict(complete_settings)
        
        # Delete existing settings for the same store to enforce one-per-store
        await settings_collection.delete_many({"store_id": settings.store_id})
        
        result = await settings_collection.insert_one(settings_dict)
        new_settings = await settings_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=PayrollSettings.from_mongo(new_settings),
            message="Payroll settings created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/payroll_settings/{settings_id}", response_model=StandardResponse[PayrollSettingsResponse])
async def update_payroll_settings(settings_id: str, settings: PayrollSettings):
    """Update existing payroll settings by ID."""
    try:
        settings_collection = get_collection("payroll_settings")
        
        # Ensure we have all fields by merging with existing settings
        existing_settings = await settings_collection.find_one({"_id": ObjectId(settings_id)})
        if existing_settings:
            existing_obj = PayrollSettings.from_mongo(existing_settings)
            # Update only the fields that are provided
            update_data = settings.model_dump(exclude_unset=True)
            updated_settings = existing_obj.model_copy(update=update_data)
        else:
            updated_settings = settings
            
        settings_dict = to_mongo_update_dict(updated_settings, exclude_unset=False)
        
        result = await settings_collection.update_one(
            {"_id": ObjectId(settings_id)}, {"$set": settings_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="Payroll settings not found", code=404)
        
        updated_settings_doc = await settings_collection.find_one({"_id": ObjectId(settings_id)})
        return success_response(
            data=PayrollSettings.from_mongo(updated_settings_doc),
            message="Payroll settings updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format for payroll settings", code=400)

        
# Update this helper function in app/routes/hr.py
async def get_or_create_payroll_settings(store_id: str) -> PayrollSettings:
    """Get payroll settings for a store, create default if not exists."""
    payroll_settings_collection = get_collection("payroll_settings")
    
    settings_doc = await payroll_settings_collection.find_one({"store_id": store_id})
    if settings_doc:
        return PayrollSettings.from_mongo(settings_doc)
    
    # Try default settings
    settings_doc = await payroll_settings_collection.find_one({"store_id": "default"})
    if settings_doc:
        return PayrollSettings.from_mongo(settings_doc)
    
    # Create default settings with ALL new fields
    default_settings = PayrollSettings(
        store_id="default",
        default_payment_cycle="bi-weekly",
        tax_rate=0.20,
        overtime_multiplier=1.5,
        overtime_threshold=40,
        pay_day=15,
        auto_process=False,
        include_benefits=False,
        benefits_rate=0.05
    )
    settings_dict = to_mongo_dict(default_settings)
    await payroll_settings_collection.insert_one(settings_dict)
    return default_settings
    
# -----------------
# Timesheets management endpoint
# -----------------
@router.get("/timesheets", response_model=StandardResponse[List[TimesheetResponse]])
async def get_timesheets(employee_id: Optional[str] = Query(None)):
    """Placeholder for fetching calculated timesheet summaries."""
    return success_response(data=[])

# -----------------
# Utility endpoints
# -----------------
@router.get("/health")
async def hr_health_check():
    """Health check for the HR module."""
    return success_response(data={"status": "healthy", "module": "hr"})

# Legacy endpoint for timesheet entries
@router.get("/timesheets_legacy", response_model=StandardResponse[List[TimesheetEntryResponse]])
async def get_timesheets_legacy():
    """Legacy endpoint for simple timesheet entries compatibility."""
    return await get_timesheet_entries()