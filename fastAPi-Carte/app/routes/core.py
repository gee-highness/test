# app/routes/core.py - COMPLETELY UPDATED
from fastapi import APIRouter, HTTPException, Depends, Query, status, Body
from typing import List, Optional, Dict, Any
from app.database import get_collection
from app.models.core import (
    Food, Order, Category, Customer, Table, Store, PurchaseOrder, GoodsReceipt, 
    Reservation, Tenant, Domain, Site, PaymentMethod, Tax, Payment, Brand, ContactMessage, User, Report, PasswordReset, Job, FailedJob, PaymentAttempt
)
from app.models.inventory import InventoryProduct
from app.models.response import (
    StandardResponse, FoodResponse, OrderResponse, CategoryResponse, CustomerResponse, 
    TableResponse, StoreResponse, PurchaseOrderResponse, 
    GoodsReceiptResponse, ReservationResponse,
    InventoryProductResponse, TenantResponse, DomainResponse, 
    SiteResponse, PaymentMethodResponse, TaxResponse, PaymentResponse, 
    BrandResponse, ContactMessageResponse, UserResponse, ReportResponse, PasswordResetResponse, PaymentAttemptResponse, JobResponse, FailedJobResponse
)
from app.utils.response_helpers import success_response, error_response, handle_http_exception, handle_generic_exception
from app.utils.mongo_helpers import to_mongo_dict, to_mongo_update_dict
from bson import ObjectId
from datetime import datetime
import math
import asyncio  # ADD THIS IMPORT

# Add this after the imports section, before the router = APIRouter(...) line

# Counter collection for atomic order number generation
async def get_next_order_number(store_id: str) -> int:
    """Get next sequential order number for a store"""
    counters_collection = get_collection("order_counters")
    
    # Find and increment counter atomically
    result = await counters_collection.find_one_and_update(
        {"store_id": store_id},
        {"$inc": {"current_number": 1}},
        upsert=True,
        return_document=True
    )
    
    if result and "current_number" in result:
        return result["current_number"]
    
    # First order for this store
    await counters_collection.update_one(
        {"store_id": store_id},
        {"$set": {"current_number": 1}},
        upsert=True
    )
    return 1

router = APIRouter(prefix="/api", tags=["core"])

# --- Generic CRUD Helper Functions ---

async def _create_item(collection_name: str, item_model, response_model):
    """Generic function to create a new item with proper response handling"""
    try:
        collection = get_collection(collection_name)
        item_dict = to_mongo_dict(item_model)
        result = await collection.insert_one(item_dict)
        new_item = await collection.find_one({"_id": result.inserted_id})
        
        # Handle different model types with to_response_dict method
        if hasattr(item_model, 'to_response_dict'):
            item_instance = item_model.__class__.from_mongo(new_item)
            response_data = item_instance.to_response_dict()
        else:
            response_data = item_model.from_mongo(new_item)
            
        return success_response(
            data=response_data,
            message=f"{collection_name[:-1].capitalize()} created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

async def _get_all_items(collection_name: str, item_model, query: dict = None):
    """Generic function to retrieve a list of items with proper response handling"""
    try:
        collection = get_collection(collection_name)
        items_data = await collection.find(query or {})
        items = []
        for item in items_data:
            # Handle models with to_response_dict method
            item_instance = item_model.from_mongo(item)
            if hasattr(item_instance, 'to_response_dict'):
                items.append(item_instance.to_response_dict())
            else:
                items.append(item_instance)
        return success_response(data=items)
    except Exception as e:
        return handle_generic_exception(e)

async def _get_item_by_id(collection_name: str, item_id: str, item_model):
    """Generic function to retrieve a single item by ID with proper response handling"""
    try:
        collection = get_collection(collection_name)
        item = await collection.find_one({"_id": ObjectId(item_id)})
    except Exception:
        return error_response(message=f"Invalid ID format for {collection_name}", code=400)
        
    if item:
        # Handle models with to_response_dict method
        item_instance = item_model.from_mongo(item)
        if hasattr(item_instance, 'to_response_dict'):
            return success_response(data=item_instance.to_response_dict())
        else:
            return success_response(data=item_instance)
    return error_response(message=f"{collection_name[:-1].capitalize()} not found", code=404)

async def _update_item(collection_name: str, item_id: str, item_model, response_model):
    """Generic function to update an item with proper response handling"""
    try:
        collection = get_collection(collection_name)
        item_dict = to_mongo_update_dict(item_model, exclude_unset=True)
        
        result = await collection.update_one(
            {"_id": ObjectId(item_id)}, {"$set": item_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message=f"{collection_name[:-1].capitalize()} not found", code=404)
            
        updated_item = await collection.find_one({"_id": ObjectId(item_id)})
        
        # Handle models with to_response_dict method
        item_instance = item_model.__class__.from_mongo(updated_item)
        if hasattr(item_instance, 'to_response_dict'):
            response_data = item_instance.to_response_dict()
        else:
            response_data = item_instance
            
        return success_response(
            data=response_data,
            message=f"{collection_name[:-1].capitalize()} updated successfully"
        )
    except Exception as e:
        return handle_generic_exception(e)

async def _delete_item(collection_name: str, item_id: str):
    """Generic function to delete an item."""
    try:
        collection = get_collection(collection_name)
        result = await collection.delete_one({"_id": ObjectId(item_id)})
        if result.deleted_count == 0:
            return error_response(message=f"{collection_name[:-1].capitalize()} not found", code=404)
        return success_response(
            data=None,
            message=f"{collection_name[:-1].capitalize()} deleted successfully"
        )
    except Exception as e:
        return handle_generic_exception(e)

# --------------------------
# --- Food Endpoints ---
# --------------------------
@router.get("/foods", response_model=StandardResponse[List[FoodResponse]])
async def get_foods(store_id: Optional[str] = Query(None)):
    return await _get_all_items("foods", Food, {"store_id": store_id} if store_id else {})

@router.get("/foods/{food_id}", response_model=StandardResponse[FoodResponse])
async def get_food(food_id: str):
    return await _get_item_by_id("foods", food_id, Food)

@router.post("/foods", response_model=StandardResponse[FoodResponse])
async def create_food(food: Food):
    return await _create_item("foods", food, FoodResponse)

@router.put("/foods/{food_id}", response_model=StandardResponse[FoodResponse])
async def update_food(food_id: str, food: Food):
    return await _update_item("foods", food_id, food, FoodResponse)

@router.delete("/foods/{food_id}", response_model=StandardResponse[dict])
async def delete_food(food_id: str):
    return await _delete_item("foods", food_id)

# --------------------------
# --- Orders Endpoints ---
# --------------------------
# --------------------------
# --- Orders Endpoints ---
# --------------------------


# Payment Attempts Endpoints
@router.post("/payment_attempts", response_model=StandardResponse[PaymentAttemptResponse])
async def create_payment_attempt(attempt: PaymentAttempt):
    return await _create_item("payment_attempts", attempt, PaymentAttemptResponse)

@router.get("/orders/stats/daily", response_model=StandardResponse[dict])
async def get_daily_order_stats(
    date: str = Query(...),
    store_id: Optional[str] = Query(None)
):
    """Get daily order statistics"""
    try:
        orders_collection = get_collection("orders")
        
        # Parse date
        target_date = datetime.fromisoformat(date.replace('Z', '+00:00')).date()
        start_dt = datetime.combine(target_date, datetime.min.time())
        end_dt = datetime.combine(target_date, datetime.max.time())
        
        # Build query
        query = {
            "created_at": {
                "$gte": start_dt.isoformat(),
                "$lte": end_dt.isoformat()
            }
        }
        if store_id:
            query["store_id"] = store_id
        
        # Get orders
        orders = await orders_collection.find(query).to_list()
        
        # Calculate statistics
        total_orders = len(orders)
        total_revenue = sum(order.get("total_amount", 0) for order in orders)
        
        # Status breakdown
        status_counts = {}
        for order in orders:
            status = order.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Payment method breakdown
        payment_methods = {}
        for order in orders:
            method = order.get("payment_method", "unknown")
            if method:  # Only count if payment_method exists
                payment_methods[method] = payment_methods.get(method, 0) + 1
        
        # Order type breakdown
        order_types = {}
        for order in orders:
            order_type = order.get("order_type", "unknown")
            order_types[order_type] = order_types.get(order_type, 0) + 1
        
        return success_response(data={
            "date": date,
            "total_orders": total_orders,
            "total_revenue": total_revenue,
            "average_order_value": total_revenue / total_orders if total_orders > 0 else 0,
            "status_breakdown": status_counts,
            "payment_method_breakdown": payment_methods,
            "order_type_breakdown": order_types,
            "store_id": store_id
        })
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/payment_attempts/{attempt_id}", response_model=StandardResponse[PaymentAttemptResponse])
async def update_payment_attempt(attempt_id: str, attempt: PaymentAttempt):
    return await _update_item("payment_attempts", attempt_id, attempt, PaymentAttemptResponse)

@router.get("/payment_attempts/order/{order_id}", response_model=StandardResponse[PaymentAttemptResponse])
async def get_payment_attempt_by_order(order_id: str):
    try:
        collection = get_collection("payment_attempts")
        attempt = await collection.find_one({"order_id": order_id})
        if attempt:
            return success_response(data=PaymentAttempt.from_mongo(attempt))
        return error_response(message="Payment attempt not found", code=404)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/orders/{order_id}", response_model=StandardResponse[OrderResponse])
async def get_order(order_id: str):
    """Get a single order with all related data"""
    try:
        orders_collection = get_collection("orders")
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        
        if not order:
            return error_response(message="Order not found", code=404)
        
        # Get related payment attempts
        payment_attempts_collection = get_collection("payment_attempts")
        payment_attempts = await payment_attempts_collection.find({"order_id": order_id}).to_list()
        
        # Get related payments
        payments_collection = get_collection("payments")
        payments = await payments_collection.find({"order_id": order_id}).to_list()
        
        order_instance = Order.from_mongo(order)
        order_dict = order_instance.model_dump()
        
        # Ensure order_number exists
        if "order_number" not in order_dict:
            order_dict["order_number"] = None
            order_dict["display_id"] = f"#{order_dict['id'][-8:]}"
        
        # Add related data
        if payment_attempts:
            order_dict["payment_attempts"] = [
                PaymentAttempt.from_mongo(pa).model_dump() 
                for pa in payment_attempts
            ]
        
        if payments:
            order_dict["payments"] = [
                Payment.from_mongo(p).model_dump() 
                for p in payments
            ]
        
        return success_response(data=order_dict)
    except Exception:
        return error_response(message="Invalid ID format", code=400)

@router.post("/orders", response_model=StandardResponse[OrderResponse])
async def create_order(order: Order):
    """Create a new order with inventory management"""
    try:
        # Set defaults for missing required fields
        if order.subtotal_amount is None:
            order.subtotal_amount = sum(item.price * item.quantity for item in order.items)
        
        if order.tax_amount is None:
            order.tax_amount = order.subtotal_amount * 0.15  # Default 15% tax
        
        if order.discount_amount is None:
            order.discount_amount = 0
            
        if order.total_amount is None:
            order.total_amount = order.subtotal_amount + order.tax_amount - order.discount_amount
            
        # Set default status if not provided
        if not order.status:
            order.status = "new"
            
        # Set default notes if not provided
        if order.notes is None:
            order.notes = ""
            
        orders_collection = get_collection("orders")
        inventory_collection = get_collection("inventory_products")
        
        # ========== NEW: Generate sequential order number ==========
        store_id = order.store_id
        if not store_id:
            # Try to get from the first item or use a default
            # You may want to pass store_id in the request
            store_id = "default"
        
        order_number = await get_next_order_number(store_id)
        # ========== END NEW ==========
        
        # Generate order ID
        order_id = str(ObjectId())
        
        # Update each item with order_id and generate item IDs if missing
        for item in order.items:
            # Set order_id for each item
            item.order_id = order_id
            
            # Generate item ID if not provided
            if not item.id:
                item.id = str(ObjectId())
            
            # Ensure price_at_sale is set (default to price if not)
            if item.price_at_sale is None:
                item.price_at_sale = item.price
        
        # Prepare order data
        order_dict = to_mongo_dict(order)
        order_dict["_id"] = ObjectId(order_id)  # Set the order ID
        order_dict["id"] = order_id  # Also include in the dict
        
        # ========== NEW: Add order number fields ==========
        order_dict["order_number"] = order_number
        order_dict["display_id"] = f"#{order_number}"
        # ========== END NEW ==========
        
        # Set timestamps
        order_dict["created_at"] = datetime.utcnow().isoformat()
        order_dict["updated_at"] = datetime.utcnow().isoformat()
        
        # Check inventory and collect stock warnings (existing code continues...)
        stock_warnings = []
        inventory_updates = []
        
        for item in order.items:
            foods_collection = get_collection("foods")
            food = await foods_collection.find_one({"_id": ObjectId(item.food_id)})
            
            if food and food.get("recipes"):
                for recipe in food["recipes"]:
                    inventory_product = await inventory_collection.find_one(
                        {"_id": ObjectId(recipe["inventory_product_id"])}
                    )
                    if inventory_product:
                        required_quantity = recipe["quantity_used"] * item.quantity
                        current_stock = inventory_product.get("quantity_in_stock", 0)
                        
                        if current_stock < required_quantity:
                            stock_warnings.append({
                                "product_id": recipe["inventory_product_id"],
                                "product_name": inventory_product.get("name", "Unknown"),
                                "required": required_quantity,
                                "available": current_stock,
                                "shortage": required_quantity - current_stock
                            })
                        
                        # Schedule inventory update
                        inventory_updates.append({
                            "product_id": recipe["inventory_product_id"],
                            "quantity_change": -required_quantity
                        })
        
        # Apply inventory updates if no critical shortages
        if not any(warning["shortage"] > 0 for warning in stock_warnings if warning.get("shortage")):
            for update in inventory_updates:
                await inventory_collection.update_one(
                    {"_id": ObjectId(update["product_id"])},
                    {"$inc": {"quantity_in_stock": update["quantity_change"]}}
                )
        else:
            order_dict["status"] = "pending_stock"
        
        # Insert order
        result = await orders_collection.insert_one(order_dict)
        new_order = await orders_collection.find_one({"_id": result.inserted_id})
        order_instance = Order.from_mongo(new_order)
        
        # Add stock warnings to response
        order_data = order_instance.model_dump()
        if stock_warnings:
            order_data["stock_warnings"] = stock_warnings
        
        return success_response(
            data=order_data,
            message=f"Order #{order_number} created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/orders/{order_id}", response_model=StandardResponse[OrderResponse])
async def update_order(
    order_id: str, 
    order_update: Dict[str, Any] = Body(...)
):
    """Update an order with validation"""
    try:
        orders_collection = get_collection("orders")
        
        # Check if order exists
        existing_order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        if not existing_order:
            return error_response(message="Order not found", code=404)
        
        # Validate status transitions
        current_status = existing_order.get("status")
        new_status = order_update.get("status")
        
        if new_status and new_status != current_status:
            valid_transitions = {
                "new": ["preparing", "cancelled"],
                "preparing": ["ready", "served", "cancelled"],
                "ready": ["served", "cancelled"],
                "served": ["paid", "cancelled"],
                "paid": [],
                "cancelled": []
            }
            
            if current_status not in valid_transitions:
                return error_response(
                    message=f"Cannot transition from status '{current_status}'",
                    code=400
                )
            
            if new_status not in valid_transitions.get(current_status, []):
                return error_response(
                    message=f"Invalid status transition from '{current_status}' to '{new_status}'",
                    code=400
                )
        
        # Update order
        update_data = {
            **order_update,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = await orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            return error_response(message="No changes made", code=400)
            
        updated_order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        order_instance = Order.from_mongo(updated_order)
        
        return success_response(
            data=order_instance.model_dump(),
            message="Order updated successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format", code=400)

@router.delete("/orders/{order_id}", response_model=StandardResponse[dict])
async def delete_order(order_id: str, force: bool = Query(False)):
    """Delete an order (with optional force delete)"""
    try:
        orders_collection = get_collection("orders")
        
        # Check if order exists
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return error_response(message="Order not found", code=404)
        
        # Check if order can be deleted
        order_status = order.get("status")
        if not force and order_status not in ["new", "cancelled"]:
            return error_response(
                message=f"Cannot delete order with status '{order_status}'. Use force=true to override.",
                code=400
            )
        
        # Delete related payment attempts
        payment_attempts_collection = get_collection("payment_attempts")
        await payment_attempts_collection.delete_many({"order_id": order_id})
        
        # Delete the order
        result = await orders_collection.delete_one({"_id": ObjectId(order_id)})
        
        if result.deleted_count == 0:
            return error_response(message="Order deletion failed", code=500)
        
        return success_response(
            data=None,
            message="Order deleted successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format", code=400)

@router.post("/orders/{order_id}/process_payment", response_model=StandardResponse[dict])
async def process_order_payment(
    order_id: str,
    payment_data: Dict[str, Any] = Body(...)
):
    """Process payment for an order"""
    try:
        orders_collection = get_collection("orders")
        payment_attempts_collection = get_collection("payment_attempts")
        payments_collection = get_collection("payments")
        
        # Get order
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return error_response(message="Order not found", code=404)
        
        # Check if order is ready for payment
        if order.get("status") not in ["served", "ready"]:
            return error_response(
                message=f"Order must be 'served' or 'ready' for payment. Current status: {order.get('status')}",
                code=400
            )
        
        # Create payment attempt
        payment_attempt = PaymentAttempt(
            order_id=order_id,
            payment_gateway=payment_data.get("payment_gateway", "halo"),
            amount=order.get("total_amount", 0),
            reference=f"PAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            status="pending",
            payment_data=payment_data,
            created_at=datetime.utcnow().isoformat()
        )
        
        attempt_dict = to_mongo_dict(payment_attempt)
        attempt_result = await payment_attempts_collection.insert_one(attempt_dict)
        
        # Simulate payment processing
        await asyncio.sleep(1)  # Use asyncio.sleep instead of sleep
        
        # Update payment attempt status
        is_successful = payment_data.get("simulate_success", True)
        if is_successful:
            # Create payment record
            payment = Payment(
                order_id=order_id,
                payment_method_id=payment_data.get("payment_method_id", ""),
                amount=order.get("total_amount", 0),
                payment_date=datetime.utcnow().isoformat(),
                transaction_id=payment_data.get("transaction_id", f"TXN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"),
                status="completed"
            )
            
            payment_dict = to_mongo_dict(payment)
            await payments_collection.insert_one(payment_dict)
            
            # Update order
            await orders_collection.update_one(
                {"_id": ObjectId(order_id)},
                {
                    "$set": {
                        "status": "paid",
                        "payment_status": "paid",
                        "payment_method": payment_data.get("payment_method"),
                        "updated_at": datetime.utcnow().isoformat()
                    }
                }
            )
            
            # Update payment attempt
            await payment_attempts_collection.update_one(
                {"_id": attempt_result.inserted_id},
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow().isoformat()
                    }
                }
            )
            
            return success_response(
                data={"payment_id": str(payment_dict["_id"])},
                message="Payment processed successfully"
            )
        else:
            # Payment failed
            await payment_attempts_collection.update_one(
                {"_id": attempt_result.inserted_id},
                {
                    "$set": {
                        "status": "failed",
                        "cancelled_at": datetime.utcnow().isoformat(),
                        "cancellation_reason": payment_data.get("error_message", "Payment failed")
                    }
                }
            )
            
            return error_response(
                message="Payment processing failed",
                code=400,
                details={"payment_attempt_id": str(attempt_result.inserted_id)}
            )
            
    except Exception as e:
        return handle_generic_exception(e)


@router.get("/orders/{order_id}/items", response_model=StandardResponse[List[dict]])
async def get_order_items(order_id: str):
    """Get all items for a specific order"""
    try:
        orders_collection = get_collection("orders")
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        
        if not order:
            return error_response(message="Order not found", code=404)
        
        return success_response(data=order.get("items", []))
    except Exception:
        return error_response(message="Invalid ID format", code=400)

@router.post("/orders/{order_id}/cancel", response_model=StandardResponse[OrderResponse])
async def cancel_order(
    order_id: str,
    reason: Optional[str] = Body(None)
):
    """Cancel an order"""
    try:
        orders_collection = get_collection("orders")
        
        # Check if order exists
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return error_response(message="Order not found", code=404)
        
        # Check if order can be cancelled
        current_status = order.get("status")
        if current_status in ["paid", "completed"]:
            return error_response(
                message=f"Cannot cancel order with status '{current_status}'",
                code=400
            )
        
        # Update order status
        result = await orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {
                "$set": {
                    "status": "cancelled",
                    "updated_at": datetime.utcnow().isoformat(),
                    "cancellation_reason": reason
                }
            }
        )
        
        if result.modified_count == 0:
            return error_response(message="Order cancellation failed", code=500)
        
        # Restore inventory if needed
        if current_status not in ["new", "cancelled"]:
            await restore_order_inventory(order_id)
        
        updated_order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        order_instance = Order.from_mongo(updated_order)
        
        return success_response(
            data=order_instance.model_dump(),
            message="Order cancelled successfully"
        )
    except Exception:
        return error_response(message="Invalid ID format", code=400)

# --------------------------
# --- Orders Endpoints ---
# --------------------------
@router.get("/orders", response_model=StandardResponse[List[OrderResponse]])
async def get_orders(
    store_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None)
):
    """Get orders - custom implementation to fix datetime issue"""
    try:
        collection = get_collection("orders")
        
        # Build query
        query = {}
        if store_id:
            query["store_id"] = store_id
        if status:
            query["status"] = status
            
        items_data = await collection.find(query)
        items = []
        for item in items_data:
            # Convert MongoDB document to dictionary
            item_dict = dict(item)
            item_dict["id"] = str(item_dict.pop("_id"))
            
            # Convert datetime fields to ISO strings
            for field in ['created_at', 'updated_at']:
                if field in item_dict and item_dict[field]:
                    if isinstance(item_dict[field], datetime):
                        item_dict[field] = item_dict[field].isoformat()
            
            # Ensure order_number exists (for older orders without it)
            if "order_number" not in item_dict:
                # Fallback to using last 8 chars of ID
                item_dict["order_number"] = None
                item_dict["display_id"] = f"#{item_dict['id'][-8:]}"
            
            items.append(item_dict)
        
        return success_response(data=items)
    except Exception as e:
        return handle_generic_exception(e)

# Helper function to restore inventory
async def restore_order_inventory(order_id: str):
    """Restore inventory quantities for a cancelled order"""
    try:
        orders_collection = get_collection("orders")
        inventory_collection = get_collection("inventory_products")
        
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return
        
        # Restore inventory for each item
        for item in order.get("items", []):
            foods_collection = get_collection("foods")
            food = await foods_collection.find_one({"_id": ObjectId(item["food_id"])})
            
            if food and food.get("recipes"):
                for recipe in food["recipes"]:
                    await inventory_collection.update_one(
                        {"_id": ObjectId(recipe["inventory_product_id"])},
                        {"$inc": {"quantity_in_stock": recipe["quantity_used"] * item["quantity"]}}
                    )
    except Exception as e:
        print(f"Error restoring inventory for order {order_id}: {e}")

@router.options("/orders")
async def orders_options():
    """Handle OPTIONS requests for orders endpoint (CORS preflight)"""
    return {
        "allow": "POST, GET, OPTIONS",
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST, GET, OPTIONS",
        "access-control-allow-headers": "*"
    }

@router.options("/orders/{order_id}")
async def orders_id_options():
    """Handle OPTIONS requests for orders/{id} endpoint (CORS preflight)"""
    return {
        "allow": "GET, PUT, DELETE, OPTIONS",
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, PUT, DELETE, OPTIONS",
        "access-control-allow-headers": "*"
    }

@router.post("/orders/{order_id}/resolve_stock", response_model=StandardResponse[dict])
async def resolve_pending_stock(order_id: str):
    """Attempt to resolve a pending_stock order by checking inventory again and fulfilling if possible"""
    try:
        orders_collection = get_collection("orders")
        inventory_collection = get_collection("inventory_products")
        foods_collection = get_collection("foods")
        
        # Validate ObjectId format
        if not ObjectId.is_valid(order_id):
            return error_response(message="Invalid order ID format", code=400)
        
        # Get the order
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return error_response(message="Order not found", code=404)
        
        # Check if order is pending_stock
        if order.get("status") != "pending_stock":
            return error_response(
                message=f"Order status is '{order.get('status')}', not 'pending_stock'",
                code=400
            )
        
        # Convert order dict to Order model
        order_obj = Order.from_mongo(order)
        
        # Check inventory for each item
        stock_warnings = []
        inventory_updates = []
        all_items_available = True
        
        for item in order_obj.items:
            # Get the food item to check its recipe
            food = await foods_collection.find_one({"_id": ObjectId(item.food_id)})
            
            if not food:
                stock_warnings.append({
                    "food_id": item.food_id,
                    "food_name": item.name,
                    "error": "Food item not found"
                })
                all_items_available = False
                continue
            
            # Check if food has recipes (ingredients)
            recipes = food.get("recipes", [])
            if not recipes:
                # No ingredients - always available
                continue
            
            # Check each ingredient
            for recipe in recipes:
                inventory_product = await inventory_collection.find_one(
                    {"_id": ObjectId(recipe["inventory_product_id"])}
                )
                
                if not inventory_product:
                    stock_warnings.append({
                        "product_id": recipe["inventory_product_id"],
                        "product_name": "Unknown",
                        "required": recipe["quantity_used"] * item.quantity,
                        "available": 0,
                        "shortage": recipe["quantity_used"] * item.quantity,
                        "food_name": item.name
                    })
                    all_items_available = False
                    continue
                
                required_quantity = recipe["quantity_used"] * item.quantity
                current_stock = inventory_product.get("quantity_in_stock", 0)
                
                if current_stock < required_quantity:
                    stock_warnings.append({
                        "product_id": recipe["inventory_product_id"],
                        "product_name": inventory_product.get("name", "Unknown"),
                        "required": required_quantity,
                        "available": current_stock,
                        "shortage": required_quantity - current_stock,
                        "food_name": item.name
                    })
                    all_items_available = False
                
                # Track inventory updates (even if currently insufficient)
                inventory_updates.append({
                    "product_id": recipe["inventory_product_id"],
                    "quantity_change": -required_quantity
                })
        
        # If all items are available, fulfill the order
        if all_items_available:
            # Update inventory quantities
            for update in inventory_updates:
                await inventory_collection.update_one(
                    {"_id": ObjectId(update["product_id"])},
                    {"$inc": {"quantity_in_stock": update["quantity_change"]}}
                )
            
            # Update order status to preparing
            result = await orders_collection.update_one(
                {"_id": ObjectId(order_id)},
                {
                    "$set": {
                        "status": "preparing",
                        "updated_at": datetime.utcnow().isoformat(),
                        "stock_resolved_at": datetime.utcnow().isoformat()
                    }
                }
            )
            
            # Fetch updated order
            updated_order = await orders_collection.find_one({"_id": ObjectId(order_id)})
            
            return success_response(
                data={
                    "order": Order.from_mongo(updated_order).dict(),
                    "message": "Order resolved successfully and moved to preparing",
                    "stock_deducted": True
                }
            )
        else:
            # Still insufficient stock
            return success_response(
                data={
                    "order_id": order_id,
                    "status": "still_pending",
                    "stock_warnings": stock_warnings,
                    "message": f"Cannot fulfill order. {len(stock_warnings)} ingredient(s) have insufficient stock.",
                    "stock_deducted": False
                }
            )
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return error_response(message=str(e), code=500)

# --------------------------
# --- Categories Endpoints ---
# --------------------------
@router.get("/categories", response_model=StandardResponse[List[CategoryResponse]])
async def get_categories(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("categories", Category, query)

@router.get("/categories/{category_id}", response_model=StandardResponse[CategoryResponse])
async def get_category(category_id: str):
    return await _get_item_by_id("categories", category_id, Category)

@router.post("/categories", response_model=StandardResponse[CategoryResponse])
async def create_category(category: Category):
    return await _create_item("categories", category, CategoryResponse)

@router.put("/categories/{category_id}", response_model=StandardResponse[CategoryResponse])
async def update_category(category_id: str, category: Category):
    return await _update_item("categories", category_id, category, CategoryResponse)

@router.delete("/categories/{category_id}", response_model=StandardResponse[dict])
async def delete_category(category_id: str):
    return await _delete_item("categories", category_id)

# --------------------------
# --- Customers Endpoints ---
# --------------------------
@router.get("/customers", response_model=StandardResponse[List[CustomerResponse]])
async def get_customers(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("customers", Customer, query)

@router.get("/customers/{customer_id}", response_model=StandardResponse[CustomerResponse])
async def get_customer(customer_id: str):
    return await _get_item_by_id("customers", customer_id, Customer)

@router.post("/customers", response_model=StandardResponse[CustomerResponse])
async def create_customer(customer: Customer):
    return await _create_item("customers", customer, CustomerResponse)

@router.put("/customers/{customer_id}", response_model=StandardResponse[CustomerResponse])
async def update_customer(customer_id: str, customer: Customer):
    return await _update_item("customers", customer_id, customer, CustomerResponse)

@router.delete("/customers/{customer_id}", response_model=StandardResponse[dict])
async def delete_customer(customer_id: str):
    return await _delete_item("customers", customer_id)

# --------------------------
# --- Tables Endpoints ---
# --------------------------
@router.get("/tables", response_model=StandardResponse[List[TableResponse]])
async def get_tables(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("tables", Table, query)

@router.get("/tables/{table_id}", response_model=StandardResponse[TableResponse])
async def get_table(table_id: str):
    return await _get_item_by_id("tables", table_id, Table)

@router.post("/tables", response_model=StandardResponse[TableResponse])
async def create_table(table: Table):
    return await _create_item("tables", table, TableResponse)

@router.put("/tables/{table_id}", response_model=StandardResponse[TableResponse])
async def update_table(table_id: str, table: Table):
    return await _update_item("tables", table_id, table, TableResponse)

@router.delete("/tables/{table_id}", response_model=StandardResponse[dict])
async def delete_table(table_id: str):
    return await _delete_item("tables", table_id)

# --------------------------
# --- Stores Endpoints ---
# --------------------------
@router.get("/stores", response_model=StandardResponse[List[StoreResponse]])
async def get_stores():
    return await _get_all_items("stores", Store)

@router.get("/stores/{store_id}", response_model=StandardResponse[StoreResponse])
async def get_store(store_id: str):
    return await _get_item_by_id("stores", store_id, Store)

@router.post("/stores", response_model=StandardResponse[StoreResponse])
async def create_store(store: Store):
    return await _create_item("stores", store, StoreResponse)

@router.put("/stores/{store_id}", response_model=StandardResponse[StoreResponse])
async def update_store(store_id: str, store: Store):
    return await _update_item("stores", store_id, store, StoreResponse)

@router.delete("/stores/{store_id}", response_model=StandardResponse[dict])
async def delete_store(store_id: str):
    return await _delete_item("stores", store_id)

# --------------------------
# --- Purchase Orders Endpoints ---
# --------------------------
@router.get("/purchase_orders", response_model=StandardResponse[List[PurchaseOrderResponse]])
async def get_purchase_orders():
    return await _get_all_items("purchase_orders", PurchaseOrder)

@router.get("/purchase_orders/{po_id}", response_model=StandardResponse[PurchaseOrderResponse])
async def get_purchase_order(po_id: str):
    return await _get_item_by_id("purchase_orders", po_id, PurchaseOrder)

@router.post("/purchase_orders", response_model=StandardResponse[PurchaseOrderResponse])
async def create_purchase_order(po: PurchaseOrder):
    return await _create_item("purchase_orders", po, PurchaseOrderResponse)

@router.put("/purchase_orders/{po_id}", response_model=StandardResponse[PurchaseOrderResponse])
async def update_purchase_order(po_id: str, po: PurchaseOrder):
    return await _update_item("purchase_orders", po_id, po, PurchaseOrderResponse)

@router.delete("/purchase_orders/{po_id}", response_model=StandardResponse[dict])
async def delete_purchase_order(po_id: str):
    return await _delete_item("purchase_orders", po_id)

# --------------------------
# --- Goods Receipts Endpoints ---
# --------------------------
@router.get("/goods_receipts", response_model=StandardResponse[List[GoodsReceiptResponse]])
async def get_goods_receipts():
    return await _get_all_items("goods_receipts", GoodsReceipt)

@router.get("/goods_receipts/{gr_id}", response_model=StandardResponse[GoodsReceiptResponse])
async def get_goods_receipt(gr_id: str):
    return await _get_item_by_id("goods_receipts", gr_id, GoodsReceipt)

@router.post("/goods_receipts", response_model=StandardResponse[GoodsReceiptResponse])
async def create_goods_receipt(gr: GoodsReceipt):
    try:
        gr_collection = get_collection("goods_receipts")
        products_collection = get_collection("inventory_products")

        # Update inventory quantities based on received items
        for item in gr.items:
            if item.condition == 'good':
                product = await products_collection.find_one({"_id": ObjectId(item.inventory_product_id)})
                if not product:
                    return error_response(message=f"Inventory Product with id {item.inventory_product_id} not found.", code=404)
                
                current_stock = product.get("quantity_in_stock", 0)
                new_stock = current_stock + item.received_quantity
                
                await products_collection.update_one(
                    {"_id": ObjectId(item.inventory_product_id)},
                    {"$set": {"quantity_in_stock": new_stock, "last_restocked_at": datetime.utcnow().isoformat()}}
                )

        # Insert the goods receipt
        gr_dict = to_mongo_dict(gr)
        
        result = await gr_collection.insert_one(gr_dict)
        new_gr = await gr_collection.find_one({"_id": result.inserted_id})
        return success_response(
            data=GoodsReceipt.from_mongo(new_gr),
            message="Goods receipt created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/goods_receipts/{gr_id}", response_model=StandardResponse[GoodsReceiptResponse])
async def update_goods_receipt(gr_id: str, gr: GoodsReceipt):
    return await _update_item("goods_receipts", gr_id, gr, GoodsReceiptResponse)

@router.delete("/goods_receipts/{gr_id}", response_model=StandardResponse[dict])
async def delete_goods_receipt(gr_id: str):
    return await _delete_item("goods_receipts", gr_id)

# --------------------------
# --- Reservations Endpoints ---
# --------------------------
@router.get("/reservations", response_model=StandardResponse[List[ReservationResponse]])
async def get_reservations(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("reservations", Reservation, query)

@router.get("/reservations/{reservation_id}", response_model=StandardResponse[ReservationResponse])
async def get_reservation(reservation_id: str):
    return await _get_item_by_id("reservations", reservation_id, Reservation)

@router.post("/reservations", response_model=StandardResponse[ReservationResponse])
async def create_reservation(reservation: Reservation):
    return await _create_item("reservations", reservation, ReservationResponse)

@router.put("/reservations/{reservation_id}", response_model=StandardResponse[ReservationResponse])
async def update_reservation(reservation_id: str, reservation: Reservation):
    return await _update_item("reservations", reservation_id, reservation, ReservationResponse)

@router.delete("/reservations/{reservation_id}", response_model=StandardResponse[dict])
async def delete_reservation(reservation_id: str):
    return await _delete_item("reservations", reservation_id)

# ----------------------------------------------------
# --- NEW CRUD Endpoints for Missing Core Models ---
# ----------------------------------------------------

# Brands Endpoints
@router.get("/brands", response_model=StandardResponse[List[BrandResponse]])
async def get_brands():
    return await _get_all_items("brands", Brand)

@router.get("/brands/{brand_id}", response_model=StandardResponse[BrandResponse])
async def get_brand(brand_id: str):
    return await _get_item_by_id("brands", brand_id, Brand)

@router.post("/brands", response_model=StandardResponse[BrandResponse])
async def create_brand(brand: Brand):
    return await _create_item("brands", brand, BrandResponse)

@router.put("/brands/{brand_id}", response_model=StandardResponse[BrandResponse])
async def update_brand(brand_id: str, brand: Brand):
    return await _update_item("brands", brand_id, brand, BrandResponse)

@router.delete("/brands/{brand_id}", response_model=StandardResponse[dict])
async def delete_brand(brand_id: str):
    return await _delete_item("brands", brand_id)

# Contact Messages Endpoints
@router.get("/contact_messages", response_model=StandardResponse[List[ContactMessageResponse]])
async def get_contact_messages():
    return await _get_all_items("contact_messages", ContactMessage)

@router.get("/contact_messages/{message_id}", response_model=StandardResponse[ContactMessageResponse])
async def get_contact_message(message_id: str):
    return await _get_item_by_id("contact_messages", message_id, ContactMessage)

@router.post("/contact_messages", response_model=StandardResponse[ContactMessageResponse])
async def create_contact_message(message: ContactMessage):
    return await _create_item("contact_messages", message, ContactMessageResponse)

@router.delete("/contact_messages/{message_id}", response_model=StandardResponse[dict])
async def delete_contact_message(message_id: str):
    return await _delete_item("contact_messages", message_id)

# Domains Endpoints
@router.get("/domains", response_model=StandardResponse[List[DomainResponse]])
async def get_domains(tenant_id: Optional[str] = Query(None)):
    query = {"tenant_id": tenant_id} if tenant_id else {}
    return await _get_all_items("domains", Domain, query)

@router.get("/domains/{domain_id}", response_model=StandardResponse[DomainResponse])
async def get_domain(domain_id: str):
    return await _get_item_by_id("domains", domain_id, Domain)

@router.post("/domains", response_model=StandardResponse[DomainResponse])
async def create_domain(domain: Domain):
    return await _create_item("domains", domain, DomainResponse)

@router.put("/domains/{domain_id}", response_model=StandardResponse[DomainResponse])
async def update_domain(domain_id: str, domain: Domain):
    return await _update_item("domains", domain_id, domain, DomainResponse)

@router.delete("/domains/{domain_id}", response_model=StandardResponse[dict])
async def delete_domain(domain_id: str):
    return await _delete_item("domains", domain_id)

# Payments Endpoints
@router.get("/payments", response_model=StandardResponse[List[PaymentResponse]])
async def get_payments(order_id: Optional[str] = Query(None)):
    query = {"order_id": order_id} if order_id else {}
    return await _get_all_items("payments", Payment, query)

@router.get("/payments/{payment_id}", response_model=StandardResponse[PaymentResponse])
async def get_payment(payment_id: str):
    return await _get_item_by_id("payments", payment_id, Payment)

@router.post("/payments", response_model=StandardResponse[PaymentResponse])
async def create_payment(payment: Payment):
    return await _create_item("payments", payment, PaymentResponse)

@router.put("/payments/{payment_id}", response_model=StandardResponse[PaymentResponse])
async def update_payment(payment_id: str, payment: Payment):
    return await _update_item("payments", payment_id, payment, PaymentResponse)

@router.delete("/payments/{payment_id}", response_model=StandardResponse[dict])
async def delete_payment(payment_id: str):
    return await _delete_item("payments", payment_id)

# Payment Methods Endpoints
@router.get("/payment_methods", response_model=StandardResponse[List[PaymentMethodResponse]])
async def get_payment_methods(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("payment_methods", PaymentMethod, query)

@router.get("/payment_methods/{method_id}", response_model=StandardResponse[PaymentMethodResponse])
async def get_payment_method(method_id: str):
    return await _get_item_by_id("payment_methods", method_id, PaymentMethod)

@router.post("/payment_methods", response_model=StandardResponse[PaymentMethodResponse])
async def create_payment_method(method: PaymentMethod):
    return await _create_item("payment_methods", method, PaymentMethodResponse)

@router.put("/payment_methods/{method_id}", response_model=StandardResponse[PaymentMethodResponse])
async def update_payment_method(method_id: str, method: PaymentMethod):
    return await _update_item("payment_methods", method_id, method, PaymentMethodResponse)

@router.delete("/payment_methods/{method_id}", response_model=StandardResponse[dict])
async def delete_payment_method(method_id: str):
    return await _delete_item("payment_methods", method_id)

# Sites Endpoints
@router.get("/sites", response_model=StandardResponse[List[SiteResponse]])
async def get_sites(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("sites", Site, query)

@router.get("/sites/{site_id}", response_model=StandardResponse[SiteResponse])
async def get_site(site_id: str):
    return await _get_item_by_id("sites", site_id, Site)

@router.post("/sites", response_model=StandardResponse[SiteResponse])
async def create_site(site: Site):
    return await _create_item("sites", site, SiteResponse)

@router.put("/sites/{site_id}", response_model=StandardResponse[SiteResponse])
async def update_site(site_id: str, site: Site):
    return await _update_item("sites", site_id, site, SiteResponse)

@router.delete("/sites/{site_id}", response_model=StandardResponse[dict])
async def delete_site(site_id: str):
    return await _delete_item("sites", site_id)

# Taxes Endpoints
@router.get("/taxes", response_model=StandardResponse[List[TaxResponse]])
async def get_taxes(store_id: Optional[str] = Query(None)):
    query = {"store_id": store_id} if store_id else {}
    return await _get_all_items("taxes", Tax, query)

@router.get("/taxes/{tax_id}", response_model=StandardResponse[TaxResponse])
async def get_tax(tax_id: str):
    return await _get_item_by_id("taxes", tax_id, Tax)

@router.post("/taxes", response_model=StandardResponse[TaxResponse])
async def create_tax(tax: Tax):
    return await _create_item("taxes", tax, TaxResponse)

@router.put("/taxes/{tax_id}", response_model=StandardResponse[TaxResponse])
async def update_tax(tax_id: str, tax: Tax):
    return await _update_item("taxes", tax_id, tax, TaxResponse)

@router.delete("/taxes/{tax_id}", response_model=StandardResponse[dict])
async def delete_tax(tax_id: str):
    return await _delete_item("taxes", tax_id)

# ==================== TENANT ENDPOINTS ====================

@router.get("/tenants", response_model=StandardResponse[List[TenantResponse]])
async def get_tenants():
    """Get all tenants (authenticated)"""
    return await _get_all_items("tenants", Tenant)

@router.get("/tenants/{tenant_id}", response_model=StandardResponse[TenantResponse])
async def get_tenant(tenant_id: str):
    """Get a specific tenant by ID (authenticated)"""
    try:
        collection = get_collection("tenants")
        tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        
        if not tenant:
            return error_response(message="Tenant not found", code=404)
            
        response_data = {
            "id": str(tenant["_id"]),
            "name": tenant.get("name", ""),
            "email": tenant.get("email", ""),
            "phone": tenant.get("phone"),
            "address": tenant.get("address"),
            "customer_page_settings": tenant.get("customer_page_settings", {}),
            "created_at": tenant.get("created_at"),
            "updated_at": tenant.get("updated_at")
        }
        
        return success_response(data=TenantResponse(**response_data))
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/tenants/domain/{domain}", response_model=StandardResponse[TenantResponse])
async def get_tenant_by_domain(domain: str):
    """Get tenant by domain (public endpoint)"""
    try:
        # First find the domain record
        domains_collection = get_collection("domains")
        domain_record = await domains_collection.find_one({"domain": domain, "is_primary": True})
        
        if not domain_record:
            return error_response(message="Domain not found", code=404)
            
        # Then get the tenant
        tenants_collection = get_collection("tenants")
        tenant = await tenants_collection.find_one({"_id": ObjectId(domain_record["tenant_id"])})
        
        if not tenant:
            return error_response(message="Tenant not found", code=404)
            
        response_data = {
            "id": str(tenant["_id"]),
            "name": tenant.get("name", ""),
            "email": tenant.get("email", ""),
            "phone": tenant.get("phone"),
            "address": tenant.get("address"),
            "customer_page_settings": tenant.get("customer_page_settings", {}),
            "created_at": tenant.get("created_at"),
            "updated_at": tenant.get("updated_at")
        }
        
        return success_response(data=TenantResponse(**response_data))
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/tenants/{tenant_id}/public", response_model=StandardResponse[TenantResponse])
async def get_tenant_public(tenant_id: str):
    """Get tenant public info (no auth required)"""
    try:
        collection = get_collection("tenants")
        tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        
        if not tenant:
            return error_response(message="Tenant not found", code=404)
            
        response_data = {
            "id": str(tenant["_id"]),
            "name": tenant.get("name", ""),
            "email": tenant.get("email", ""),
            "phone": tenant.get("phone"),
            "address": tenant.get("address"),
            "customer_page_settings": tenant.get("customer_page_settings", {}),
            "created_at": tenant.get("created_at"),
            "updated_at": tenant.get("updated_at")
        }
        
        return success_response(data=TenantResponse(**response_data))
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/tenants", response_model=StandardResponse[TenantResponse])
async def create_tenant(tenant: Tenant):
    """Create a new tenant"""
    return await _create_item("tenants", tenant, TenantResponse)

@router.put("/tenants/{tenant_id}", response_model=StandardResponse[TenantResponse])
async def update_tenant(tenant_id: str, tenant_update: dict):
    """Update tenant information"""
    try:
        collection = get_collection("tenants")
        
        # Validate tenant exists
        existing_tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        if not existing_tenant:
            return error_response(message="Tenant not found", code=404)
        
        # Prepare update data
        update_data = {}
        for key, value in tenant_update.items():
            if value is not None:
                update_data[key] = value
        
        # Always set updated_at
        update_data["updated_at"] = datetime.utcnow().isoformat()
        
        result = await collection.update_one(
            {"_id": ObjectId(tenant_id)},
            {"$set": update_data}
        )
        
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="No changes made", code=400)
            
        # Return updated tenant
        updated_tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        
        response_data = {
            "id": str(updated_tenant["_id"]),
            "name": updated_tenant.get("name", ""),
            "email": updated_tenant.get("email", ""),
            "phone": updated_tenant.get("phone"),
            "address": updated_tenant.get("address"),
            "customer_page_settings": updated_tenant.get("customer_page_settings", {}),
            "created_at": updated_tenant.get("created_at"),
            "updated_at": updated_tenant.get("updated_at")
        }
        
        return success_response(
            data=TenantResponse(**response_data),
            message="Tenant updated successfully"
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/tenants/{tenant_id}/settings", response_model=StandardResponse[TenantResponse])
async def get_tenant_settings(tenant_id: str):
    """Get tenant settings including customer page customization"""
    try:
        collection = get_collection("tenants")
        tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        
        if not tenant:
            return error_response(message="Tenant not found", code=404)
            
        response_data = {
            "id": str(tenant["_id"]),
            "name": tenant.get("name", ""),
            "email": tenant.get("email", ""),
            "phone": tenant.get("phone"),
            "address": tenant.get("address"),
            "customer_page_settings": tenant.get("customer_page_settings", {}),
            "created_at": tenant.get("created_at"),
            "updated_at": tenant.get("updated_at")
        }
        
        return success_response(data=TenantResponse(**response_data))
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/tenants/{tenant_id}/settings", response_model=StandardResponse[TenantResponse])
async def update_tenant_settings(tenant_id: str, settings_update: dict):
    """Update tenant customer page settings"""
    try:
        collection = get_collection("tenants")
        
        # Validate tenant exists
        tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        if not tenant:
            return error_response(message="Tenant not found", code=404)
        
        # Update only the customer_page_settings field
        update_data = {
            "customer_page_settings": settings_update,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        result = await collection.update_one(
            {"_id": ObjectId(tenant_id)},
            {"$set": update_data}
        )
        
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="No changes made", code=400)
            
        # Return updated tenant
        updated_tenant = await collection.find_one({"_id": ObjectId(tenant_id)})
        
        response_data = {
            "id": str(updated_tenant["_id"]),
            "name": updated_tenant.get("name", ""),
            "email": updated_tenant.get("email", ""),
            "phone": updated_tenant.get("phone"),
            "address": updated_tenant.get("address"),
            "customer_page_settings": updated_tenant.get("customer_page_settings", {}),
            "created_at": updated_tenant.get("created_at"),
            "updated_at": updated_tenant.get("updated_at")
        }
        
        return success_response(
            data=TenantResponse(**response_data),
            message="Tenant settings updated successfully"
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.delete("/tenants/{tenant_id}", response_model=StandardResponse[dict])
async def delete_tenant(tenant_id: str):
    """Delete a tenant"""
    return await _delete_item("tenants", tenant_id)

# ----------------------------------------------------
# --- Utility Endpoints (From Original File) ---
# ----------------------------------------------------

# Low stock items endpoint
@router.get("/inventory/low-stock", response_model=StandardResponse[List[InventoryProductResponse]])
async def get_low_stock_items():
    try:
        products_collection = get_collection("inventory_products")
        low_stock_items = []
        products = await products_collection.find()
        for product in products:
            if product.get("quantity_in_stock", 0) <= product.get("reorder_level", 0):
                low_stock_items.append(InventoryProduct.from_mongo(product))
        return success_response(data=low_stock_items)
    except Exception as e:
        return handle_generic_exception(e)

# Pending purchase orders endpoint
@router.get("/purchase_orders/pending", response_model=StandardResponse[List[PurchaseOrderResponse]])
async def get_pending_purchase_orders():
    try:
        po_collection = get_collection("purchase_orders")
        pending_statuses = ['draft', 'pending-approval', 'approved', 'ordered']
        pending_orders = []
        pos = await po_collection.find({"status": {"$in": pending_statuses}})
        for po in pos:
            pending_orders.append(PurchaseOrder.from_mongo(po))
        return success_response(data=pending_orders)
    except Exception as e:
        return handle_generic_exception(e)

# Order items endpoints (for individual order item operations)
@router.get("/order_items/{order_item_id}", response_model=StandardResponse[dict])
async def get_order_item(order_item_id: str):
    try:
        orders_collection = get_collection("orders")
        orders = await orders_collection.find()
        for order in orders:
            for item in order.get("items", []):
                if str(item.get("id")) == order_item_id:
                    return success_response(data=item)
        return error_response(message="Order item not found", code=404)
    except Exception as e:
        return handle_generic_exception(e)

# Store foods endpoints
@router.get("/store_foods", response_model=StandardResponse[List[dict]])
async def get_store_foods(store_id: Optional[str] = Query(None)):
    try:
        foods_collection = get_collection("foods")
        query = {"store_id": store_id} if store_id else {}
        store_foods = []
        foods = await foods_collection.find(query)
        for food in foods:
            store_foods.append({
                "food_id": str(food["_id"]),
                "store_id": food.get("store_id", ""),
                "is_available": food.get("is_available", True)
            })
        return success_response(data=store_foods)
    except Exception as e:
        return handle_generic_exception(e)

# Recipe items endpoints
@router.get("/recipes", response_model=StandardResponse[List[dict]])
async def get_recipes(food_id: Optional[str] = Query(None)):
    try:
        foods_collection = get_collection("foods")
        recipes = []
        foods = await foods_collection.find()
        for food in foods:
            if food.get("recipes"):
                for recipe in food["recipes"]:
                    if not food_id or str(food["_id"]) == food_id:
                        recipes.append({
                            **recipe,
                            "food_id": str(food["_id"]),
                            "id": recipe.get("id", str(food["_id"]) + "_" + recipe.get("inventory_product_id", ""))
                        })
        return success_response(data=recipes)
    except Exception as e:
        return handle_generic_exception(e)

# Health check endpoint for core module
@router.get("/health")
async def health_check():
    return success_response(data={"status": "healthy", "module": "core"})

# --------------------------
# --- Users Endpoints ---
# --------------------------
@router.get("/users", response_model=StandardResponse[List[UserResponse]])
async def get_users():
    """Retrieve all users (without passwords)."""
    try:
        users_collection = get_collection("users")
        users = []
        user_docs = await users_collection.find()
        for user in user_docs:
            # Convert to User model first
            user_model = User.from_mongo(user)
            user_dict = user_model.to_dict()
            user_dict.pop('password', None)  # Remove password
            
            users.append(user_dict)
        
        return success_response(data=users)
    except Exception as e:
        return handle_generic_exception(e)

@router.get("/users/{user_id}", response_model=StandardResponse[UserResponse])
async def get_user(user_id: str):
    """Retrieve a single user by ID (without password)."""
    try:
        users_collection = get_collection("users")
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            # Convert to User model first
            user_model = User.from_mongo(user)
            user_dict = user_model.to_dict()
            user_dict.pop('password', None)  # Remove password
            
            return success_response(data=user_dict)
        return error_response(message="User not found", code=404)
    except Exception:
        return error_response(message="Invalid ID format for user", code=400)

@router.post("/users", response_model=StandardResponse[UserResponse])
async def create_user(user: User):
    """Create a new user."""
    try:
        users_collection = get_collection("users")
        user_dict = to_mongo_dict(user)
        
        result = await users_collection.insert_one(user_dict)
        new_user = await users_collection.find_one({"_id": result.inserted_id})
        
        # Remove password from response
        user_data = User.from_mongo(new_user)
        user_dict = user_data.to_dict()
        user_dict.pop("password", None)
        
        return success_response(
            data=user_dict,
            message="User created successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.put("/users/{user_id}", response_model=StandardResponse[UserResponse])
async def update_user(user_id: str, user: User):
    """Update an existing user."""
    try:
        users_collection = get_collection("users")
        user_dict = to_mongo_update_dict(user, exclude_unset=True)
        
        result = await users_collection.update_one(
            {"_id": ObjectId(user_id)}, {"$set": user_dict}
        )
        if result.modified_count == 0 and result.matched_count == 0:
            return error_response(message="User not found", code=404)
            
        updated_user = await users_collection.find_one({"_id": ObjectId(user_id)})
        
        # Remove password from response
        user_data = User.from_mongo(updated_user)
        user_dict = user_data.to_dict()
        user_dict.pop("password", None)
        
        return success_response(
            data=user_dict,
            message="User updated successfully"
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.delete("/users/{user_id}", response_model=StandardResponse[dict])
async def delete_user(user_id: str):
    """Delete a user."""
    return await _delete_item("users", user_id)

# --------------------------
# --- Password Resets Endpoints ---
# --------------------------
@router.get("/password_resets", response_model=StandardResponse[List[PasswordResetResponse]])
async def get_password_resets():
    return await _get_all_items("password_resets", PasswordReset)

@router.get("/password_resets/{reset_id}", response_model=StandardResponse[PasswordResetResponse])
async def get_password_reset(reset_id: str):
    return await _get_item_by_id("password_resets", reset_id, PasswordReset)

@router.post("/password_resets", response_model=StandardResponse[PasswordResetResponse])
async def create_password_reset(reset: PasswordReset):
    return await _create_item("password_resets", reset, PasswordResetResponse)

@router.delete("/password_resets/{reset_id}", response_model=StandardResponse[dict])
async def delete_password_reset(reset_id: str):
    return await _delete_item("password_resets", reset_id)

# --------------------------
# --- Jobs Endpoints ---
# --------------------------
@router.get("/jobs", response_model=StandardResponse[List[JobResponse]])
async def get_jobs():
    return await _get_all_items("jobs", Job)

@router.get("/jobs/{job_id}", response_model=StandardResponse[JobResponse])
async def get_job(job_id: str):
    return await _get_item_by_id("jobs", job_id, Job)

@router.post("/jobs", response_model=StandardResponse[JobResponse])
async def create_job(job: Job):
    return await _create_item("jobs", job, JobResponse)

@router.delete("/jobs/{job_id}", response_model=StandardResponse[dict])
async def delete_job(job_id: str):
    return await _delete_item("jobs", job_id)

# --------------------------
# --- Failed Jobs Endpoints ---
# --------------------------
@router.get("/failed_jobs", response_model=StandardResponse[List[FailedJobResponse]])
async def get_failed_jobs():
    return await _get_all_items("failed_jobs", FailedJob)

@router.get("/failed_jobs/{job_id}", response_model=StandardResponse[FailedJobResponse])
async def get_failed_job(job_id: str):
    return await _get_item_by_id("failed_jobs", job_id, FailedJob)

@router.post("/failed_jobs", response_model=StandardResponse[FailedJobResponse])
async def create_failed_job(job: FailedJob):
    return await _create_item("failed_jobs", job, FailedJobResponse)

@router.delete("/failed_jobs/{job_id}", response_model=StandardResponse[dict])
async def delete_failed_job(job_id: str):
    return await _delete_item("failed_jobs", job_id)


# Add to core.py - Dependency checking endpoint
@router.get("/check_dependencies/{entity_name}/{entity_id}")
async def check_dependencies(entity_name: str, entity_id: str):
    """Check if an entity has dependencies before deletion"""
    try:
        dependencies = []
        
        if entity_name == "categories":
            # Check if category is used by any foods
            foods_collection = get_collection("foods")
            foods_using_category = await foods_collection.find({"category_id": entity_id}).to_list(length=1)
            if foods_using_category:
                dependencies.append(f"{len(foods_using_category)} food item(s)")
                
        elif entity_name == "foods":
            # Check if food is used in any orders
            orders_collection = get_collection("orders")
            orders_with_food = await orders_collection.find({"items.food_id": entity_id}).to_list(length=1)
            if orders_with_food:
                dependencies.append(f"{len(orders_with_food)} order(s)")
                
        elif entity_name == "employees":
            # Check if employee is assigned to orders, shifts, or payroll
            orders_collection = get_collection("orders")
            orders_with_employee = await orders_collection.find({"employee_id": entity_id}).to_list(length=1)
            if orders_with_employee:
                dependencies.append(f"{len(orders_with_employee)} order(s)")
                
            shifts_collection = get_collection("shifts")
            shifts_with_employee = await shifts_collection.find({"employee_id": entity_id}).to_list(length=1)
            if shifts_with_employee:
                dependencies.append(f"{len(shifts_with_employee)} shift(s)")
                
        elif entity_name == "inventory_products":
            # Check if inventory product is used in any food recipes
            foods_collection = get_collection("foods")
            foods_using_product = await foods_collection.find({"recipes.inventory_product_id": entity_id}).to_list(length=1)
            if foods_using_product:
                dependencies.append(f"{len(foods_using_product)} food recipe(s)")
                
            # Check if used in purchase orders
            po_collection = get_collection("purchase_orders")
            po_using_product = await po_collection.find({"items.inventory_product_id": entity_id}).to_list(length=1)
            if po_using_product:
                dependencies.append(f"{len(po_using_product)} purchase order(s)")
                
        elif entity_name == "suppliers":
            # Check if supplier is used by any inventory products
            inventory_collection = get_collection("inventory_products")
            products_with_supplier = await inventory_collection.find({"supplier_id": entity_id}).to_list(length=1)
            if products_with_supplier:
                dependencies.append(f"{len(products_with_supplier)} inventory product(s)")
                
        elif entity_name == "tables":
            # Check if table has active orders or reservations
            orders_collection = get_collection("orders")
            active_orders = await orders_collection.find({
                "table_id": entity_id,
                "status": {"$in": ["new", "preparing", "served"]}
            }).to_list(length=1)
            if active_orders:
                dependencies.append(f"{len(active_orders)} active order(s)")
                
            reservations_collection = get_collection("reservations")
            upcoming_reservations = await reservations_collection.find({
                "table_id": entity_id,
                "status": "confirmed"
            }).to_list(length=1)
            if upcoming_reservations:
                dependencies.append(f"{len(upcoming_reservations)} upcoming reservation(s)")
                
        elif entity_name == "customers":
            # Check if customer has orders or reservations
            orders_collection = get_collection("orders")
            customer_orders = await orders_collection.find({"customer_id": entity_id}).to_list(length=1)
            if customer_orders:
                dependencies.append(f"{len(customer_orders)} order(s)")
                
            reservations_collection = get_collection("reservations")
            customer_reservations = await reservations_collection.find({"customer_id": entity_id}).to_list(length=1)
            if customer_reservations:
                dependencies.append(f"{len(customer_reservations)} reservation(s)")
                
        elif entity_name == "users":
            # Check if user is linked to an employee
            employees_collection = get_collection("employees")
            employee_with_user = await employees_collection.find({"user_id": entity_id}).to_list(length=1)
            if employee_with_user:
                dependencies.append("1 employee record")
        
        return success_response(
            data={
                "hasDependencies": len(dependencies) > 0,
                "dependencies": dependencies,
                "message": f"Cannot delete - used by: {', '.join(dependencies)}" if dependencies else "Safe to delete"
            }
        )
        
    except Exception as e:
        return handle_generic_exception(e)


# Add detailed health check endpoint
@router.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check for debugging"""
    try:
        # Test database connection
        from app.database import get_database
        db = get_database()
        await db.command("ping")
        db_status = "healthy"
        
        # Test collections
        collections = await db.list_collection_names()
        
        return success_response(data={
            "status": "healthy",
            "database": db_status,
            "collections": collections,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        return error_response(
            message="Health check failed",
            code=503,
            details={"error": str(e)}
        )


# Add Halo transaction endpoint at the end of core.py

@router.get("/halo/status")
async def halo_status():
    """Simple endpoint to test if Halo is working"""
    return success_response(
        data={
            "status": "available",
            "timestamp": datetime.utcnow().isoformat(),
            "endpoints": ["/api/halo/transaction", "/api/halo/status"]
        },
        message="Halo payment endpoint is active"
    )

@router.post("/halo/transaction", response_model=StandardResponse[dict])
async def process_halo_transaction(transaction_data: Dict[str, Any] = Body(...)):
    """Process Halo payment transaction"""
    try:
        # Extract transaction data
        amount = transaction_data.get("amount", 0)
        order_id = transaction_data.get("order_id")
        
        if not order_id:
            return error_response(message="Order ID is required", code=400)
        
        if amount <= 0:
            return error_response(message="Amount must be greater than 0", code=400)
        
        # Create a simple success response
        transaction_id = transaction_data.get("transaction_id", f"HALO-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
        
        response_data = {
            "status": "success",
            "transaction_id": transaction_id,
            "order_id": order_id,
            "amount": amount,
            "message": "Payment processed successfully",
            "payment_reference": f"PAY-REF-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Try to update order if it exists (not "new-order")
        if order_id != "new-order":
            try:
                orders_collection = get_collection("orders")
                # Try to find and update the order
                order = await orders_collection.find_one({"_id": ObjectId(order_id)})
                if order:
                    await orders_collection.update_one(
                        {"_id": ObjectId(order_id)},
                        {
                            "$set": {
                                "payment_status": "paid",
                                "payment_method": transaction_data.get("payment_method", "card"),
                                "updated_at": datetime.utcnow().isoformat()
                            }
                        }
                    )
                    response_data["order_updated"] = True
            except:
                # If order not found or invalid ID, continue anyway
                response_data["order_updated"] = False
        
        return success_response(
            data=response_data,
            message="Halo transaction processed successfully"
        )
        
    except Exception as e:
        return error_response(
            message="Halo transaction failed",
            code=500,
            details={"error": str(e), "timestamp": datetime.utcnow().isoformat()}
        )


# Add this to your core.py routes section
@router.post("/halo/verify", response_model=StandardResponse[dict])
async def verify_halo_payment(
    reference: str = Query(..., description="Halo transaction reference")
):
    """Verify a Halo payment status"""
    try:
        # Check payment attempts collection
        payment_attempts_collection = get_collection("payment_attempts")
        
        # Try to find by reference
        attempt = await payment_attempts_collection.find_one({
            "reference": reference
        })
        
        if not attempt:
            # Try to find by order_id if reference is an order ID
            attempt = await payment_attempts_collection.find_one({
                "order_id": reference
            })
        
        if attempt:
            return success_response(data={
                "status": attempt.get("status", "pending"),
                "transaction_id": attempt.get("reference"),
                "order_id": attempt.get("order_id"),
                "amount": attempt.get("amount"),
                "completed_at": attempt.get("completed_at"),
                "created_at": attempt.get("created_at"),
                "payment_gateway": attempt.get("payment_gateway")
            })
        
        return error_response(
            message="Transaction not found",
            code=404,
            details={"reference": reference}
        )
        
    except Exception as e:
        return handle_generic_exception(e)
