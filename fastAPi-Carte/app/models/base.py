# app/models/base.py - FIXED VERSION
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
from pydantic_core import core_schema
from bson import ObjectId
from datetime import datetime, date
import json

class PyObjectId(str):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler) -> core_schema.CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ObjectId),
                core_schema.str_schema()
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda x: str(x) if x else None
            ),
        )

    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return str(v)
        if isinstance(v, str) and ObjectId.is_valid(v):
            return v
        raise ValueError("Invalid ObjectId")

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

class MongoModel(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    created_at: Optional[datetime] = None 
    updated_at: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda dt: dt.isoformat() if dt else None,  # Handle None
        }

    def to_dict(self, **kwargs) -> dict:
        """Convert model to dictionary with proper ID handling"""
        exclude_unset = kwargs.pop('exclude_unset', True)
        by_alias = kwargs.pop('by_alias', True)
        
        data = self.model_dump(
            exclude_unset=exclude_unset,
            by_alias=by_alias,
            **kwargs,
        )
        
        # Handle ID fields - ensure we don't have both id and _id
        if '_id' in data and 'id' in data:
            del data['id']
        elif 'id' in data and '_id' not in data:
            data['_id'] = data.pop('id')
            
        return data

    @classmethod
    def from_mongo(cls, data: dict):
        """Convert MongoDB document to model instance"""
        if not data:
            return None
            
        data = data.copy()
        
        # Convert _id to id
        if '_id' in data:
            if isinstance(data['_id'], ObjectId):
                data['id'] = str(data['_id'])
            else:
                data['id'] = data['_id']
            # Remove _id to avoid conflicts
            del data['_id']
        
        # Convert any remaining nested ObjectIds to strings
        for field, value in data.items():
            if isinstance(value, ObjectId):
                data[field] = str(value)
        
        # Let Pydantic handle datetime conversion automatically
        # No need to convert datetime objects to strings
        return cls(**data)
