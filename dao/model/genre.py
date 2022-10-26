from marshmallow import Schema, fields
from sqlalchemy import Column, Integer, String

from setup_db import db


class Genre(db.Model):
    __tablename__ = 'genre'
    id = Column(Integer, primary_key=True)
    name = Column(String(255))


class GenreSchema(Schema):
    id = fields.Int()
    name = fields.Str()
