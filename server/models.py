from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    serialize_rules = ('-password_hash',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', back_populates='user', cascade="all, delete-orphan")

    @validates('username')
    def validate_username(self, key, value):
        if not value or value.strip() == '':
            raise ValueError("Username must be present and not empty.")
        return value

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) 
    user = db.relationship('User', back_populates='recipes')

    @validates('user_id')
    def validate_user_id(self, key, value):
        if value is None:
            raise ValueError("User ID must be present and not empty.")
        return value

    @validates('title')
    def validate_title(self, key, value):
        if not value or value.strip() == '':
            raise ValueError("Title must be present and not empty.")
        return value

    @validates('instructions')
    def validate_instructions(self, key, value):
        if len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value

    __tablename__ = 'recipes'
    
"""     def __init__(self, **kwargs):  #this was needed to pas the models test but caused issues with seeding
        super().__init__(**kwargs)
        if not self.user_id:
            first_user = User.query.first()  
            if first_user:
                self.user_id = first_user.id """