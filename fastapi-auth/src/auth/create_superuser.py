# src/auth/create_superuser.py

# ! Command => python -m src.auth.create_superuser

import click
from sqlalchemy.orm import Session
from ..database import SessionLocal  # Adjust the import based on your project structure
from .models import User  # Adjust the import based on your project structure

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@click.command()
@click.option('--username', prompt='Username', help='The username of the superuser.')
@click.option('--email', prompt='Email', help='The email of the superuser.')
@click.option('--password', prompt='Password', hide_input=True, confirmation_prompt=True, help='The password of the superuser.')
def create_superuser(username: str, email: str, password: str):
    """Create a new superuser."""
    db: Session = next(get_db())
    
    # Check if the user already exists
    existing_user = db.query(User).filter((User .username == username) | (User .email == email)).first()
    if existing_user:
        click.echo("A user with this username or email already exists.")
        return

    # Create the superuser
    new_user = User(
        username=username,
        email=email,
        full_name=username,  # You can customize this as needed
        is_superuser=True,
        is_staff=True,
        role='admin',  # Set the role as needed
    )
    new_user.set_password(password)  # Hash the password
    db.add(new_user)
    db.commit()
    
    click.echo(f"Superuser {username} created successfully.")

if __name__ == '__main__':
    create_superuser()