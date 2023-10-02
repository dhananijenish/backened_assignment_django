# Backend Assignment

Brief description of your project. Mention its purpose, main features, and any other relevant information.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Sample Requests and Responses](#sample-requests-and-responses)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the repository:**

    ```
    git clone git@github.com:dhananijenish/backened_assignment_django.git
    cd project-directory
    ```

2. **Set up virtual environment (optional but recommended):**

    ```
    python -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies:**

    ```
    pip install -r requirements.txt
    ```

4. **Database migrations:**

    ```
    python manage.py makemigrations
    python manage.py migrate
    ```

5. **Run the development server:**

    ```
    python manage.py runserver
    ```

## Usage

Provide instructions on how to use your application. Include any setup steps, configuration options, or environment variables that need to be set.

## API Endpoints

- **POST /api/register/**
  - Register a new user.
  - Required fields: `email`, `password`.
  
- **POST /api/login/**
  - Log in a user.
  - Required fields: `email`, `password`.
  
- **POST /api/token/refresh/**
  - Refresh an expired access token.
  - Required fields: `refresh`.

- **GET /api/posts/**
  - Retrieve all posts created by the authenticated user.
  
- **POST /api/posts/**
  - Create a new post.
  - Required fields: `title`, `content`.

- **GET /api/posts/{post_id}/**
  - Retrieve details of a specific post.

- **PUT /api/posts/{post_id}/**
  - Update a specific post.
  - Allowed fields: `title`, `content`.

- **DELETE /api/posts/{post_id}/**
  - Delete a specific post.

## Authentication

- **Register:**
  - Endpoint: `/api/register/`
  - Method: `POST`
  - Required fields: `email`, `password`

- **Login:**
  - Endpoint: `/api/login/`
  - Method: `POST`
  - Required fields: `email`, `password`

- **Token Refresh:**
  - Endpoint: `/api/token/refresh/`
  - Method: `POST`
  - Required fields: `refresh`

## Sample Requests and Responses

### Register User

**Request:**
```
POST /api/register/
{
    "email": "user@example.com",
    "password": "secretpassword"
}
```

**Response:**
```
{
    "user_id": 1,
    "email": "user@example.com",
    "access": "your-access-token",
    "refresh": "your-refresh-token"
}
```

### Log In User

**Request:**
```
POST /api/login/
{
    "email": "user@example.com",
    "password": "secretpassword"
}
```

**Response:**
```
{
    "email": "user@example.com",
    "token": {
        "refresh": "your-refresh-token",
        "access": "your-access-token"
    }
}
```

### Create Post

**Request:**
```
POST /api/posts/
{
    "title": "New Post",
    "content": "This is the content of the new post."
}
```

**Response:**
```
{
    "id": 1,
    "title": "New Post",
    "content": "This is the content of the new post.",
    "user": 1,
    "created_at": "2023-10-02T12:00:00Z"
}
```


