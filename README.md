# Spring Boot Backend API

## Table of Contents
- [Overview](#overview)
- [Technologies Used](#technologies-used)
- [API Endpoints](#api-endpoints)
- [Authentication & Authorization](#authentication--authorization)
- [Error Handling](#error-handling)


## Overview
This is a Spring Boot backend API for managing users, handling authentication, and performing secure operations. The API uses cookies and sessions for user authentication and role-based access control. It exposes a set of endpoints for user management, login/logout operations, and secure resource access.

## Technologies Used
- **Spring Boot** - Backend framework.
- **Spring Security** - For authentication and authorization.
- **Hibernate/JPA** - For ORM (Object-Relational Mapping).
- **MySQL** - Database used for data persistence.
- **Maven** - For project build and dependency management.
- **Tomcat** - Embedded web server.

## API Endpoints
| Method | Endpoint                  | Description                        | Auth Required |
|--------|---------------------------|------------------------------------|---------------|
| GET    | `/api/users/all`          | Get all users                      | Yes           |
| POST   | `/api/users/login`        | Login a user, creates session      | No            |
| POST   | `/api/auth/users/logout`  | Logout, invalidate current session | Yes           |
| POST   | `/api/api/users/register` | Register a new user                | No            |
| GET    | `/api/auth/profile`       | Get user profile                   | Yes   (TBA)   |

For detailed API documentation, please refer to the Swagger documentation at `http://localhost:8080/swagger-ui`.

## Authentication & Authorization
- **Cookies and Sessions:** The API uses cookies and sessions for authentication. When a user logs in, a session is created, and a cookie is sent to the client for subsequent requests.
- **Roles:** The API supports different user roles such as `ROLE_USER` and `ROLE_ADMIN` for fine-grained access control.(Not in use)

### How to Login:
1. Use the `/api/users/login` endpoint with valid credentials.
2. A session will be created, and a cookie will be sent back to the client, which must be included in the headers for secured endpoints.

## Error Handling
Custom error handling is implemented for common HTTP errors such as `404 Not Found`, `403 Forbidden`, and `500 Internal Server Error`. Each error response contains a status code and a corresponding error message.

Example error response:
```json
{
  "statusCode": 404,
  "message": "Page not found"
}
