# Auth Assessment Project

This project simulates a real-world scenario where a developer builds a reusable authentication and authorization library ("Spring Boot Starter") and a consuming sample application.

## Project Structure

The project is invalid as a multi-module Maven project:

- **`core-security-starter`**: The reusable library containing:
    - JWT utility (`JwtTokenProvider`) for token generation and validation.
    - Security configuration (`SecurityFilterChain`) with Stateless session management.
    - Custom filters (`JwtAuthenticationFilter`, `RequestLoggingFilter`).
    - Exception handling (`JwtAuthenticationEntryPoint`, `JwtAccessDeniedHandler`).
- **`sample-application`**: A Spring Boot application that uses `core-security-starter`. It includes:
    - H2 Database with `User` entity and `UserRepository`.
    - `CustomUserDetailsService` implementation.
    - `AuthController` for login.
    - `TestController` with Public, User, and Admin endpoints.

## Prerequisites

- Java 17+ (Project uses Java 21)
- Maven 3.8+

## How to Build

From the root directory, run:

```bash
mvn clean install
```

This will build both modules and install `core-security-starter` into your local Maven repository so `sample-application` can use it.

## How to Run

Navigate to the sample application directory and run:

```bash
cd sample-application
mvn spring-boot:run
```

The application will start on port `8080`.

## API Endpoints

### Public
- `GET /api/public/health` - Check API status.

### Authentication
- `POST /api/auth/login` - Authenticate and get a JWT.
    - **Body**: `{ "username": "admin", "password": "admin123" }` (or "user"/"user123")
    - **Response**: `{ "accessToken": "..." }`

### Protected (Requires Bearer Token)
- `GET /api/user/me` - Get current user details. (Any authenticated user)
- `GET /api/admin/users` - Get all users. (Requires `ROLE_ADMIN`)

## Default Users (H2 Database)

- **Admin**: `admin` / `password` (Roles: `ROLE_ADMIN`, `ROLE_USER`)
- **User**: `user` / `password` (Roles: `ROLE_USER`)

## Testing

To run the integration tests:

```bash
mvn test -pl sample-application
```
## Design Decisions & Trade-offs

- Implemented authentication logic inside a reusable Spring Boot Starter to promote reuse across services.
- Used JWT for stateless authentication to simplify horizontal scalability.
- Chose BCrypt for password hashing due to its adaptive strength and security.
- Embedded JWT validation inside a filter within the starter to keep security concerns out of consuming applications.
- Used role-based authorization with Spring Security for fine-grained access control.
- H2 database was selected for the sample application to simplify setup and testing.
