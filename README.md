
# FastAPI Auth

FastAPI Auth is a robust authentication system built using FastAPI. This project provides a modular structure for handling authentication, API endpoints, analytics, and more. It is designed to be scalable and easy to maintain.

## Installation

To get started with the FastAPI Auth project, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/shiladityamajumder/fastapi.git
   cd fastapi-auth
   ```

2. Create a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements/base.txt
   ```

## Usage

To run the FastAPI application, use the following command:

```bash
uvicorn src.main:app --reload
```

You can access the API documentation at `http://127.0.0.1:8000/docs`.

## Configuration

Configuration settings can be found in the `.env` file. Make sure to set the necessary environment variables for your database and other services.

## Testing

To run the tests, use the following command:

```bash
pytest
```

Make sure to have the test dependencies installed from `requirements/dev.txt`.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Additional Information

For further details on the authentication methods and API endpoints, refer to the documentation within the project or the official FastAPI documentation.