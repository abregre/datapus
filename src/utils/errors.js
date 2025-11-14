class ApiError extends Error {
    constructor(statusCode, code, message, details = {}) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
    }
}

class AuthenticationError extends ApiError {
    constructor(message = "Authentication Failed") {
        super(401, "AUTHENTICATION_FAILED", message);
    }
}

class ValidationError extends ApiError {
    constructor(code, message) {
        super(400, code, message);
    }
}

class NotFoundError extends ApiError {
    constructor(message = "Not Found") {
        super(404, "NOT_FOUND", message);
    }
}

class S3Error extends ApiError {
    constructor(message = "S3 Operation Failed") {
        super(500, "S3_OPERATION_FAILED", message);
    }
}

class VirusScanError extends ApiError {
    constructor(message = "Virus Detected") {
        super(420, "VIRUS_DETECTED", message);
    }
}

class InternalError extends ApiError {
    constructor(message = "Internal Server Error") {
        super(500, "INTERNAL_ERROR", message);
    }
}

module.exports = {
    ApiError,
    AuthenticationError,
    ValidationError,
    NotFoundError,
    S3Error,
    VirusScanError,
    InternalError,
};
