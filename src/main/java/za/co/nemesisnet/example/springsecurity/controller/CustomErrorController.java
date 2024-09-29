package za.co.nemesisnet.example.springsecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<?> handleError(HttpServletRequest request) {
        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
        // Default status code in case it's null
        if (statusCode == null) {
            statusCode = HttpStatus.INTERNAL_SERVER_ERROR.value();
        }
        String errorMessage = "Unknown error";

        if (statusCode == HttpStatus.NOT_FOUND.value()) {
            errorMessage = "Page not found";
        } else if (statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
            errorMessage = "Internal server error";
        } else if (statusCode == HttpStatus.FORBIDDEN.value()) {
            errorMessage = "Access denied";
        }

        return ResponseEntity.status(statusCode).body(new ErrorResponse(statusCode, errorMessage));
    }

    private static class ErrorResponse {
        private final Integer statusCode;
        private final String message;

        public ErrorResponse(Integer statusCode, String message) {
            this.statusCode = statusCode;
            this.message = message;
        }

        public Integer getStatusCode() {
            return statusCode;
        }

        public String getMessage() {
            return message;
        }
    }
}
