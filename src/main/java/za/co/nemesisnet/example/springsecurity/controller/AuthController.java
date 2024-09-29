package za.co.nemesisnet.example.springsecurity.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
@RequestMapping("/api/auth")

@RestController
public class AuthController {
    @PostMapping("/user/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {

        // Optionally, clear any cookies
        // Invalidate the session if it exists
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        // Remove the JSESSIONID cookie by setting MaxAge to 0 and Path to root
        Cookie cookie = new Cookie("JSESSIONID", null);
        cookie.setPath("/"); // Make sure the path matches your application's root path
        cookie.setMaxAge(0); // Setting MaxAge to 0 deletes the cookie
        cookie.setHttpOnly(true); // For security, make sure the cookie is HttpOnly
        cookie.setSecure(false); // If you're using HTTPS, set the cookie to Secure
        response.addCookie(cookie);
        request.getSession().invalidate(); // Invalidate session

        // Clear the SecurityContextHolder for the current user session
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("message", "Logout successful"));
    }
}

