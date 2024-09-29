package za.co.nemesisnet.example.springsecurity.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import za.co.nemesisnet.example.springsecurity.domain.User;
import za.co.nemesisnet.example.springsecurity.service.UserService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private  AuthenticationManager authenticationManager;

    @Autowired
    public UserController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<User> registerUser(@RequestBody User user) {
        User savedUser = userService.registerUser(user);
        return ResponseEntity.ok(savedUser);
    }

//    @PostMapping("/login")
//    public ResponseEntity<Object> login(@RequestBody User user, HttpServletRequest request) {
//        try {
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//            // Log the contents of the SecurityContextHolder
//            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//            if (auth != null) {
//                System.out.println("Authenticated user: " + auth.getName());
//                System.out.println("Authorities: " + auth.getAuthorities());
//            } else {
//                System.out.println("No authentication found");
//            }
//
//            HttpSession session = request.getSession(true);
//            session.setAttribute("user", user.getUsername());
//            session.setMaxInactiveInterval(60 * 60); // 60 minutes
//            System.out.println("Session ID: " + session.getId());
//            System.out.println("Session Username: " + session.getAttribute("user"));
//
//            return ResponseEntity.ok("User logged in successfully!");
//        } catch (AuthenticationException e) {
//            Map<String, String> errorResponse = new HashMap<>();
//            errorResponse.put("message", "Invalid username or password.");
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
//        }
//    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody User user, HttpServletRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext()); // Store context in session

            return ResponseEntity.ok("User logged in successfully!");
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password.");
        }

    }


  /*  @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
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

        // Clear the SecurityContextHolder for the current user session
        SecurityContextHolder.clearContext();

        return ResponseEntity.ok("User logged out successfully!");
    }*/


    @GetMapping("/all")
    public ResponseEntity<Object> getAllUsers(HttpServletRequest request) {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized access. Please log in.");
        }
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }
}
