package za.co.nemesisnet.example.springsecurity.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final CustomLogoutSuccessHandler customLogoutSuccessHandler;
    private final CustomLoginSuccessHandler customLoginSuccessHandler; // Inject the custom login success handler

    public SecurityConfig(UserDetailsService userDetailsService, CustomLogoutSuccessHandler customLogoutSuccessHandler, CustomLoginSuccessHandler customLoginSuccessHandler) {
        this.userDetailsService = userDetailsService;
        this.customLogoutSuccessHandler = customLogoutSuccessHandler;
        this.customLoginSuccessHandler = customLoginSuccessHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(request -> {
                    var corsConfig = new CorsConfiguration();
                    corsConfig.setAllowedOrigins(List.of("http://localhost:5173"));
                    corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                    corsConfig.setAllowCredentials(true);  // This allows cookies to be sent with requests
                    corsConfig.setAllowedHeaders(List.of("*"));
                    return corsConfig;
                }))  // Enable CORS
                .csrf(csrf -> csrf.disable()) // Disable CSRF for simplicity in development
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/users/register", "/api/users/login", "/", "/home", "/error").permitAll()  // Public access for register, login
                        .requestMatchers("/api/users/all").authenticated() // Require authentication for fetching all users
                        .anyRequest().authenticated()  // All other endpoints require authentication
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)  // Allow only one session per user
                )
                .formLogin(form -> form
                        .loginPage("/login")  // Custom login page if needed
                        //.defaultSuccessUrl("/home", true)  // This is removed, as we now use a custom handler
                        .successHandler(customLoginSuccessHandler)  // Use the custom login success handler
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/api/auth/users/logout")  // Custom logout URL
                        .invalidateHttpSession(true)  // Invalidate the session
                        .deleteCookies("JSESSIONID")  // Delete the session cookie (JSESSIONID) on logout
                        .logoutSuccessHandler(customLogoutSuccessHandler)  // Use the custom logout success handler
                        .permitAll()
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            System.out.println("Authentication failed: " + authException.getMessage());
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                        })
                );

        // Add the custom filter to the security chain
        http.addFilterBefore(sessionCookieAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public SessionCookieAuthenticationFilter sessionCookieAuthenticationFilter(HttpSecurity http) throws Exception {
        return new SessionCookieAuthenticationFilter(authManager(http), userDetailsService);  // Return the configured filter
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        return authenticationManagerBuilder.build();
    }
}
