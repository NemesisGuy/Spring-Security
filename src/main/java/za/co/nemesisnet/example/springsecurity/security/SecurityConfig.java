package za.co.nemesisnet.example.springsecurity.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final UserDetailsService userDetailsService; // Inject UserDetailsService

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
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
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for simplicity in development

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/users/register", "/api/users/login","/").permitAll()  // Public access for register, login
                        .requestMatchers("/api/users/all").authenticated() // Require authentication for fetching all users
                        .anyRequest().authenticated()  // All other endpoints require authentication
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)  // Allow only one session per user
                )
                .formLogin(form -> form
                        .loginPage("/login")  // Custom login page if needed
                        .defaultSuccessUrl("/home", true)  // Redirect on successful login
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")  // Custom logout URL
                        .invalidateHttpSession(true)  // Invalidate the session
                        .deleteCookies("JSESSIONID")  // Delete the session cookie (JSESSIONID) on logout
                        .logoutSuccessUrl("/")  // Redirect to login after logout
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
        SessionCookieAuthenticationFilter filter = new SessionCookieAuthenticationFilter(authManager(http), userDetailsService);
        return filter; // Return the configured filter
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

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            System.out.println("User logged in: " + authentication.getName());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            response.setStatus(HttpServletResponse.SC_OK);
        };
    }
}
