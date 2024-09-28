package za.co.nemesisnet.example.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import za.co.nemesisnet.example.springsecurity.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

}
