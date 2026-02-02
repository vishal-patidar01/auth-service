package com.vishal.auth.auth_app_backend.repositories;

import com.vishal.auth.auth_app_backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

//    Custom finder methods
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
