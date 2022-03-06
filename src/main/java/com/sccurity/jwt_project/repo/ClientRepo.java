package com.sccurity.jwt_project.repo;

import com.sccurity.jwt_project.domain.Client;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository interface for our User model
 */
public interface ClientRepo extends JpaRepository<Client, Long> {
    Client findByUsername(String username);
}
