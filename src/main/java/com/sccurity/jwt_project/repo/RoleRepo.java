package com.sccurity.jwt_project.repo;

import com.sccurity.jwt_project.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;


/**
 * The repository interface for our Role model.
 */
public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
