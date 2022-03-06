package com.sccurity.jwt_project;

import com.sccurity.jwt_project.domain.Client;
import com.sccurity.jwt_project.domain.Role;
import com.sccurity.jwt_project.service.ClientService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtProjectApplication.class, args);
    }

    /**
     * Inside the Security Config we have created a bean
     * for password encoder and here we are actually creating that bean.
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     *
     * This method is used to create users and roles on the runtime.
     */
    @Bean
    CommandLineRunner runner(ClientService clientService) {
        return args -> {
            clientService.saveRole(new Role(null, "ROLE_USER"));
            clientService.saveRole(new Role(null, "ROLE_MANAGER"));
            clientService.saveRole(new Role(null, "ROLE_ADMIN"));
            clientService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            clientService.saveClient(new Client(null, "John Travolta", "john", "1234", new ArrayList<>()));
            clientService.saveClient(new Client(null, "Will Smith", "will", "1234", new ArrayList<>()));
            clientService.saveClient(new Client(null, "Jim Carry", "jim", "1234", new ArrayList<>()));
            clientService.saveClient(new Client(null, "Arnold Schwarzenegger", "arnold", "1234", new ArrayList<>()));
            clientService.saveClient(new Client(null, "Shoaib Rafa", "rafa", "jasmine", new ArrayList<>()));
            clientService.saveClient(new Client(null, "Mike Logan", "mike", "12345", new ArrayList<>()));

            clientService.addRoleToClient("john", "ROLE_USER");
            clientService.addRoleToClient("john", "ROLE_MANAGER");
            clientService.addRoleToClient("will", "ROLE_MANAGER");
            clientService.addRoleToClient("jim", "ROLE_ADMIN");
            clientService.addRoleToClient("arnold", "ROLE_SUPER_ADMIN");
            clientService.addRoleToClient("arnold", "ROLE_ADMIN");
            clientService.addRoleToClient("arnold", "ROLE_USER");
            clientService.addRoleToClient("rafa", "ROLE_MANAGER");
            clientService.addRoleToClient("rafa", "ROLE_SUPER_ADMIN");
            clientService.addRoleToClient("mike", "ROLE_USER");
        };
    }
}
