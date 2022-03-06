package com.sccurity.jwt_project.controller;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sccurity.jwt_project.domain.Client;
import com.sccurity.jwt_project.domain.Role;
import com.sccurity.jwt_project.service.ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
@RequestMapping("/api")
public class UserController {

    private final ClientService clientService;

    @Autowired
    public UserController(ClientService clientService) {
        this.clientService = clientService;
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<List<Client>> getClients() {
        return ResponseEntity.ok().body(clientService.getClients());
    }

    @PostMapping("/user/save")
    public ResponseEntity<Client> saveUser(@RequestBody Client client) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(clientService.saveClient(client));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(clientService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToClient(@RequestBody RoleToClientForm form) {
        clientService.addRoleToClient(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/user_role")
    @PreAuthorize("hasAnyAuthority('ROLE_USER, ROLE_MANAGER')")
    public String testMethodUsers() {
        return "Users has access to this resource";
    }


    @GetMapping("/admin_role")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String testMethodAdmin() {
        return "Admins has access to this resource";
    }

    @GetMapping("/manager_role")
    @PreAuthorize("hasAuthority('ROLE_MANAGER')")
    public String testMethodManager() {
        return "Managers has access to this resource";
    }

    @GetMapping("/manager_role/test")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String testMethodManagerTest() {
        return "Managers has access to this resource to test";
    }

    @GetMapping("/super_admin_role")
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    public String testMethodSuperAdmin() {
        return "Super Admin has access to this resource";
    }


    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Brearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("Nx@709090".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                Client client = clientService.getClient(username);
                String access_token = JWT.create()
                        .withSubject(client.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", client.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception ex) {
                response.setHeader("error", ex.getMessage());
                response.setStatus(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", ex.getMessage());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }

}

/**
 * To add a role to a current client we need to have a way to get the user and role from the request
 * therefore the following class is created and called from the addRoleToClient method.
 */

class RoleToClientForm {
    private String username;
    private String roleName;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }
}
