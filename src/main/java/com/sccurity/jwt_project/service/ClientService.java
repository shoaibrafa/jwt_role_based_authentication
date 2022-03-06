package com.sccurity.jwt_project.service;

import com.sccurity.jwt_project.domain.Client;
import com.sccurity.jwt_project.domain.Role;
import java.util.List;

/**
 * This interface defines the required methods to manage the users.
 * The UserServiceImpl implements these methods.
 */
public interface ClientService {
    Client saveClient(Client client);
    Role saveRole(Role role);
    void addRoleToClient(String username, String roleName);
    Client getClient(String username);
    List<Client> getClients();
}
