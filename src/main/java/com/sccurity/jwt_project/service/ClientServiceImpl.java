package com.sccurity.jwt_project.service;

import com.sccurity.jwt_project.domain.Client;
import com.sccurity.jwt_project.domain.Role;
import com.sccurity.jwt_project.repo.RoleRepo;
import com.sccurity.jwt_project.repo.ClientRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


/**
 * This service class implements all methods from the UserService
 * and UserDetailsService.
 */

@Service
@Transactional
public class ClientServiceImpl implements ClientService, UserDetailsService {

    private final ClientRepo clientRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ClientServiceImpl(ClientRepo clientRepo,
                             RoleRepo roleRepo,
                             PasswordEncoder passwordEncoder){
        this.clientRepo = clientRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }


    /**
     * Inside the SecurityConfig class we have created a bean of type UserDetails which is used inside the
     * configure(AuthenticationManagerBuilder auth) method. Here we implemnent that bean how to operate.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Client client = clientRepo.findByUsername(username);
        if(client == null){
            throw new UsernameNotFoundException("User not found in the database");
        }else {
            System.out.println("User found in the database");
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        client.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        return new User(client.getUsername(), client.getPassword(), authorities);
    }


    /**
     * this method is used to save the users in the database
     */
    @Override
    public Client saveClient(Client client) {
        client.setPassword(passwordEncoder.encode(client.getPassword()));
        return clientRepo.save(client);
    }



    /**
     * this method is used to save the roles in the database
     */
    @Override
    public Role saveRole(Role role) {
        return roleRepo.save(role);
    }



    /**
     * this method is used to add roles to the current user.
     */
    @Override
    public void addRoleToClient(String username, String roleName) {
        Client client = clientRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        client.getRoles().add(role);
    }



    /**
     * this method returns a user based on the user's username
     */
    @Override
    public Client getClient(String username) {
        return clientRepo.findByUsername(username);
    }


    /**
     * This method is used to return the list of all users
     */
    @Override
    public List<Client> getClients() {
        return clientRepo.findAll();
    }
}
