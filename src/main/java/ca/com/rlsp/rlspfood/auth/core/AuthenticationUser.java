package ca.com.rlsp.rlspfood.auth.core;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthenticationUser extends User {

    private String fullName;
    private Long id;

    public AuthenticationUser(ca.com.rlsp.rlspfood.auth.domain.User user) {
        super(user.getEmail(), user.getPassword(), Collections.emptyList());

        this.fullName = user.getName();
        this.id = user.getId();
    }
}
