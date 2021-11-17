package ca.com.rlsp.rlspfood.auth.core;

import ca.com.rlsp.rlspfood.auth.domain.User;
import ca.com.rlsp.rlspfood.auth.domain.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Usa a implementacao de >> UserDetailsService << para consultar os usuarios
 */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(()-> new UsernameNotFoundException("Username not found on DB"));

        return new AuthenticationUser(user);
    }
}
