package mc.apps.spring;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserService implements UserDetailsService {
//    private final PasswordEncoder passwordEncoder;
//
//    public UserService(PasswordEncoder passwordEncoder) {
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    @Override
//    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
//        if("user".equals(login)) {
//            return new User(login, passwordEncoder.encode("password"), new ArrayList<>());
//        } else {
//            throw new UsernameNotFoundException("User not found with login: " + login);
//        }
//    }

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        if("user".equals(login)) {
            return new User(login, "password", new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with login: " + login);
        }
    }
}