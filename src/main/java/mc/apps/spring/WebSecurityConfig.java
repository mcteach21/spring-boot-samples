package mc.apps.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//@Configuration
//@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
    private final UserDetailsService userService;
    private final ObjectMapper objectMapper;
    private PasswordEncoder bCryptPasswordEncoder;

    public WebSecurityConfig(UserService userService, ObjectMapper objectMapper) {
        this.userService = userService;
        this.objectMapper = objectMapper;
        logger.info("WebSecurityConfig - userService : "+userService);
    }

    @Autowired
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userService);

        bCryptPasswordEncoder = bCryptPasswordEncoder();
        logger.info("configureGlobal - bCryptPasswordEncoder : "+bCryptPasswordEncoder);
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    @Service(value = "userDetailsService")
    public class CustomUserDetailsService implements UserDetailsService {

//        @Autowired
//        private UserRepository userRepository;

        @Override
        public UserDetails loadUserByUsername(String input) {
            User user = null;

//            if (input.contains("@"))
//                user = userRepository.findByEmail(input);
//            else
//                user = userRepository.findByUsername(input);

            if (user == null)
                throw new BadCredentialsException("Bad credentials");

            new AccountStatusUserDetailsChecker().check(user);
            return user;
        }

    }
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
//        PasswordEncoder encoder = passwordEncoder();
        logger.info("**********************************************");
        logger.info("UserDetailsService");
        logger.info("**********************************************");

        logger.info("UserDetailsService - encoder : "+bCryptPasswordEncoder);

        final User.UserBuilder userBuilder = User.builder().passwordEncoder(bCryptPasswordEncoder::encode);
        UserDetails user = userBuilder
                .username("m.chou")
                .password("123")
                .roles("USER")
                .build();

        UserDetails admin = userBuilder
                .username("m.admin")
                .password("321")
                .roles("USER","ADMIN")
                .build();

        logger.info("userDetailsService - user : "+user);
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() //We don't need CSRF for this example
                .authorizeRequests()
                .antMatchers("/css/**","/webjars/**","/images/**", "/").permitAll()
//                .antMatchers("/admin/**").authenticated()
                .antMatchers("/contact").hasRole("USER")
                .anyRequest().authenticated() // all others requires a logged in user
                .and()
                .formLogin()
                .loginProcessingUrl("/login") //the URL on which the clients should post the login information
                .usernameParameter("login") //the username parameter in the queryString, default is 'username'
                .passwordParameter("password") //the password parameter in the queryString, default is 'password'
                .successHandler(this::loginSuccessHandler)
                .failureHandler(this::loginFailureHandler)
                .and()
                .logout()
                .logoutUrl("/logout") //the URL on which the clients should post if they want to logout
                .logoutSuccessHandler(this::logoutSuccessHandler)
                .invalidateHttpSession(true)
                .and()
                .exceptionHandling(); //default response if the client wants to get a resource unauthorized
                //.authenticationEntryPoint(new Http401AuthenticationEntryPoint("401"));

    }
    private void loginSuccessHandler( HttpServletRequest request,  HttpServletResponse response, Authentication authentication) throws IOException {
        logger.info("***********************************************");
        logger.info("loginSuccessHandler!");
        logger.info("***********************************************");
        response.setStatus(HttpStatus.OK.value());
        objectMapper.writeValue(response.getWriter(), "Access Granted!");
    }
    private void loginFailureHandler( HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        logger.info("***********************************************");
        logger.info("loginFailureHandler!");
        String login= request.getParameter("login");
        String pwd= request.getParameter("password");
        logger.info(login+"|"+pwd);
        logger.info("***********************************************");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());


        objectMapper.writeValue(response.getWriter(), "Access Denied : "+e.getMessage());
    }
    private void logoutSuccessHandler(  HttpServletRequest request,  HttpServletResponse response, Authentication authentication) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        objectMapper.writeValue(response.getWriter(), "Bye!");
    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/css/**","/webjars/**", "/**").permitAll()
//                .antMatchers("/admin/**").hasRole("USER")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .and()
//                .logout()
//                .permitAll();
//    }

//    @Autowired
//    private AccessDeniedHandler accessDeniedHandler;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/css/**","/webjars/**", "/").permitAll()
//                .antMatchers("/admin/**").hasRole("USER")
//                .antMatchers("/user/**").hasAnyRole("USER")
//                .and()
//                .formLogin()
//                .loginPage("/login").failureUrl("/error");

////        http.csrf().disable()
////                .authorizeRequests()
////                .antMatchers("/css/**","/webjars/**", "/").permitAll()
////                .antMatchers("/admin/**").hasAnyRole("ADMIN")
////                .antMatchers("/user/**").hasAnyRole("USER")
////                .anyRequest().authenticated()
////                .and()
////                .formLogin()
////                .loginPage("/login")
////                .permitAll()
////                .and()
////                .logout()
////                .permitAll()
////                .and()
////                .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
//   }
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                .inMemoryAuthentication()
//                .withUser("user").password("password").roles("USER");
//   }


}
