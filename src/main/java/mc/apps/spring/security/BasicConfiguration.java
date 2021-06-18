package mc.apps.spring.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class BasicConfiguration extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(BasicConfiguration.class);

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth
                .inMemoryAuthentication()
                .withUser("mc")
                .password(encoder.encode("123"))
                .roles("USER")
                .and()
                .withUser("mc2")
                .password(encoder.encode("admin"))
                .roles("USER", "ADMIN");
    }

    @Bean
    public LogoutHandler logoutHandler() {
        return new CustomLogoutHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin/**")
                .authenticated()
                .antMatchers("/css/**","/webjars/**","/images/**", "/**").permitAll()
                .and()
                // login
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .loginProcessingUrl("/login")
                .usernameParameter("login")
                .passwordParameter("password")

                // logout
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                // .logoutSuccessUrl("/")
                .addLogoutHandler(logoutHandler())
                .logoutSuccessHandler(this::logoutSuccessHandler);

                // .httpBasic();
    }

    private void logoutSuccessHandler(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.sendRedirect("/");  // => .logoutSuccessUrl("/")

        logger.info("*********************************************");
        logger.info("LogoutSuccessHandler : bye!");
        logger.info("*********************************************");
    }

    @Service
    public class CustomLogoutHandler implements LogoutHandler {
       // private final UserCache userCache;
        //        public CustomLogoutHandler(UserCache userCache) {
        //            this.userCache = userCache;
        //        }
        @Override
        public void logout(HttpServletRequest request, HttpServletResponse response,
                           Authentication authentication) {
            //            String userName = UserUtils.getAuthenticatedUserName();
            //            userCache.evictUser(userName);
            String refererUrl = request.getHeader("Referer");
            logger.info("*********************************************");
            logger.info("LogoutHandler : "+refererUrl);
            logger.info("*********************************************");
        }
    }
}
