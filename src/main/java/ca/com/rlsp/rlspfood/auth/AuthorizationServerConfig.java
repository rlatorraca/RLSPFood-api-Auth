package ca.com.rlsp.rlspfood.auth;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    // @formatter:off
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .mvcMatcher("/messages/**")
//                .authorizeRequests()
//                .mvcMatchers("/messages/**").access("hasAuthority('SCOPE_message.read')")
//                .and()
//                .oauth2ResourceServer()
//                .jwt();
//    }
    // @formatter:on

}
