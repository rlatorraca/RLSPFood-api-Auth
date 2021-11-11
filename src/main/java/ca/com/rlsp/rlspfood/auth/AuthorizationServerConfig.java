package ca.com.rlsp.rlspfood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    public static final String WRITE = "write";
    public static final String PASSWORD = "password";
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    //@formatter:off

    /**
     * Configura o Cliente para o Fluxo Password Credentials
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("rlspfood-web") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes(PASSWORD, "refresh_token") // Fluxo Password Credentials
                    .scopes(WRITE, "read")
                    .accessTokenValiditySeconds(60 * 60 * 6) // 60 sec * 60 min * 6h = 6hours (Access Token working time)
                    .refreshTokenValiditySeconds(60 * 60 * 24 * 2) // 60 sec * 60 min * 24h * 2d = 2 dias (Refresh Token working time)
                .and()
                    .withClient("rlspfood-mobile") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("321"))
                    .authorizedGrantTypes(PASSWORD, "refresh_token") // Fluxo Password Credentials
                    .scopes(WRITE, "read")
                .and()
                    .withClient("check-token") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("check321"))
                    .authorizedGrantTypes(PASSWORD) // Fluxo Password Credentials
                    .scopes(WRITE, "read");
    }
    //@formatter:on


    /**
     * Token Introspection (Check Token Validate)
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()"); // para acessar o recurso de /check_token deve estar autenticado
        //security.checkTokenAccess("permitAll"); // Permite acesso sem autenticacao
    }

    /**
     *  Necessario APENAS para o Grant de Fluxo Password Credentials (precis do authentication manager)
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoint) throws Exception{
        endpoint
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
                //.reuseRefreshTokens(false); // Fazer a renovacao do Refresh Token quando expirer (nao usar reutilizacao)

    }

}
