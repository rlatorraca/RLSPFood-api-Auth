package ca.com.rlsp.rlspfood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    public static final String WRITE = "write";
    public static final String PASSWORD = "password";
    public static final String READ = "read";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATION_CODE = "authorization_code";

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    /**
     *  Usado para usar o Redis No-SQL para armazenar os tokens
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;
     */


    /**
     * Tem a configuracao de todos os Tokens Granter (Authorization Code, Implicit, Cloud Credentials, etc) + PKCE
     * @param endpoints
     * @return
     */
    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }

    //@formatter:off

    /**
     * Configura o Cliente para o Fluxo Password Credentials
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                // Clients => Password Credentials
                    .withClient("rlspfood-web") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("123"))
                    .authorizedGrantTypes(PASSWORD, REFRESH_TOKEN) // Fluxo Password Credentials
                    .scopes(WRITE, READ)
                    .accessTokenValiditySeconds(60 * 60 * 6) // 60 sec * 60 min * 6h = 6hours (Access Token working time)
                    .refreshTokenValiditySeconds(60 * 60 * 24 * 2) // 60 sec * 60 min * 24h * 2d = 2 dias (Refresh Token working time)
                .and()
                    .withClient("rlspfood-mobile") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("321"))
                    .authorizedGrantTypes(PASSWORD, REFRESH_TOKEN) // Fluxo Password Credentials
                    .scopes(WRITE, READ)

                // Client Crendentials
                .and()
                    .withClient("billing-token") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("billing321"))
                    .authorizedGrantTypes(CLIENT_CREDENTIALS) // Fluxo Password Credentials
                    .scopes(WRITE, READ)

                // Clients => Authorization Code
                // Simple => http://auth.rlspfood.local:8082/oauth/authorize?response_type=code&client_id=food-analytics&state=R1SP&redirect_uri=http://www.foodanalytics.local:8084
                // PCKE Plain=> http://auth.rlspfood.local:8082/oauth/authorize?response_type=code&client_id=food-analytics&state=R1SP&redirect_uri=http://www.foodanalytics.local:8084&code_challenge=test123&code_challenge_method=plain
                // PCKE SHA256 => http://auth.rlspfood.local:8082/oauth/authorize?response_type=code&client_id=food-analytics&state=R1SP&redirect_uri=http://www.foodanalytics.local:8084&code_challenge=3ZNmLe2fEZNLrIBkxw-KE2AA7itu41zve1stpJ49ki0&code_challenge_method=s256
                // - code verifier(sha256 de 43 a 128 bits, sem parenteses) : R0dr1g0L4t0rr4c4D3S4nct1sP1r3s986532875421784512235689
                // - code challenge : base64url(sha 256 (code verifier)) : 3ZNmLe2fEZNLrIBkxw-KE2AA7itu41zve1stpJ49ki0
                // => Online PKCE Generator Tool : https://tonyxu-io.github.io/pkce-generator/
                .and()
                    .withClient("food-analytics") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("analytics321"))
                    .authorizedGrantTypes(AUTHORIZATION_CODE) // Fluxo Password Credentials
                    .scopes(WRITE, READ)
                    .redirectUris("http://client-app", "http://www.foodanalytics.local:8084")

                // Verify Token validate
                .and()
                    .withClient("check-token") // Identificacao do Cliente (quem faz requisicao do Token  para o Authorization Server)
                    .secret(passwordEncoder.encode("check321"))

                // Implicti Grant Type >> DON'T USE << - Just for testing
                // http://auth.rlspfood.local:8082/oauth/authorize?response_type=token&client_id=testImplictGrantType&state=R1SP&redirect_uri=http://test.implicit.grant.type
                .and()
                    .withClient("testImplictGrantType")
                .authorizedGrantTypes("implicit")
                .scopes(WRITE, READ)
                    .redirectUris("http://test.implicit.grant.type");
    }
    //@formatter:on


    /**
     * Token Introspection (Check Token Validate)
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .allowFormAuthenticationForClients() // aceita todas formas de autenticacao com ou sem client + secret
                .checkTokenAccess("isAuthenticated()"); // para acessar o recurso de /check_token deve estar autenticado
        //security.checkTokenAccess("permitAll"); // Permite acesso sem autenticacao
    }

    /**
     *  Necessario APENAS para o Grant de Fluxo Password Credentials (precis do authentication manager)
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoint) throws Exception{
        endpoint
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .accessTokenConverter(jwtAccessTokenConverter())
                // .tokenStore(getRedisTokenStore()) ==> Usado para usar o Redis No-SQL para armazenar os tokens
                .tokenGranter(tokenGranter(endpoint))
                .reuseRefreshTokens(false); // Fazer a renovacao do Refresh Token quando expirer (nao usar reutilizacao)

    }


    /**
     * Usado para usar o Redis No-SQL para armazenar os tokens
     * @return
    private RedisTokenStore getRedisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
     */

    /**
     * Implementa Chave SIMETRICA para o HMAC SHA-256
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey("R0dr1g0L4t0rr4c4D3SP1R3SR0dr1g0L4t0rr4c4D3SP1R3SR0dr1g0L4t0rr4c4D3SP1R3S");

        return jwtAccessTokenConverter;
    }

}
