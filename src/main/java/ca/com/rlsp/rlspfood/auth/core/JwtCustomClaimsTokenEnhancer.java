package ca.com.rlsp.rlspfood.auth.core;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {
    /**
     * Add Claims (attributes) in the token
     * @param accessToken
     * @param authentication
     * @return accessToken
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        if(authentication.getPrincipal() instanceof AuthenticationUser) {
            var authUser = (AuthenticationUser) authentication.getPrincipal();

            var info = new HashMap<String, Object>();
            info.put("full_name", authUser.getFullName());
            info.put("user_id", authUser.getId());

            var oAuth2AccessToken = (DefaultOAuth2AccessToken) accessToken;
            oAuth2AccessToken.setAdditionalInformation(info);
        }

        return accessToken;
    }
}
