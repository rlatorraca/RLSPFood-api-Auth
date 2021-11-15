package ca.com.rlsp.rlspfood.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;


@Validated
@Component
@ConfigurationProperties("rlspfood.jwt.keystore")
public class RlspFoodJwtKeyStoreProperties {

    @NotBlank
    private String path;

    @NotBlank
    private String password;

    @NotBlank
    private String keyPairAlias;


    // GETTERs and SETTERs
    public String getPath() {
        return path;
    }

    public String getPassword() {
        return password;
    }

    public String getKeyPairAlias() {
        return keyPairAlias;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setKeyPairAlias(String keyPairAlias) {
        this.keyPairAlias = keyPairAlias;
    }
}
