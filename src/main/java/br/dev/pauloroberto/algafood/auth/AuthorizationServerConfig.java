package br.dev.pauloroberto.algafood.auth;

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

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("algafood-web") // Password Flow
                        .secret(passwordEncoder.encode("senha123"))
                        .authorizedGrantTypes("password", "refresh_token")
                        .scopes("write", "read")
                        .accessTokenValiditySeconds(60 * 60 * 6) // Equivalente a 6 horas, sendo que o padrão são 12 horas
                        .refreshTokenValiditySeconds(60 * 60 * 24 * 7) // Equivalente a 7 dias, sendo que o padrão é 30 dias
                .and()
                    .withClient("analytics") // Authorization Code Flow // http://localhost:8081/oauth/authorize?response_type=code&client_id=analytics&state=abc&redirect_uri=http://aplicacao-cliente
                        .secret(passwordEncoder.encode("analytics123"))
                        .authorizedGrantTypes("authorization_code")
                        .scopes("read")
                        .redirectUris("http://aplicacao-cliente") // URL de callback
                .and()
                    .withClient("faturamento") // Client Credentials Flow
                        .secret(passwordEncoder.encode("faturamento123"))
                        .authorizedGrantTypes("client_credentials")
                        .scopes("write", "read")
                .and()
                    .withClient("checktoken")
                        .secret(passwordEncoder.encode("check123"));
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false); // Desabilita o reuso de refresh tokens
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
//        security.checkTokenAccess("isAuthenticated()"); // Padrão
        security.checkTokenAccess("permitAll()"); // Libera o acesso ao endpoint de validação de tokens
    }

}
