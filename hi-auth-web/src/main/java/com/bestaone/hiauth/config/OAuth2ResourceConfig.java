package com.bestaone.hiauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import javax.annotation.Resource;


/**
 * 资源服务器
 * 这个注解就决定了这是个资源服务器。它决定了哪些资源需要什么样的权限。
 */
@Configuration
@EnableResourceServer
public class OAuth2ResourceConfig extends ResourceServerConfigurerAdapter {


    /**
     * TokenStore 的默认实现为 InMemoryTokenStore 即内存存储，对于 Client 信息，ClientDetailsService 接口负责从存储仓库中读取数据，
     * 在上面的 Demo 中默认使用的也是 InMemoryClientDetailsService 实现类
     */
    @Resource
    private TokenStore tokenStore;


    /**
     * Spring Cloud Security OAuth2 通过 DefaultTokenServices 类来完成 token 生成、过期等 OAuth2 标准规定的业务逻辑，
     * 而 DefaultTokenServices 又是通过 TokenStore 接口完成对生成数据的持久化
     * @return
     */
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore);
        return defaultTokenServices;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer config) {
        config.tokenServices(tokenServices());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/api/**")
                .and()
                .authorizeRequests()
                .antMatchers("/api/user/profile")
                .authenticated()
//              .antMatchers(HttpMethod.DELETE, "/oauth/revoke_token")
//              .authenticated()
                .antMatchers("/api/**")
                .access("#oauth2.hasScope('AUTH')");
    }

}