package com.bestaone.hiauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.sql.DataSource;

/**
 * 认证服务器(验证服务器配置)
 * 使用 @EnableAuthorizationServer 来配置授权服务机制，并继承 AuthorizationServerConfigurerAdapter 该类重写 configure 方法定义授权服务器策略
 */
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private Environment env;

    @Resource
    private AuthenticationManager authenticationManager;

    /**
     * 自定义授权页面
     */
    @Autowired
    private AuthorizationEndpoint authorizationEndpoint;

    @PostConstruct
    public void init() {
        authorizationEndpoint.setUserApprovalPage("forward:/oauth/my_approval_page");
        authorizationEndpoint.setErrorPage("forward:/oauth/my_error_page");
    }


    /*@Bean
    RedisTokenStore redisTokenStore(){
        return new RedisTokenStore(redisConnectionFactory);
    }*/

    /**
     *  @Bean // 声明 ClientDetails实现
     *     public ClientDetailsService clientDetails() {
     *         return new JdbcClientDetailsService(dataSource);
     *     }
     */

    /**
     * <p>注意，自定义TokenServices的时候，需要设置@Primary，否则报错，</p>
     * @return
     */
    /*@Primary
    @Bean
    public DefaultTokenServices defaultTokenServices(){
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(redisTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(clientDetails());
        tokenServices.setAccessTokenValiditySeconds(60*60*12); // token有效期自定义设置，默认12小时
        tokenServices.setRefreshTokenValiditySeconds(60 * 60 * 24 * 7);//默认30天，这里修改
        return tokenServices;
    }*/

    @Bean
    public DataSource dataSource() {
        final DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(env.getProperty("spring.datasource.driver-class-name"));
        dataSource.setUrl(env.getProperty("spring.datasource.url"));
        dataSource.setUsername(env.getProperty("spring.datasource.username"));
        dataSource.setPassword(env.getProperty("spring.datasource.password"));
        return dataSource;
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource());
    }

    @Bean
    protected AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(dataSource());
    }

    /**
     *
     * // 声明TokenStore实现
     * 在数据库中存储token
     * InMemoryTokenStore：默认采用该实现，将令牌信息保存在内存中，易于调试
     * JdbcTokenStore：令牌会被保存近关系型数据库，可以在不同服务器之间共享令牌
     * JwtTokenStore：使用 JWT 方式保存令牌，它不需要进行存储，但是它撤销一个已经授权令牌会非常困难，所以通常用来处理一个生命周期较短的令牌以及撤销刷新令牌
     *
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource());
    }


    /**
     * 客户端配置（给谁发令牌）
        配置客户端详情（Client Details）
         ClientDetailsServiceConfigurer 能够使用内存或 JDBC 方式实现获取已注册的客户端详情，有几个重要的属性：
        clientId：客户端标识 ID
        secret：客户端安全码
        scope：客户端访问范围，默认为空则拥有全部范围
        authorizedGrantTypes：客户端使用的授权类型，默认为空
        authorities：客户端可使用的权限
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // oauth_client_details
        clients.jdbc(dataSource());


        /*clients.inMemory().withClient("internet_plus") // 测试用，将客户端信息存储在内存中
                .withClient("client")       // client_id
                .secret("internet_plus") // client_secret
                //有效时间 2小时
                .accessTokenValiditySeconds(72000)
                // 该client允许的授权类型:密码授权模式和刷新令牌
                .authorizedGrantTypes("refresh_token","password")
                // // 允许的授权范围
                .scopes( "all").
                .autoApprove(true); */ //登录后绕过批准询问(/oauth/confirm_access)
    }


    /**
     *
     *  //告诉Spring Security Token的生成方式
     *
     * 授权是使用 AuthorizationEndpoint 这个端点来进行控制的，使用 AuthorizationServerEndpointsConfigurer
     * 这个对象实例来进行配置，默认是支持除了密码授权外所有标准授权类型，它可配置以下属性：
     * authenticationManager：认证管理器，当你选择了资源所有者密码（password）授权类型的时候，请设置这个属性注入一个 AuthenticationManager 对象
     * userDetailsService：可定义自己的 UserDetailsService 接口实现
     * authorizationCodeServices：用来设置收取码服务的（即 AuthorizationCodeServices 的实例对象），主要用于 "authorization_code" 授权码类型模式
     * implicitGrantService：这个属性用于设置隐式授权模式，用来管理隐式授权模式的状态
     * tokenGranter：完全自定义授权服务实现（TokenGranter 接口实现），只有当标准的四种授权模式已无法满足需求时
     *
     *
     * 配置授权端点 URL（Endpoint URLs）
     * AuthorizationServerEndpointsConfigurer 配置对象有一个 pathMapping() 方法用来配置端点的 URL，它有两个参数：
     * 参数一：端点 URL 默认链接
     * 参数二：替代的 URL 链接
     * 下面是一些默认的端点 URL：
     * /oauth/authorize：授权端点
     * /oauth/token：令牌端点
     * /oauth/confirm_access：用户确认授权提交端点
     * /oauth/error：授权服务错误信息端点
     * /oauth/check_token：用于资源服务访问的令牌解析端点
     * /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话
     * 授权端点的 URL 应该被 Spring Security 保护起来只供授权用户访问
     *
     * 认证服务器配置用户加载规则实现
     * AuthorizationEndpoint 支持的授权类型可以通过 AuthorizationServerEndpointsConfigurer 进行配置。 默认情况下，除了密码之外，所有的授权类型都是受支持的（请参阅下面的关于如何打开的细节）。 以下属性影响授权类型：
     * authenticationManager：通过注入 AuthenticationManager 来开启密码授权。
     * userDetailsService：如果你注入一个 UserDetailsService，或者全局地配置了一个UserDetailsService（例如在 GlobalAuthenticationManagerConfigurer中），那么刷新令牌授权将包含对用户详细信息的检查，以确保该帐户仍然是活动的
     * authorizationCodeServices：为授权代码授权定义授权代码服务（AuthorizationCodeServices 的实例）。
     * implicitGrantService：在 imlpicit 授权期间管理状态。
     * tokenGranter：TokenGranter（完全控制授予和忽略上面的其他属性）
     * @param endpoints
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        // oauth_approvals
        endpoints.approvalStore(approvalStore());
        // oauth_code
        endpoints.authorizationCodeServices(authorizationCodeServices());
        // oauth_access_token & oauth_refresh_token
        endpoints.tokenStore(tokenStore());
        // 支持password grant type
        endpoints.authenticationManager(authenticationManager);

        //
        /**
         * 配置端点的 URL
         * 默认逻辑/oauth/confirm_access，让他重定向到我们自己的路径，然后进行个性哈
         *  AuthorizationServerEndpointsConfigurer 有一个 pathMapping() 方法。它有两个参数：
         * 端点的默认（框架实现）URL 路径
         * 必需的自定义路径（以“/”开头）
         * 框架提供的 URL 路径是/oauth/authorize（授权端点），/oauth/token（令牌端点），/oauth/confirm_access（用户在这里发布授权批准），/oauth/error（用于在授权服务器上渲染错误），/oauth/check_token（由资源服务器用来解码访问令牌）和/oauth/token_key（如果使用JWT令牌，公开密钥用于令牌验证）。
         * 注： 授权端点/oauth/authorize（或其映射替代）应该使用Spring Security进行保护，以便只有通过身份验证的用户才能访问。
         * 例如使用标准的 Spring Security WebSecurityConfigurer：
         */
        //endpoints.pathMapping("/oauth/confirm_access", "/token/confirm_access");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        //oauthServer.tokenKeyAccess("permitAll()");

        //允许所有资源服务器访问公钥端点（/oauth/token_key）
        //只允许验证用户访问令牌解析端点（/oauth/check_token）
        //oauthServer .checkTokenAccess("isAuthenticated()");

        // 允许客户端发送表单来进行权限认证来获取令牌
        oauthServer.allowFormAuthenticationForClients();
    }

}