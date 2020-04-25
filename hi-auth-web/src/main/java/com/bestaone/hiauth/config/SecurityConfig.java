package com.bestaone.hiauth.config;

import com.bestaone.hiauth.config.smscode.SmsCodeAuthenticationSecurityConfig;
import com.bestaone.hiauth.config.validatecode.ValidateCodeSecurityConfig;
import com.bestaone.hiauth.service.impl.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * Security 配置类 说明登录方式、登录页面、哪个url需要认证、注入登录失败/成功过滤器
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    /**
     * 重写PasswordEncoder 接口中的方法，实例化加密策略
     * @return 返回 BCrypt 加密策略
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig(){
        return new SmsCodeAuthenticationSecurityConfig();
    }

    @Bean
    public ValidateCodeSecurityConfig validateCodeSecurityConfig(){
        return new ValidateCodeSecurityConfig();
    }

    @Bean
    public UserDetailsService simpleUserDetailsService(){
        return new UserDetailsServiceImpl();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(simpleUserDetailsService());
    }


    /**
     * 认证管理
     *
     * @return 认证管理对象
     * @throws Exception 认证异常信息
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //在UsernamePasswordAuthenticationFilter 过滤器前 加一个过滤器 来搞验证码
      //  http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
        http.userDetailsService(userDetailsService());
        http.csrf().disable();

        //开启短信登陆功能
        http.apply(smsCodeAuthenticationSecurityConfig());
        //开启验证码功能
        http.apply(validateCodeSecurityConfig());

        http.formLogin()//表单登录 方式
                .loginPage("/signin")
                .loginProcessingUrl("/signin/form/account") //登录需要经过的url请求
                .defaultSuccessUrl("/index").and()
                 //.successHandler(new MyAuthenticationSuccessHandler())//.defaultSuccessUrl("/index")
                .logout().logoutUrl("/signout")
                .logoutSuccessUrl("/signin").and()
                .authorizeRequests() //请求授权
                .antMatchers("/signin","/signin/form/tel","/code/image","/code/mobile","/static/**").permitAll() //不需要权限认证的url
                 //这个地址由ApiAuthFilter过滤，不需要登录拦截
                .antMatchers("/api/**")
                .permitAll()
                 //这个地址由AuthorizationServer使用，不需要登录拦截
                .antMatchers("/oauth/**")
                .permitAll()
                 //这个地址开放地址
                .antMatchers("/public/**")
                .permitAll()
                .antMatchers("/user/**")
                .hasAnyRole("USER","ADMIN")
                .anyRequest()//其他任意请求需要登录(任何请求)
                .authenticated();//需要身份认证
               // .and().csrf().disable()//关闭跨站请求防护
               // .logout() //默认注销地址：/logout
               // .logoutSuccessUrl("/authentication/require");//注销之后 跳转的页面


    }

}