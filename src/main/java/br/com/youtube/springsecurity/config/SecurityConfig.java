package br.com.youtube.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {

        /**
         * Você pode implementar os métedos de encode e matches do PasswordEncoder
         * PasswordEncoder passwordEncoder =new PasswordEncoder(){...}
         * Ou utilizar a forma que o SpringSecurity já traz pra você
         * */
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /**
         * Responsável pela autenticação do usuário
         * **/
        auth
                .inMemoryAuthentication()
                    .passwordEncoder(passwordEncoder())
                    .withUser("caio")
                    .password(passwordEncoder().encode("pass123"))
                    .roles("USER")
                .and()
                    .passwordEncoder(passwordEncoder())
                    .withUser("admin")
                    .password(passwordEncoder().encode("admin"))
                    .roles("ADMIN")

        ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * Responsável pela configuração de permissionamento
         * */
        http
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/test")
                        .hasRole("USER")
                    .antMatchers("/test/admin")
                        .hasRole("ADMIN")
                .and().httpBasic()
        ;
    }
}
