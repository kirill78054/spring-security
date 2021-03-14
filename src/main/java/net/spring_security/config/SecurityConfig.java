package net.spring_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() //- механизм от csrf угрозы
                .authorizeRequests() //-  к каким страницам человек имеет/не имеет доступ
                .antMatchers("/").permitAll() //- указывает на какие url пользователь имеет доступ
                .anyRequest()
                .authenticated() //- на все остальные,  запросы пользователь должен быть аутефицирован
                .and()
                .formLogin() //- для логина используй форм логин, она находится по этой ссылке и по дефолту после редиректню сюда
                .loginPage("/auth/login").permitAll()
                .defaultSuccessUrl("/auth/success")
                .and()
                .logout() //- по умолчанию идет GET, но в документации указанно что это небезопастно поэтому настраеваем POST
                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST")) //- по нужному запросу
                .invalidateHttpSession(true) //- при логауте инвалидируй мою сессию которая есть
                .clearAuthentication(true) //- очисть мне аутификацию, в которой содержатся мои данные
                .deleteCookies("JSESSIONID") //- удали куки
                .logoutSuccessUrl("/auth/login"); //- перебрось на нужную страницу
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder(12);
    }

    @Bean
    protected DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }
}
