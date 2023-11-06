package com.erik.polls.config;

import com.erik.polls.security.CustomUserDetailsService;
import com.erik.polls.security.JwtAuthenticationEntryPoint;
import com.erik.polls.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration  // Указывает, что это класс для конфигурации бинов в Spring
@EnableWebSecurity  // Активирует безопасность для веб-приложения
@EnableGlobalMethodSecurity(  // Разрешает использование различных аннотаций безопасности на уровне методов
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // WebSecurityConfigurerAdapter - это базовый класс в Spring Security, который позволяет настраивать правила безопасности для веб-приложения
    // Реализует WebMvcConfigurer (интерфейс, предоставляющий методы для настройки WebMVC)

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Конфигурация правил безопасности HTTP, включая CORS, CSRF, управление исключениями и сессиями
        // Разрешения доступа к различным URL путем использования antMatchers
        http
                .cors()  // включает поддержку Cross-Origin Resource Sharing, чтобы разрешить запросы от других доменов
                .and()
                .csrf()
                .disable()  // отключает CSRF (межсайтовую подделку запроса) защиту
                .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)  // устанавливает обработчик аутентификации для неаутентифицированных запросов
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // настраивает управление сеансами и устанавливает политику "без состояния" (STATELESS), что означает, что сеансы не будут создаваться и использоваться
                .and()
                .authorizeRequests()
                .antMatchers("/",
                        "/favicon.ico",
                        "/**/*.png",
                        "/**/*.gif",
                        "/**/*.svg",
                        "/**/*.jpg",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js")  // все эти пути разрешены без аутентификации (доступно для всех)
                .permitAll()
                .antMatchers("/api/auth/**")  // все пути, начинающиеся с /api/auth/, доступны без аутентификации
                .permitAll()
                .antMatchers("/api/user/checkUsernameAvailability", "/api/user/checkEmailAvailability")  // указанные пути доступны без аутентификации.
                .permitAll()
                .antMatchers(HttpMethod.GET, "/api/polls/**", "/api/users/**")  // все GET-запросы к путям, начинающимся с /api/polls/ или /api/users/, доступны без аутентификации
                .permitAll()
                .anyRequest()  // все остальные запросы требуют аутентификации пользователя
                .authenticated();

        // Установка фильтра безопасности JwtAuthenticationFilter перед стандартным UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }
}

