package com.erik.polls.config;

import com.erik.polls.security.UserPrincipal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

@Configuration // класс определяет бины конфигурации
@EnableJpaAuditing  // и включает аудит JPA
public class AuditingConfig {

    @Bean
    public AuditorAware<Long> auditorProvider() {
        return new SpringSecurityAuditAwareImpl();
    }
}

// класс предоставляет текущего пользователя для аудита в БД (audit - check)
class SpringSecurityAuditAwareImpl implements AuditorAware<Long> {

    //  метод, получающий информацию об аутентификации через SecurityContextHolder Spring Security
    //  проверяет, аутентифицирован ли пользователь, и возвращает идентификатор пользователя для аудита
    //  если пользователь не аутентифицирован или аутентификация анонимна, возвращает Optional.empty()
    @Override
    public Optional<Long> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null ||
                !authentication.isAuthenticated() ||
                authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        return Optional.ofNullable(userPrincipal.getId());
    }
}
