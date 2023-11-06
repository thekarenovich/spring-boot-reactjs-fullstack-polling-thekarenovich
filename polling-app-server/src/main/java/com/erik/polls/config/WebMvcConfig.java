package com.erik.polls.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    // WebMvcConfigurer – интерфейс, предоставляющий методы для настройки WebMVC

    private final long MAX_AGE_SECS = 3600;

    @Value("${app.cors.allowedOrigins}")
    private String[] allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")  // все эндпоинты подпадают под эти настройки CORS
                .allowedOrigins(allowedOrigins)  // разрешенные источники для CORS запросов, а именно: http://localhost:3000
                .allowedMethods("HEAD", "OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE")  // разрешенные HTTP-методы для CORS
                .maxAge(MAX_AGE_SECS); // максимальное время кэширования для предопределения CORS в секундах
    }
}
