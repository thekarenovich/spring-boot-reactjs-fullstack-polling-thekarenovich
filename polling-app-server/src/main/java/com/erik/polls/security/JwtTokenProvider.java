package com.erik.polls.security;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    // generateToken() используется для генерации нового токена JWT на основе объекта
    // Он извлекает информацию о пользователе (в данном случае, идентификатор пользователя) из объекта Authentication
    // Затем создается текущая дата (now) и дата истечения срока действия токена (expiryDate), которая вычисляется путем добавления значения jwtExpirationInMs к текущей дате
    // Затем используется Jwts.builder() для создания нового JWT, устанавливаются полезные данные,
    // такие как идентификатор пользователя, дата выпуска (в настоящее время) и дата истечения срока действия
    // Далее токен подписывается с помощью алгоритма подписи HS512 и секретного ключа (jwtSecret)
    // Наконец, с использованием метода compact() полученное JWT преобразуется в строку и возвращается
    public String generateToken(Authentication authentication) {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    // getUserIdFromJWT() используется для извлечения идентификатора пользователя из токена JWT
    // Он разбирает переданный токен, проверяет его подпись с помощью секретного ключа jwtSecret и извлекает полезные данные (Claims)
    // Затем метод возвращает извлеченный идентификатор пользователя, преобразованный в тип Long
    public Long getUserIdFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    // validateToken() используется для проверки действительности токена JWT
    // Он пытается разобрать и проверить подпись токена с помощью секретного ключа jwtSecret
    // Если разбор или проверка не удается, выбрасывается соответствующее исключение и всплывает соответствующее сообщение об ошибке
    // Если токен проходит проверку успешно, метод возвращает true. Если возникает ошибка, он возвращает false.
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }
}
