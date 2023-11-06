package com.erik.polls.controller;

import com.erik.polls.model.Role;
import com.erik.polls.model.RoleName;
import com.erik.polls.model.User;
import com.erik.polls.payload.ApiResponse;
import com.erik.polls.payload.JwtAuthenticationResponse;
import com.erik.polls.payload.LoginRequest;
import com.erik.polls.payload.SignUpRequest;
import com.erik.polls.repository.RoleRepository;
import com.erik.polls.repository.UserRepository;
import com.erik.polls.exception.AppException;
import com.erik.polls.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenProvider tokenProvider;


    @PostMapping("/signin")  // Аутентификация
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    // ResponseEntity<?> – метод возвращает объект типа ResponseEntity, содержащий любой тип данных.

        // Аутентификация, используя переданные имя пользователя и пароль из loginRequest.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

        // Аутентификация в контексте безопасности, чтобы показать, что пользователь успешно прошел аутентификацию.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Генерация JWT на основе аутентификации пользователя.
        String jwt = tokenProvider.generateToken(authentication);

        // JWT пользотваеля в ответе системы с кодом состояния 200.
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }

    @PostMapping("/signup")  // Регистрация
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, "Username is already taken!"),
                    HttpStatus.BAD_REQUEST);
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, "Email Address already in use!"),
                    HttpStatus.BAD_REQUEST);
        }

        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), signUpRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new AppException("User Role not set."));

        user.setRoles(Collections.singleton(userRole));
        // Каждая роль должна быть уникальной, и пользователь не должен иметь дублирующихся ролей, поэтому Set.

        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/users/{username}")
                .buildAndExpand(result.getUsername()).toUri();

        return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));
    }
}

// user.setPassword(passwordEncoder.encode(user.getPassword()));
// Кодирование пароля используется для обеспечения безопасности хранения паролей пользователей.
// Хранение паролей в открытом виде не рекомендуется, так как это может представлять угрозу безопасности, если БД станут доступными для неавторизованного доступа.
// При кодировании пароля, он преобразуется в непонятный хэш, который сложно обратно преобразовать в исходный пароль.
// Когда пользователь вводит пароль при авторизации, его введенный пароль также кодируется и сравнивается с хранимым в БД кодированным паролем.
// Это помогает сохранять безопасность паролей пользователей.