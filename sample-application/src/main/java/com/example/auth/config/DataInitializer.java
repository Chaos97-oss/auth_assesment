package com.example.auth.config;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (!userRepository.existsByUsername("admin")) {
                User admin = new User("admin", passwordEncoder.encode("admin123"), Set.of("ADMIN", "USER"));
                userRepository.save(admin);
            }
            if (!userRepository.existsByUsername("user")) {
                User user = new User("user", passwordEncoder.encode("user123"), Set.of("USER"));
                userRepository.save(user);
            }
        };
    }
}
