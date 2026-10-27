// UserService.java
// D. Singletary
// 11/20/25
// User service for task manager application

package edu.fscj.cen3024c.taskmanager.services;

import edu.fscj.cen3024c.taskmanager.dto.CreateUserRequestDTO;
import edu.fscj.cen3024c.taskmanager.dto.UpdateUserRequestDTO;
import edu.fscj.cen3024c.taskmanager.dto.UserDTO;
import edu.fscj.cen3024c.taskmanager.entities.Task;
import edu.fscj.cen3024c.taskmanager.entities.User;
import edu.fscj.cen3024c.taskmanager.exceptions.UserNotFoundException;
import edu.fscj.cen3024c.taskmanager.repositories.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ===== CRUD Methods with DTO conversion =====

    @Transactional(readOnly = true)
    public List<UserDTO> findAll() {
        return userRepository.findAll()
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDTO findById(Integer id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
        return convertToDTO(user);
    }

    // Helper to return raw entity (for updates/deletes)
    @Transactional(readOnly = true)
    public User findByIdEntity(Integer id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    // ===== Create / Update using request DTOs =====

    @Transactional public UserDTO createUser(CreateUserRequestDTO request) {
        String salt = generateSalt();
        String hash;
        try {
            hash = hashPassword(request.getPassword(), salt);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
        User user = new User();
        user.setUsername(request.getUsername());

        // NEW FIELDS ON ENTITY (you must add these in User.java)
        user.setSalt(salt);
        user.setPasswordHash(hash);
        User savedUser = userRepository.save(user);
        return convertToDTO(savedUser); }

    @Transactional
    public UserDTO updateUser(Integer id, UpdateUserRequestDTO request) {
        User existingUser = findByIdEntity(id);
        existingUser.setUsername(request.getUsername());
        // Always re-hash since password is required
        String salt = generateSalt();
        String hash;
        try {
            hash = hashPassword(request.getPassword(), salt);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e); }
        existingUser.setSalt(salt);
        existingUser.setPasswordHash(hash);
        User updatedUser = userRepository.save(existingUser);
        return convertToDTO(updatedUser);
    }

    public void deleteById(Integer id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException(id);
        }
        userRepository.deleteById(id);
    }

    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String hashPassword(String password, String salt) throws Exception {
        byte[] saltBytes = Base64.getDecoder().decode(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }

    // ===== Entity to DTO Conversion =====
    public UserDTO convertToDTO(User user) {
        Set<String> taskTitles = (user.getTasks() != null)
                ? user.getTasks().stream()
                .map(Task::getTitle)
                .collect(Collectors.toSet())
                : Set.of();

        return new UserDTO(
                user.getId(),
                user.getUsername(),
                taskTitles
        );
    }
}
