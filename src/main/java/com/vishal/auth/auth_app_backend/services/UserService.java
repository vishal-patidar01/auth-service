package com.vishal.auth.auth_app_backend.services;

import com.vishal.auth.auth_app_backend.dtos.UserDto;
import org.springframework.stereotype.Service;

public interface UserService {

    UserDto createUser(UserDto userDto);

    UserDto getUserByEmail(String email);

    UserDto updateUser(UserDto userDto, String userId);

    void deleteUser(String userId);

    UserDto getUserById(String userId);

    Iterable<UserDto> getAllUsers();
}
