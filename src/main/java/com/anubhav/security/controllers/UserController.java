package com.anubhav.security.controllers;

import com.anubhav.security.dtos.ChangePasswordRequest;
import com.anubhav.security.dtos.ChangePasswordResponse;
import com.anubhav.security.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/users")
public class UserController
{
    @Autowired
    private IUserService userService;

    @PatchMapping
    public ResponseEntity<ChangePasswordResponse> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, Principal connectedUser)
    {
        ChangePasswordResponse response = userService.changePassword(changePasswordRequest, connectedUser);
        return ResponseEntity.ok(response);
    }
}
