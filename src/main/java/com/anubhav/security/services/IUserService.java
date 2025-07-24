package com.anubhav.security.services;

import com.anubhav.security.dtos.ChangePasswordRequest;
import com.anubhav.security.dtos.ChangePasswordResponse;

import java.security.Principal;

public interface IUserService
{
    ChangePasswordResponse changePassword(ChangePasswordRequest changePasswordRequest, Principal connectedUser);
}
