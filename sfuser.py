#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfuser
# Purpose:      Manage spiderfoot users
#
# Author:      Kodama Chameleon <contact@kodamachameleon.com>
#
# Created:     26/07/2024
# Copyright:   (c) Kodama Chameleon 2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import hashlib
import re
import getpass

from spiderfoot import SpiderFootHelpers

def create_ha1(username, realm, password):
    """Generate a hash for the given password."""
    ha1_str = f"{username}:{realm}:{password}"
    return hashlib.md5(ha1_str.encode()).hexdigest()

def get_valid_username(prompt="Enter username: "):
    """
    Prompts the user for a username, validates its formatting, and returns the username if valid.
    
    :param prompt: The prompt message to display to the user.
    :return: Validated username string.
    :raises ValueError: If the username is invalid.
    """
    while True:
        username = input(prompt).strip()
        
        # Check if username is not empty
        if not username:
            print("Username cannot be empty. Please try again.")
            continue
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9._-]{3,30}$', username):
            print("Invalid username. It should be 3-30 characters long and may contain letters, numbers, periods, underscores, or hyphens.")
            continue
        
        # If all checks pass, return the username
        return username

def get_valid_password(prompt="Enter password: ", confirm_prompt="Confirm password: "):
    """
    Prompts the user for a password, hides the input, confirms the password, and validates its formatting.
    
    :param prompt: The prompt message to display to the user for entering the password.
    :param confirm_prompt: The prompt message to display to the user for confirming the password.
    :return: Validated password string.
    :raises ValueError: If the password is invalid or does not match confirmation.
    """
    while True:
        # Get and confirm password
        password = getpass.getpass(prompt)
        confirm_password = getpass.getpass(confirm_prompt)
        
        # Check if passwords match
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        
        # Validate password format
        if not re.match(r'^[a-zA-Z0-9@#$%^&+=]{8,20}$', password):
            print("Invalid password. It should be 8-20 characters long and may include letters, numbers, and special characters (@, #, $, %, ^, &, +, =).")
            continue
        
        # If all checks pass, return the password
        return password

if __name__ == "__main__":

    # Storing a new user
    def store_user(username, realm, password, passwd_file):

        # Read current file
        user_list = {}
        with open(passwd_file, 'r') as f:
            secrets = f.read().split("\n")
            
            for secret in secrets:
                try:
                    u, r, ha1 = secret.split(":")
                    user_list[u] = {
                        "realm": r,
                        "ha1": ha1
                    }
                except ValueError:
                    # TODO: Add logger warning
                    pass
        
        # Update user list
        user_list[username] = {
            "realm": realm,
            "ha1": create_ha1(username, realm, password)
        }

        # Save new list
        with open(passwd_file, 'w') as f:
            for key, value in user_list.items():
                f.write(f"{key}:{value['realm']}:{value['ha1']}\n")

    username = get_valid_username()
    password = get_valid_password()
    passwd_file = SpiderFootHelpers.dataPath() + 'passwd'
    realm = '127.0.0.1'

    store_user(username, realm, password, passwd_file=passwd_file)