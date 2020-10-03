#!/usr/bin/python

# ****************************************************************************
# Purpose:
# Get and validate input from a user.
# ****************************************************************************
# Creator:          Tim Lansing
# Creation Date:    12 September 2020
# ****************************************************************************
# Notes:
# This script was created using:
#     - Python 3.8.2.
# ****************************************************************************
# History:
# 9 September 2020 - Tim Lansing - Initial creation.
# ****************************************************************************

# Imports
import os

# Declare global variables.
# None at this time.


def clear_screen():
    '''
    This clears the screens for most Windows and Linux systems. If unable to clear screen then does nothing.
    :return: None.
    '''
    failure_code = os.system('cls')
    if failure_code:
        failure_code = os.system('clear')
        if failure_code:
            print("", end='')


def ask_yes_no_question(question):
    '''
    This asks a yes or no question to the user.
    :param question: Array of strings including the question to be asked.
    :return: 'y' or 'n' for the 'yes' or 'no response made by the user.
    '''

    user_input = ""
    while "y" != user_input and "n" != user_input:
        for line in question:
            print(line)
        print("")
        print("Enter: 'y' for yes or 'n' for no.")
        print("")
        user_input = input("Selection: ")
        if "n" != user_input and "y" != user_input:
            clear_screen()
            print("Sorry, '" + user_input + "' is not a valid response. 'y' or 'n' must be entered.")
            print("")
    return user_input
