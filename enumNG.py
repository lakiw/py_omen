#!/usr/bin/env python3


"""
Name: enumNG
  --OMEN guess generation program
  --(O)rdered (M)arkov (EN)umerator
  -- Generates password guesses based on the conditional probabilty of passwords appearing together

Written by Matt Weir
Backend algorithm based on the work done https://github.com/RUB-SysSec/OMEN
Document describing the approach: https://hal.archives-ouvertes.fr/hal-01112124/file/omen.pdf
An even better document describing this: http://mobsec.rub.de/media/mobsec/arbeiten/2014/12/12/2013-ma-angelstorf-omen.pdf

Copyright 2021 Matt Weir

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Contact Info: cweir@vt.edu

"""


##--Including this to print error message if python < 3.0 is used
from __future__ import print_function
import sys
###--Check for python3 and error out if not--##
if sys.version_info[0] < 3:
    print("This program requires Python 3.x", file=sys.stderr)
    sys.exit(1)

import argparse
import os  ##--Used for file path information

import time ##--Used for testing

#Custom modules
from omen_cracker.input_file_io import load_rules
from omen_cracker.markov_cracker import MarkovCracker
from omen_cracker.optimizer import Optimizer
from omen_cracker.ascii_art import ascii_fail, print_banner


def parse_command_line(program_info):
    """
    Responsible for parsing the command line.

    Note: This is a fairly standardized format that I use in many of my programs

    Inputs:

        program_info: A dictionary that contains the default values of
        command line options. Results overwrite the default values and the
        dictionary is returned after this function is done.

    Returns:
        True: If the command line was parsed successfully

        False: If an error occured parsing the command line

        (Program Exits): If the --help option is specified on the command line
    """

    # Keeping the title text to be generic to make re-using code easier
    parser = argparse.ArgumentParser(
        description= program_info['name'] +
        ', version: ' +
        program_info['version']
    )

    parser.add_argument(
        '--rule',
        '-r',
        help='Name of ruleset to use. Default is ' + '[' + program_info['rule_name'] + ']',
        metavar='RULESET_NAME',
        required=False,
        default=program_info['rule_name']
    )

    parser.add_argument(
        '--session',
        '-s',
        help='Session name for saving/restarting a session. Default is ' + '[' + program_info['session_name'] + ']',
        metavar='SESSION_NAME',
        required=False,
        default=program_info['session_name']
    )

    parser.add_argument(
        '--load',
        '-l',
        help='Loads a previous guessing session',
        dest='load',
        action='store_const',
        const= not program_info['load_session'],
        default = program_info['load_session']
    )


    parser.add_argument(
        '--debug',
        '-d',
        help='Print debugging info vs password guesses',
        dest='debug',
        action='store_const',
        const= not program_info['debug']
    )

    parser.add_argument(
        '--test',
        '-t',
        help='For debugging. Allows you to type in a password and will print out parse info for it',
        dest='test',
        action='store_const',
        const = not program_info['test']
    )

    parser.add_argument(
        '--limit',
        '-n',
        help='Generate N guesses and then exit.',
        dest='limit',
        metavar='NUM_GUESSES',
        required=False,
        type=int,
        default=0
    )

    # Parse all the args and save them
    args=parser.parse_args()

    # Standard Options
    program_info['rule_name'] = args.rule
    program_info['session_name'] = args.session
    program_info['load_session'] = args.load

    # Debugging Options
    program_info['debug'] = args.debug
    program_info['limit'] = args.limit
    program_info['test'] = args.test

    # Check validity of options
    if program_info['limit'] and program_info['limit'] < 0:
        print(f"The guess --limit/-n must be a positive number. The value specified was {program_info['limit']}")
        return False

    return True


def main():
    """
    Main function, starts everything off

    Inputs:
        None

    Returns:
        None
    """

    program_info = {
        # Program and Contact Info
        'name':'Py-OMEN Guesser',
        'author':'Matt Weir',
        'contact':'cweir@vt.edu',
        'source':'https://github.com/lakiw/py_omen',

        # Program version info.
        'version': '0.2',
        # Min_rules_version is the oldest version of the trainer that can be used
        'min_rules_version': '0.1',

        # Runtime specific values, can be overriden via command line options
        # Rule Name
        'rule_name':'Default',
        # Session name for saving/restarting a session
        'session_name':'default',
        #If we are restoring a session vs starting a new one
        'load_session':False,

        # Debugging and Research Options
        # If we are doing debugging by default or not
        'debug':False,
        # Additional debuging by allowing the user to enter in passwords to be parsed
        'test':False,
        # Maximum number of guesses, if 0 it will ignore the limit.
        'limit':0
    }

    # Print out banner
    print_banner(program_info)

    # Parsing the command line
    if not parse_command_line(program_info):
        # There was a problem with the command line so exit
        print("Exiting...",file=sys.stderr)
        return

    # Set up the directory to load the ruleset from
    absolute_base_directory = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),'Rules',program_info['rule_name']
        )

    # Dictionary that will contain the grammar
    grammar = {}

    # Load the ruleset here
    print("loading ruleset: " + program_info['rule_name'],file=sys.stderr)
    if not load_rules(absolute_base_directory, grammar, min_version=program_info['min_rules_version']):
        print("Error reading the ruleset, exiting", file=sys.stderr)
        ascii_fail()
        return

    # Initialize the TMTO optimizer
    optimizer = Optimizer(max_length = 4)

    # Initialize the Markov Cracker
    try:
        cracker = MarkovCracker(
            grammar = grammar,
            version = program_info['version'],
            base_directory = os.path.dirname(os.path.realpath(__file__)),
            session_name = program_info['session_name'],
            rule_name = program_info['rule_name'],
            uuid = grammar['uuid'],
            optimizer = optimizer,
            restore = program_info['load_session'],
            )
    except:
        print("Error loading the save file, exiting", file=sys.stderr)
        ascii_fail()
        return

    # If there is debugging going on for parsing user supplied strings
    if program_info['test']:
        while True:
            guess = input("Enter string to parse:")
            cracker.parse_input(guess)

    # Start generating guesses
    print("--Starting to generate guesses-- ",file=sys.stderr)
    try:
        start_time = time.time()
        num_guesses = 0

        guess, level = cracker.next_guess()
        while guess is not None:
            num_guesses += 1
            if program_info['debug']:
                if num_guesses % 100000 == 0:
                    elapsed_time = time.time() - start_time
                    print()
                    print("guesses: " + str(num_guesses))
                    print("level: " + str(level))
                    print("guesses a second: " + str(num_guesses / elapsed_time))

            else:
                if num_guesses % 1000000 == 0:
                    cracker.save_session()

                print(guess)

                # These lines are for debugging
                #guess = guess + '\n'
                #guess = guess.encode('utf-8')
                #sys.stdout.buffer.write(guess)
                #sys.stdout.flush()
                #input("hit enter")

            if program_info['limit'] > 0 and num_guesses >= program_info['limit']:
                break

            guess, level = cracker.next_guess()

    except (KeyboardInterrupt, BrokenPipeError):
        print("Halting guess generation based on Ctrl-C being detected",file=sys.stderr)
        cracker.save_session()

    print('', file=sys.stderr)
    print("--Done generating guesses-- ",file=sys.stderr)


if __name__ == "__main__":
    main()
