#!/usr/bin/env python3


"""
Name: createNG
  --OMEN training program
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
import uuid  ##--Used to uniquely identify the ruleset. Used for saving/restaring cracking sessions

#Custom modules
from omen_trainer.common_file_io import detect_file_encoding
from omen_trainer.alphabet_lookup import AlphabetLookup
from omen_trainer.trainer_file_io import TrainerFileIO
from omen_trainer.output_file_io import save_rules_to_disk
from omen_trainer.alphabet_generator import AlphabetGenerator
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

    # Input File options
    group = parser.add_argument_group('Input Files')

    group.add_argument(
        '--training',
        '-t',
        help='The training set of passwords to train from.',
        metavar='FILENAME',
        required=True
    )

    group.add_argument(
        '--encoding',
        '-e',
        help='File encoding used to read the input training set. If not specified autodetect is used',
        metavar='ENCODING',
        required=False
    )

    group.add_argument(
        '--alphabet',
        '-a',
        help='Dynamically learn alphabet from training set vs using the default [a-zA-Z0-9!.*@-_$#<?]. ' +
            'Note, the size of alphabet will get up to the N most common characters. Higher values can slow down the cracker ' +
            'and increase memory requirements',
        type=int,
        metavar='SIZE_OF_ALPHABET',
        required=False
    )

    # Output file options
    group = parser.add_argument_group('Output Options')
    group.add_argument(
        '--rule',
        '-r',
        help='Name of generated ruleset. Default is ' +
            '[' + program_info['rule_name'] + ']',
        metavar='RULESET_NAME',
        required=False,
        default=program_info['rule_name']
    )

    # Markov grammar options
    group = parser.add_argument_group('nGram Calculation')
    group.add_argument(
        '--ngram',
        '-n',
        help='Changes the size of the nGram n ' +
            '(possible values="2", "3", "4") Default is [' + str(program_info['ngram']) + ']',
        metavar='INT',
        required=False,
        type=int,
        choices=range(2,6),
        default=program_info['ngram']
    )

    # Parse all the args and save them
    args=parser.parse_args()

    # Input File options
    program_info['training_file'] = args.training
    program_info['encoding'] = args.encoding

    # Alphabet options
    program_info['learn_alphabet'] = args.alphabet

    # Sanity check of values
    if args.alphabet and args.alphabet < 10:
        print("Minimum alphabet size is 10 because based on past experience anything less than that is probably a typo. If this is a problem please post on the github site")
        return False

    # Output file options
    program_info['rule_name'] = args.rule

    # Markov grammar options
    program_info['ngram'] = args.ngram

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
        'name':'Py-OMEN Trainer',
        'author':'Matt Weir',
        'contact':'cweir@vt.edu',
        'source':'https://github.com/lakiw/py_omen',

        # Program version info.
        'version': '0.2',

        # Training set options
        'training_file':None,
        'encoding':None,

        # Output options
        'rule_name':'Default',

        # nGram Calculation
        'ngram':4,
        'max_level':10,
        'alphabet':'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!.*@-_$#<?',
        'learn_alphabet':None,
        'smooting':None,

        # Options added for this version of OMEN
        'max_length':20,
    }

    # Print out banner
    print_banner(program_info)

    # Parsing the command line
    if not parse_command_line(program_info):
        # There was a problem with the command line so exit
        print("Exiting...",file=sys.stderr)
        return

    # Set the file encoding for the training set
    # If NOT specified on the command line by the user run an autodetect
    if program_info['encoding'] is None:
        possible_file_encodings = []
        if not detect_file_encoding(program_info['training_file'], possible_file_encodings):
            ascii_fail()
            print("Exiting...")
            return

        program_info['encoding'] = possible_file_encodings[0]

    # Learn the alphabet if specified
    if program_info['learn_alphabet'] is not None:
        print('',file=sys.stderr)
        print('---Starting first pass through training set to learn the alphabet---',file=sys.stderr)
        print('',file=sys.stderr)

        # Open the training file IO for the first pass to learn the Alphabet
        try:
            input_dataset = TrainerFileIO(program_info['training_file'], program_info['encoding'])

        # Error opening the file for reading
        except Exception as msg:
            print(msg,file=sys.stderr)
            print("Error reading file " + program_info['training_file'], file=sys.stderr)
            ascii_fail()
            print("Exiting...")
            return

        # Initialize the alphabet generator
        ag = AlphabetGenerator(alphabet_size = program_info['learn_alphabet'], ngram = program_info['ngram'])

        # Now loop through all the passwords to get the character counts for the alphabet
        password = input_dataset.read_password()
        total_count = 0
        while password is not None:
            if total_count % 1000000 == 0 and total_count != 0:
                print(str(total_count//1000000) +' Million', file=sys.stderr)
            ag.process_password(password)
            password = input_dataset.read_password()
            total_count +=1

        # Sort and return the alphabet
        program_info['alphabet'] = ag.get_alphabet()

        # Saving this only for printing out the location of the alphabet file to console
        alphabet_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),'Rules',program_info['rule_name'],'alphabet.txt')
        print("Done learning alphabet", file=sys.stderr)
        print("Displaying learned alphabet to a console usually ends poorly for non-standard characters.", file=sys.stderr)
        print("If you want to review what the alphabet actually is you can view it at: " + alphabet_file, file=sys.stderr)

    else:
        print("Using Default Alphabet", file=sys.stderr)

    print("", file=sys.stderr)

    # Initialize lookup tables
    omen_trainer = AlphabetLookup(
        alphabet = program_info['alphabet'],
        ngram = program_info['ngram'],
        max_length = program_info['max_length']
        )

    # Initialize the trainer file io
    try:
        input_dataset = TrainerFileIO(program_info['training_file'], program_info['encoding'])

    # If an error ocurrs when opening the file for reading
    except Exception as msg:
        print (msg,file=sys.stderr)
        print ("Error reading file " + program_info['training_file'] ,file=sys.stderr)
        ascii_fail()
        print("Exiting...")
        return

    print("--Starting to parse passwords--",file=sys.stderr)
    print("Passwords parsed so far (in millions): ", file=sys.stderr)
    # Go through every password
    password = input_dataset.read_password()
    total_count = 0
    while password is not None:
        # Print out status info
        if total_count % 1000000 == 0 and total_count != 0:
            print(str(total_count//1000000) +' Million', file=sys.stderr)
        omen_trainer.parse(password)
        password = input_dataset.read_password()
        total_count +=1

    print()
    print("Done with intial parsing.", file=sys.stderr)
    print("Number of passwords trained on: " + str(total_count), file=sys.stderr)
    print("Number of file encoding errors = " + str(input_dataset.num_encoding_errors), file=sys.stderr)
    print()
    print("--Applying probability smoothing--", file=sys.stderr)

    omen_trainer.apply_smoothing()

    print("--Saving Results--", file=sys.stderr)

    # Save the results

    # Get the absolute path in case this program is run from another dirctory
    absolute_base_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)),'Rules', program_info['rule_name'])

    # This will be the config that is actually written to disk
    config_info = {
        'program_details':{
            'name':program_info['name'],
            'author':program_info['author'],
            'contact':program_info['contact'],
            'version': program_info['version'],
        },

        'training_settings': {
            'training_file':program_info['training_file'],
            'alphabet_encoding':program_info['encoding'],
            'ngram':program_info['ngram'],
            'max_level':10,
            'uuid':str(uuid.uuid4()),
        },
    }

    # Bundle everything to send to the "save_rules_to_disk" function
    save_info = {
        "rule_directory":absolute_base_directory,
        "ngrams":omen_trainer,
        }

    try:
        save_rules_to_disk(omen_trainer, save_info, config_info)

    except IOError as error:
        print ("Error saving rules", file=sys.stderr)
        print ("Error is " + str(error), file=sys.stderr)
        print ("The OMEN training data likely was not saved to disk", file=sys.stderr)
        return

    print()
    print("Done! Enjoy cracking passwords with OMEN!", file=sys.stderr)
    print("To use this training set to crack, make sure you use the following option in enumNG:", file=sys.stderr)
    print("    '-r " + program_info['rule_name'] + "'" , file=sys.stderr)


if __name__ == "__main__":
    main()
