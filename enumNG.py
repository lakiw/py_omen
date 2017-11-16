#!/usr/bin/env python3

########################################################################################
#
# Name: enumNG
#  --OMEN guess generation program
#  --(O)rdered (M)arkov (EN)umerator
#  -- Generates password guesses based on the conditional probabilty of passwords appearing together
#
#  Written by Matt Weir
#  Backend algorithm based on the work done https://github.com/RUB-SysSec/OMEN
#  Document describing the approach: https://hal.archives-ouvertes.fr/hal-01112124/file/omen.pdf
#  An even better document describing this: http://mobsec.rub.de/media/mobsec/arbeiten/2014/12/12/2013-ma-angelstorf-omen.pdf
#  
#
#  The MIT License (MIT)
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#
#
#  Contact Info: cweir@vt.edu
#
#  enumNG.py
#
#########################################################################################


##--Including this to print error message if python < 3.0 is used
from __future__ import print_function
import sys
###--Check for python3 and error out if not--##
if sys.version_info[0] < 3:
    print("This program requires Python 3.x", file=sys.stderr)
    sys.exit(1)
    
import argparse
import os  ##--Used for file path information
import configparser

import time ##--Used for testing

#Custom modules
from omen_cracker.input_file_io import load_rules
from omen_cracker.markov_cracker import MarkovCracker
from omen_cracker.optimizer import Optimizer
  
####################################################
# Parses the command line
####################################################
def parse_command_line(runtime_options):
    parser = argparse.ArgumentParser(description='OMEN Guess Generator: Creates password guesses')
    
    parser.add_argument('--rule','-r', help='Name of ruleset to use. Default is ' + 
        '[' + runtime_options['rule_name'] + ']',
        metavar='RULESET_NAME', required=False, default=runtime_options['rule_name'])
        
    parser.add_argument('--session','-s', help='Session name for saving/restarting a session. Default is ' + 
        '[' + runtime_options['session_name'] + ']',
        metavar='SESSION_NAME', required=False, default=runtime_options['session_name'])
        
    parser.add_argument('--restore', help='Restore the previous cracking session specified in the "--session" option',
        dest='restore', action='store_const', const = not runtime_options['restore'])
        
    parser.add_argument('--debug','-d', help='Print debugging info vs password guesses',
        dest='debug', action='store_const', const= not runtime_options['debug'])
        
    parser.add_argument('--test','-t', help='For debugging. Allows you to type in a password and will print out parse info for it',
        dest='test', action='store_const', const = not runtime_options['test'])
        
    parser.add_argument('--max_guesses','-m', help='Set a maximum number of guesses ',
        dest='max_guesses', metavar='NUM_GUESSES', required=False, type=int, default=-1)
    
    try:
        args=parser.parse_args()
        
        ##Ruleset Name
        runtime_options['rule_name'] = args.rule
        runtime_options['debug'] = args.debug
        runtime_options['test'] = args.test
        runtime_options['session_name'] = args.session
        runtime_options['restore'] = args.restore
        runtime_options['max_guesses'] = args.max_guesses

    except Exception as msg:
        print(msg, file=sys.stderr)
        return False
    except SystemExit:
        return False

    return True 

    
###################################################################################
# Prints the startup banner when this tool is run
###################################################################################
def print_banner(program_details):
    print('',file=sys.stderr)
    print (program_details['program'] + " Version " + program_details['version'], file=sys.stderr)
    print ("This version written by " + program_details['author'], file=sys.stderr)
    print ("Original version writtem by the Horst Goertz Institute for IT-Security", file=sys.stderr)
    print ("Sourcecode available at " + program_details['source'], file=sys.stderr)
    print('',file=sys.stderr)  


####################################################################################
# ASCII art for displaying an error state before quitting
####################################################################################
def print_error():
    print('',file=sys.stderr)
    print('An error occured, shutting down',file=sys.stderr)
    print('',file=sys.stderr)
    print(r' \__/      \__/      \__/      \__/      \__/      \__/          \__/',file=sys.stderr)
    print(r' (oo)      (o-)      (@@)      (xx)      (--)      (  )          (OO)',file=sys.stderr)
    print(r'//||\\    //||\\    //||\\    //||\\    //||\\    //||\\        //||\\',file=sys.stderr)
    print(r'  bug      bug       bug/w     dead      bug       blind      bug after',file=sys.stderr)
    print(r'         winking   hangover    bug     sleeping    bug     whatever you did',file=sys.stderr)
    print('',file=sys.stderr)

    
###################################################################################
# ASCII art for more generic failure
###################################################################################
def ascii_fail():
    print("                                          __ ",file=sys.stderr)
    print("                                      _  |  |",file=sys.stderr)
    print("                  Yye                |_| |--|",file=sys.stderr)
    print("               .---.  e           AA | | |  |",file=sys.stderr)
    print("              /.--./\  e        A",file=sys.stderr)
    print("             // || \/\  e      ",file=sys.stderr)
    print("            //|/|| |\/\   aa a    |\o/ o/--",file=sys.stderr)
    print("           ///|\|| | \/\ .       ~o \.'\.o'",file=sys.stderr)
    print("          //|\|/|| | |\/\ .      /.` \o'",file=sys.stderr)
    print("         //\|/|\|| | | \/\ ( (  . \o'",file=sys.stderr)
    print("___ __ _//|/|\|/|| | | |\/`--' '",file=sys.stderr)
    print("__/__/__//|\|/|\|| | | | `--'",file=sys.stderr)
    print("|\|/|\|/|\|/|\|/|| | | | |",file=sys.stderr)
    print("",file=sys.stderr)
    
  
##################################################################
# Main function
##################################################################
def main():
    
    management_vars = {
        ##--Information about this program--##
        'program_details':{
            'program':'enumNG.py',
            'version': '0.1',
            'author':'Matt Weir',
            'contact':'cweir@vt.edu',
            'source':'https://github.com/lakiw/py_omen'
        },
        ##--Runtime specific values, can be overriden via command line options
        'runtime_options':{
 
            ##Rule Name
            'rule_name':'Default',
            
            ##If we are doing debugging by default or not
            'debug':False,
            
            ##Additional debuging by allowing the user to enter in passwords to be parsed
            'test':False,
            
            ##Session name for saving/restarting a session
            'session_name':'default',
            
            ##If we are restoring a session vs starting a new one
            'restore':False,
            
            ##Maximum number of guesses, if negative ignore
            'max_guesses':-1,

        }
    }  
    
    ##--Print out banner
    print_banner(management_vars['program_details'])
    
    ##--Parse the command line ---##
    command_line_results = management_vars['runtime_options']
    if parse_command_line(command_line_results) != True:
        return
        
    ##--Load the RuleSet ---##
    absolute_base_directory = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),'Rules',command_line_results['rule_name']
        )
    
    ##--Dictionary that will contain the grammar
    grammar = {}
     
    ##--Actually load the ruleset here
    print("loading ruleset: " + command_line_results['rule_name'],file=sys.stderr)
    if not load_rules(absolute_base_directory, grammar, min_version=management_vars['program_details']['version']):
        print("Error reading the ruleset, exiting", file=sys.stderr)
        ascii_fail()
        return
    
    ##--Initialize the TMTO optimizer
    optimizer = Optimizer(max_length = 4)
    
    ##--Initialize the Markov Cracker 
    try:    
        cracker = MarkovCracker(
            grammar = grammar, 
            version = management_vars['program_details']['version'], 
            base_directory = os.path.dirname(os.path.realpath(__file__)), 
            session_name = command_line_results['session_name'],
            rule_name = command_line_results['rule_name'],
            uuid = grammar['uuid'],
            optimizer = optimizer,
            restore = command_line_results['restore'],   
            )  
    except:
        print("Error loading the save file, exiting", file=sys.stderr)
        ascii_fail()
        return
    
    ##--If there is debugging going on for parsing user supplied strings
    if command_line_results['test']:
        while True:
            guess = input("Enter string to parse:")
            cracker.parse_input(guess)
        
    ##--Start generating guesses
    print("--Starting to generate guesses-- ",file=sys.stderr)
    try:
 
        start_time = time.clock()
        num_guesses = 0
        
        guess, level = cracker.next_guess()
        while guess != None:
            num_guesses += 1
            if command_line_results['debug']:
                if num_guesses % 100000 == 0:
                    elapsed_time = time.clock() - start_time
                    print()
                    print("guesses: " + str(num_guesses))
                    print("level: " + str(level))
                    print("guesses a second: " + str(num_guesses / elapsed_time))
            else:
                if num_guesses % 1000000 == 0:
                    cracker.save_session()
                #guess = guess + '\n'
                #guess = guess.encode('utf-8')
                #sys.stdout.buffer.write(guess)
                #sys.stdout.flush()
                print(guess)
                #input("hit enter")
                
            if command_line_results['max_guesses'] > 0 and num_guesses >= command_line_results['max_guesses']:
                break
            guess, level = cracker.next_guess()
            
    except (KeyboardInterrupt, BrokenPipeError) as e:
        print("Halting guess generation based on Ctrl-C being detected",file=sys.stderr)
        cracker.save_session()
    
    print('', file=sys.stderr)    
    print("--Done generating guesses-- ",file=sys.stderr)

        

if __name__ == "__main__":
    main()