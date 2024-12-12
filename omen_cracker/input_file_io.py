#############################################################################
# Reads in an OMEN ruleset from disk
#############################################################################

import sys
import os
import codecs
import configparser
from distutils.version import LooseVersion  #--Compare the trainer version used to generate the ruleset


###########################################################################
# Top level function that is called to read in the ruleset from disk
#
# Grammar is passed in as an empty dictionary
# Grammar is returned using the following format
# {
#   alphabet: ['a', 'b', 'c', ...],
#   alphabet_encoding:,'ascii',
#   version: '0.1',
#   ngram: 4,
#   max_level: 11,
#   uuid: 0afs-a23131...,
#   ln: {
#       0:[5, 7],
#       1:[1, 2],
#       ..
#   },
#   ip: {
#       0:['aaa','aab'],
#       1:['cab','qsq'],
#       ...
#   },
#   ep: { 'aaa': 0, 'aab': 4, ...},
#   cp: { 
#        'aaa':
#           {
#               0:['b','c'],
#               2:['d','e']
#               ...,
#        } },
# }
###########################################################################
def load_rules(base_directory, grammar, min_version=None):
    
    ##--Top level try statement for file errors, use this to catch all
    ##--read issues
    try:
        ##--Load the configuration
        _load_config(base_directory, "config.txt", grammar)
        
        ##--Check the version of the training set to make sure it is compatible
        if min_version != None:            
            if LooseVersion(grammar['version']) < LooseVersion(min_version):
                print("Error: The ruleset needs to be created by version " + min_version + " of the training program", file=sys.stderr)
                print("It is recommended that you re-train you ruleset using this version of createNG.py", file=sys.stderr)
                return False
                
        ##--Load the alphabet
        _load_alphabet(base_directory, "alphabet.txt", grammar)
        
        ##--Load the IP ngrams
        _load_ngrams(base_directory, "IP.level", grammar, "ip", grammar['ngram'] - 1)
        
        ##--Load the EP ngrams
        _load_ngrams(base_directory, "EP.level", grammar, "ep", grammar['ngram'] - 1)
        
        ##--Load the CP ngrams
        _load_ngrams(base_directory, "CP.level", grammar, "cp", grammar['ngram'])
        
        ##--Load the length info
        _load_length(base_directory, "LN.level", grammar, "ln", grammar['ngram'])        
                
    except Exception as msg:
        print(msg)
        return False
        
    return True
    

def _load_config(base_directory, filename, grammar):
    """
    Reads the config file in using configparser

    Inputs:
        base_directory: (String) The directory to load the config file from

        filename: (String) The name of the file to read in

        grammar: (Dict) The grammar to create from the config on disk

    Returns:
        None
    """
    try:
        # Combine the directory and filename to get the full file path
        full_file_path = os.path.join(base_directory, filename)
        
        # Create the configparser instance to process the config file
        config = configparser.ConfigParser()
        
        # Open up the config file
        config.read_file(open(full_file_path))
        
        grammar['version'] = config.get('program_details','version')
        grammar['alphabet_encoding'] = config.get('training_settings','alphabet_encoding')
        grammar['ngram'] = config.getint('training_settings','ngram')
        grammar['max_level'] = config.getint('training_settings','max_level')
        grammar['uuid'] = config.get('training_settings','uuid')
        
    except IOError as msg:
        print("Could not open the config file for the ruleset specified. The rule directory may not exist", file=sys.stderr)
        print("Filename: " + full_file_path, file=sys.stderr)
        raise
    except configparser.Error as msg:
        print("Error occured parsing the configuration file: " + str(msg),file=sys.stderr)
        raise

        
########################################################################################
# Loads the alphabet from file
# Make sure you call _load_config before this so that the alphabet_encoding is set
########################################################################################
def _load_alphabet(base_directory, filename, grammar):        
    try:
        full_file_path = os.path.join(base_directory, filename)
        grammar['alphabet'] = []
        ##--Using errors= 'strict' to throw an exception if we can't read any of the alphabet file
        ##--If that problem occurs, it strongly implies something happened during the training phase
        with codecs.open(full_file_path, 'r', encoding= grammar['alphabet_encoding'], errors= 'strict') as file:
            for line in file:
               grammar['alphabet'].append(line.rstrip('\n\r'))
               
    except IOError as msg:
        print("Could not open the config file for the ruleset specified. The rule directory may not exist", file=sys.stderr)
        print("Filename: " + full_file_path, file=sys.stderr)
        raise 
    except ValueError as msg:
        print("Error reading a character from the alphabet file")
        print("This implies there was some problem with a custom alphabet used during training")
        raise
  
  
########################################################################################
# Reads the probability info for ngrams
# Keeping this generic so it can read in IP, EP, and CP
#
# Needs to be called after the config file and alphabet have been parsed into grammar
#########################################################################################
def _load_ngrams(base_directory, filename, grammar, name, ngram_size):
    
    ##--Initialize the ngram dictionary
    grammar[name] = {}
    
    ##--For IP--##
    ##  Needs a bit more since we're indexing by level
    if name == "ip":
        for level in range(0,grammar['max_level']+1):
            grammar[name][level] = []      

    try:
        full_file_path = os.path.join(base_directory, filename)
        
        ##--Open the file for writing
        with open(full_file_path, 'r') as file:
            for line in file:
                line = line.rstrip('\n\r').split('\t')

                ##--If there wasn't a line to read. This indicates an error in the trianing file somewhere
                if len(line) != 2:
                    print("Error parsing " + full_file_path)
                    print("This indicates there was a problem with the training program or the file was corrupted somehow")
                    raise Exception
                    
                ##--Will throw a ValueError if not an int
                level = int(line[0])
                ##--Sanity check on the range the level falls in
                if level < 0 or level > grammar['max_level']:
                    print("Invalid level found parsing " + full_file_path)
                    print("Level = " + str(level))
                    print("This indicates there was a problem with the training program or the file was corrupted somehow")
                    raise Exception
                    
                ##--Save the level--##
                
                ##--For IP--##
                if name == "ip":
                    grammar[name][level].append(line[1])
                
                ##--For EP--##
                elif name == "ep":
                    grammar[name][line[1]] = level
                    
                ##--For CP--##
                elif name == "cp":
                    ##--Get all of the characters except the last character
                    search_string = line[1][0:-1]
                    if search_string not in grammar[name]:
                        grammar[name][search_string] = {}
                    if level not in grammar[name][search_string]:
                        grammar[name][search_string][level] = []
                        
                    grammar[name][search_string][level].append(line[1][-1])
                else:
                    print("Hmm that shouldn't happen. Hit an unexpected error with the function to load the rules")
               
    except IOError as msg:
        print("Could not open the config file for the ruleset specified. The rule directory may not exist", file=sys.stderr)
        print("Filename: " + full_file_path, file=sys.stderr)
        raise 
    except ValueError as msg:
        print("Error reading an item from the file: " + full_file_paht)
        print("This indicates there was a problem with the training program or the file was corrupted somehow")
        raise
    except Exception as msg:
        print("exception: " + str(msg))
        raise
        
########################################################################################
# Reads the probability info for guess length
#
# Needs to be called after the config file and alphabet have been parsed into grammar
#########################################################################################
def _load_length(base_directory, filename, grammar, name, min_size):
    
    ##--Initialize the level dictionary
    grammar[name] = {}
    for level in range(0,grammar['max_level']+1):
        grammar[name][level] = []
        
        
    try:
        full_file_path = os.path.join(base_directory, filename)
        
        ##--Open the file for writing
        with open(full_file_path, 'r') as file:
            ##--The length of the current item
            cur_length = 1
            
            ##--Read all of the lines in the file. Each one will be a new length level
            for line in file:
                
                ##--Will throw a ValueError if not an int
                level = int(line.rstrip('\n\r'))
                
                ##--Sanity check on the range the level falls in
                if level < 0 or level > grammar['max_level']:
                    print("Invalid level found parsing " + full_file_path)
                    print("Level = " + str(level))
                    print("This indicates there was a problem with the training program or the file was corrupted somehow", file=sys.stderr)
                    raise Exception
                    
                ##--Save the level
                ##  Don't save if the length is smaller than the mininum size for this ruleset
                if (cur_length >= min_size):
                    ##--Note, we're saving the number of Conditional Probability items that need to be applied
                    ##  to an IP, not the final guess length. This is to avoid having to recalculate that all the
                    ##  time during guess gneneration
                    grammar[name][level].append(cur_length - (min_size -1))
                
                ##--Increment cur_length for the next length
                cur_length += 1 
        
    except IOError as msg:
        print("Could not open the config file for the ruleset specified. The rule directory may not exist", file=sys.stderr)
        print("Filename: " + full_file_path, file=sys.stderr)
        raise 
    except ValueError as msg:
        print("Error reading an item from the file: " + full_file_paht)
        print("This indicates there was a problem with the training program or the file was corrupted somehow")
        raise
