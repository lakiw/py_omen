#############################################################################
# Contains OMEN specific file IO functions to save training data to disk
#############################################################################

import sys
import os
import configparser
import codecs

from .common_file_io import make_sure_path_exists

#################################################################################
# Main function called to save all of the data to disk
#
#################################################################################
def save_rules_to_disk(omen_trainer, save_info, config_info):
    
    encoding = config_info['training_settings']['alphabet_encoding']
    
    ##--Create the rule directory if it does not exist already
    try:
        make_sure_path_exists(save_info["rule_directory"])
    
    ##--Print out where the error occured, but then re-raise it for the calling function
    ##--to inform the user that the rules will not be saved
    except Exception as msg:
        print (msg)
        print("Error creating the rules directory " + save_info["rule_directory"])
        raise
    
    ##--Save the IP ngrams to disk
    ##--Open the file for writing--##
    full_path = os.path.join(save_info["rule_directory"], "IP.level")
    try:
        with codecs.open(full_path, 'w', encoding=encoding) as file:
            ##--Loop through the top (ngram-1) list that has IP
            for key, data in omen_trainer.grammar.items():
                file.write(str(data['ip_level'])+ "\t" + key + "\n")             
    ##--Print out where the error occured, but then re-raise it for the calling function
    ##--to inform the user that the rules will not be saved
    except:
        print("Error creating the rules file: " + full_path)
        raise 
        
    ##--Save the EP ngrams to disk
    ##--Open the file for writing--##
    full_path = os.path.join(save_info["rule_directory"], "EP.level")
    try:
        with codecs.open(full_path, 'w', encoding=encoding) as file:
            ##--Loop through the top (ngram-1) list that has IP
            for key, data in omen_trainer.grammar.items():
                file.write(str(data['ep_level'])+ "\t" + key + "\n")    
    ##--Print out where the error occured, but then re-raise it for the calling function
    ##--to inform the user that the rules will not be saved
    except:
        print("Error creating the rules file: " + full_path)
        raise 
        
    ##--Save the CP ngrams to disk
    ##--Open the file for writing--##
    full_path = os.path.join(save_info["rule_directory"], "CP.level")
    try:
        with codecs.open(full_path, 'w', encoding=encoding) as file:
            ##--Loop through the top (ngram-1) list that has IP
            for key, data in omen_trainer.grammar.items():
                ##--Loop through all of the final letter transitions
                for last_letter, level in data['next_letter'].items():
                    file.write(str(level[0]) + "\t" + key + last_letter +  "\n")                    
    ##--Print out where the error occured, but then re-raise it for the calling function
    ##--to inform the user that the rules will not be saved
    except:
        print("Error creating the rules file: " + full_path)
        raise 
        
    ##--Save the Length info to disk
    ##--Open the file for writing--##
    full_path = os.path.join(save_info["rule_directory"], "LN.level")
    try:
        with open(full_path, 'w') as file:
            ##--Loop through the length list
            for length, count in enumerate(omen_trainer.ln_lookup):
                print("PW Length " +str(length + 1) + " : " + str(count[1]))           
                file.write(str(count[0]) + "\n")  
                
    ##--Print out where the error occured, but then re-raise it for the calling function
    ##--to inform the user that the rules will not be saved
    except:
        print("Error creating the rules file: " + full_path)
        raise 
        
    ##--Save the config file
    _save_config(
        file_name= "config.txt",
        directory= save_info["rule_directory"],
        config_info = config_info,
        )
        
    ##--Save the alphabet file
    _save_alphabet(
        file_name= "alphabet.txt",
        directory= save_info["rule_directory"],
        alphabet = omen_trainer.alphabet,
        encoding = encoding
        )
    
    return   
       
    
############################################################################################
# Saves the main config file for this ruleset to disk
############################################################################################
def _save_config(file_name, directory, config_info):

    config = configparser.ConfigParser()
    
    ##--Set up the config to contain all the data saved in config_info--##
    ##--Establish the top level sections
    for section in config_info:
        config.add_section(section)
        ##--Add the individual keys for that section
        for key in config_info[section]:
            config.set(section, key, str(config_info[section][key]))
        
    ##--Save the config file--##
    try:
        full_path = os.path.join(directory, file_name) 
        with open(full_path, 'w') as configfile:
            config.write(configfile)    
    except IOError as msg:
        print("Error writing config file :" + str(msg))
        raise


###############################################################################################
# Saves the alphabet file to disk
# One letter per line
# Doing this so we can support different character encodings and multi-character sets
################################################################################################
def _save_alphabet(file_name, directory, alphabet, encoding):
    try:
        full_path = os.path.join(directory, file_name) 
        with codecs.open(full_path, 'w', encoding=encoding) as alphafile:
            for item in alphabet:
                alphafile.write(item+'\n')
    except IOError as error:
        print (error)
        print ("Error opening file " + str(full_path))
        raise