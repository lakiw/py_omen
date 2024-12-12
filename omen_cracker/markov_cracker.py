#!/usr/bin/env python3

#########################################################################################################
# Brute force generation of password guesses using Markov probabilities to generate likely guesses first
# This uses the OMEN algorithm for generating guesses
##########################################################################################################


import sys
import os 
import random #--Used for honeywords
import pickle #--Used for saving sessions

from .guess_structure import GuessStructure
           

#########################################################################################################
# Contains all the logic for handling Markov guess generation
# Based on OMEN
#
# Seperating this out so it can be included in other programs like the PCFG password cracker
#########################################################################################################
class MarkovCracker:


    ############################################################################################
    # Initializes the cracker
    # If grammar is none, then the cracker will basically act as a noop
    ############################################################################################
    def __init__(self, grammar, version, base_directory, session_name, rule_name, uuid, optimizer = None, restore = False):
        
        ##--Store the ruleset
        self.grammar = grammar
        
        ##--Save the optimizer
        self.optimizer = optimizer
        
        ##--This is the maximum level an item can be
        self.max_level = grammar['max_level']
        
        ##--The version that this is running, used for saving/loading files
        self.version = version
        
        ##--The rule name this is running on, used for saving/loading files
        self.rule_name = rule_name
        
        ##--The UUID of the rule file to make sure re-training didn't happen between save and restore
        self.uuid = uuid
        
        ##--Where to save the save file
        self.full_save_file_path = os.path.join(base_directory, session_name + '.sav')
        
        ##--The length of initial prob items, saving it so we don't constantly
        ##  have to calculate ngram - 1
        self.length_ip = grammar['ngram'] - 1
        
        ##--The first valid IP pointer
        self.start_ip = self._find_first_object(self.grammar['ip'])     
         
        ##--The first valid length pointer
        self.start_length = self._find_first_object(self.grammar['ln'])
        
        ##--If Starting From Scratch --##
        if not restore:
        
            ##--This is the target total level we are looking for
            self.target_level = None
            
            ##--If it should increase the target level or not
            self.increase_target_level = False      
            
            ##--The current length pointer
            self.cur_len = None
            
            ##--The current IP pointer
            self.cur_ip = None
            
            ##--The current guess structure
            self.cur_guess = None
        
        ##--Restore a session from disk
        else:
            self.load_session()
    
    ###############################################################################################
    # Finds the first valid IP or Length object
    # Throws exception if there is no valid items
    ################################################################################################
    def _find_first_object(self, lookup_table):
        for level in range(0,self.max_level):
            if len(lookup_table[level]) != 0:
                return level
        print("Either the IP or LN is not valid, please report this bug on the github page", file=sys.stderr)
        raise Exception
    
    
    ###############################################################################################
    # Generates the "next" guess from this model
    # Will return None when no more guesses are left to be created
    # After that, it will "reset" so if you call it again it will start looping over the same guesses
    ###############################################################################################
    def next_guess(self, level = None):
        
        ##--Deal with starting off the Markov chain
        if self.cur_guess == None:
            ##--Check to see if it should loop through all the levels automatically
            if level == None:
                self.increase_target_level = True
                ##--Might as well initialize the target level to be the lowest possible level
                self.target_level = self.start_length + self.start_ip               
                
            ##--Only generate guesses for the current level
            else:
                ##--Quick bail out if the target level is too low to generate any guesses
                if self.start_length + self.start_ip > level:
                    return None
                self.increase_target_level = False
                self.target_level = level                            
        
            ##--Set the starting IP and Length--
            self.cur_len = [self.start_length, 0]
            self.cur_ip  = [self.start_ip, 0]   
        
            ##--Create the guess structure        
            self.cur_guess = GuessStructure(
                max_level = self.max_level,
                cp = self.grammar['cp'], 
                ip = self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],
                cp_length = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]],
                target_level = self.target_level  - self.cur_len[0] - self.cur_ip[0],
                optimizer = self.optimizer,
                )

        ##--Grab the next guess for the current length and current target        
        guess =  self.cur_guess.next_guess()        

        ##--If guess is None, then there isn't a guess for the current length so increase the length if possible
        while guess == None:
            
            ##--Attempt to increase the IP for the curent target level + length
            if not self._increase_ip_for_target(working_target = self.target_level - self.cur_len[0]):
                #print(f"CHECKPASSDEBUG Level:{self.target_level}")    
                ##--Attempt to increase the length for the current target level
                if not self._increase_len_for_target():
                    ##--If we can't, then check if we can increase the target level
                    ##  Reset the length and IP back to the starting locations
                    if self.increase_target_level == True:
                        self.target_level += 1
                        self.cur_len = [self.start_length, 0]
                        self.cur_ip  = [self.start_ip, 0]  
                        ##--Create the guess structure
                        self.cur_guess = GuessStructure(
                            cp = self.grammar['cp'],
                            max_level = self.max_level,
                            ip = self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],
                            cp_length = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]],
                            target_level = self.target_level - self.cur_len[0] - self.cur_ip[0],
                            optimizer = self.optimizer,
                            )
                    
                    ##--Done with all password guesses for this level, and can't increase level, exit
                    else:
                        self.cur_guess = None
                        return None

            # print(str(self.target_level) + " : " + str(self.cur_len) + " : " + str(self.cur_ip))      
            guess =  self.cur_guess.next_guess()
            #print("level: " + str(self.target_level) + " length = " + str(self.cur_len) + " ip " + str(self.cur_ip))
            
        return guess, self.target_level
            
    
    ###############################################################################################
    # Increases the length for the current target level
    # Returns False if it was unsucessful
    # FYI Should always return True if target level > max_level
    ###############################################################################################
    def _increase_len_for_target(self):
        level = self.cur_len[0]
        index = self.cur_len[1] + 1
        
        ln = self.grammar['ln']
        
        ##--Loop through all the valid levels left
        while level <= self.max_level:
            
            ##--Check to see if there is a length option for the current level
            size = len(ln[level])
            if size > index:
                
                ##--Save the new length pointer
                self.cur_len = [level, index]
                
                ##--Reset the current IP
                self.cur_ip  = [self.start_ip, 0]  
                
                ##--Reset the current guess
                self.cur_guess = GuessStructure(
                    cp = self.grammar['cp'],
                    max_level = self.max_level,                    
                    ip = self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],
                    cp_length = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]],
                    target_level = self.target_level  - self.cur_len[0] - self.cur_ip[0],
                    optimizer = self.optimizer,
                    )
                return True
            
            ##--No valid items at this level, check if we can go up a level
            level += 1
            index = 0
            if level > self.max_level:
                return False
            elif level > self.target_level:
                return False
                      
        
    ###############################################################################################
    # Increases the IP for the current target level
    # Returns False if it was unsucessful
    ###############################################################################################
    def  _increase_ip_for_target(self, working_target = 0):
        level = self.cur_ip[0]
        index = self.cur_ip[1] + 1
        
        ip = self.grammar['ip']
        
        ##--Loop through all the valid levels left
        while level <= self.max_level:
            
            ##--Check to see if there is a IP option for the current level
            size = len(ip[level])
            if size > index:
                
                ##--Save the new IP pointer
                self.cur_ip = [level, index]
                          
                ##--Reset the current guess
                self.cur_guess = GuessStructure(
                    cp = self.grammar['cp'],
                    max_level = self.max_level,                      
                    ip = self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],
                    cp_length = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]],
                    target_level = self.target_level - self.cur_len[0] - self.cur_ip[0],
                    optimizer = self.optimizer,
                    )
                return True
            
            ##--No valid items at this level, check if we can go up a level
            level += 1
            index = 0
            if level > self.max_level:
                return False
            elif level > working_target:
                return False
       
    
    #########################################################################################################
    # Used for debugging, will print out the parse tree for an input string
    #########################################################################################################
    def parse_input(self, guess):
        
        ##--Parse length
        check_len = len(guess) - self.length_ip
        for i in range(0,self.max_level):
            if check_len in self.grammar['ln'][i]:
                print("Length: " + str(len(guess)) + " Level: " + str(i))
                break
                
        ##--Parse IP
        ip = guess[0:self.length_ip]
        for i in range(0,self.max_level):
            if ip in self.grammar['ip'][i]:
                print("IP: " + ip + " Level: " + str(i))
                break
        
        ##--Parse CP
        loop_count = len(guess) - self.length_ip
        for i in range (0,loop_count):
            cp = self.grammar['cp'][guess[i:i+self.length_ip]]
            for level in cp:
                if guess[i+self.length_ip] in cp[level]:
                    print(guess[i+self.length_ip] + " : " + str(level))
                    break
                          
    
    ####################################################################################################################
    # Saves a cracking session to disk
    # Note: Using python pickles just to make coding it easier
    #       Of course that makes debugging harder, and the overall saving slower though. 
    #       May move away from this in the future
    ####################################################################################################################
    def save_session(self):
        with open(self.full_save_file_path, 'wb') as file:
            ##--Save the level, rule, and uuid info for sanity checking when starting up again
            pickle.dump(self.version, file)
            pickle.dump(self.rule_name, file)
            pickle.dump(self.uuid, file)
            
            ##--Save the Markov Cracker variables here
            pickle.dump(self.target_level, file)
            pickle.dump(self.increase_target_level, file)          
            pickle.dump(self.cur_ip, file)
            pickle.dump(self.cur_len, file)
            
            ##--Save the guess structure variables here, not saving the full guess structure since it
            ##  includes a link to the grammar itself.
            pickle.dump(self.cur_guess.parse_tree, file)
            pickle.dump(self.cur_guess.first_guess, file)
            
    
    ###############################################################################################################
    # Restores a session from disk
    ###############################################################################################################    
    def load_session(self):
        with open(self.full_save_file_path, 'rb') as file:
            
            ##--Load the version and rule name to make sure the save file is compatible with this programs
            version = pickle.load(file)
            rule_name = pickle.load(file)
            uuid = pickle.load(file)
            
            ##--Perform sanity checks to make sure the rule name, uuid, and version are the same
            if (version != self.version):
                print("Saved file created using a different version of enumNG.py", file=sys.stderr)
                print("Current version of this program: " + str(self.version),file=sys.stderr)
                print("Version that this save file was created with: " + str(version),file=sys.stderr)
                print("", file=sys.stderr)
                print("Due to the beta nature of this program, currently there is ", file=sys.stderr)
                print("no backwards compatability support for loading save files", file=sys.stderr)
                print("created using previous versions of this program", file=sys.stderr)
                print("", file=sys.stderr)
                raise Exception
            
            if (rule_name != self.rule_name):
                print("Make sure you specify the same rule name you created the save file with", file=sys.stderr)
                print("Current Ruleset Name: " + str(self.rule_name),file=sys.stderr)
                print("Save File Ruleset Name: " + str(rule_name), file=sys.stderr)
                print("", file=sys.stderr)
                print("Re-run enumNG.py with the save file ruleset", file=sys.stderr)
                print("I know, this could be automated to make it easier. It's on my todo list.", file=sys.stderr)
                print("", file=sys.stderr)
                raise Exception
            
            if (uuid != self.uuid):
                print("It appears you re-trained the ruleset that the save file used", file=sys.stderr)
                print("Ruleset Name: " + str(self.rule_name),file=sys.stderr)
                print("Current UUID of Ruleset: " + str(self.uuid), file=sys.stderr)
                print("UUID of Saved Session: " + str(uuid), file=sys.stderr)
                print("", file=sys.stderr)
                print("This program will likely not behave correctly if it tries to restore the session", file=sys.stderr)
                print("with the new ruleset", file=sys.stderr)
                print("", file=sys.stderr)
                raise Exception
            
            ##--Reset the options for the Markov Cracker
            self.target_level = pickle.load(file)
            self.increase_target_level = pickle.load(file)           
            self.cur_ip = pickle.load(file)
            self.cur_len = pickle.load(file)
            
            ##--Reset the current guess
            parse_tree = pickle.load(file)
            first_guess = pickle.load(file)
               
            self.cur_guess = GuessStructure(
                cp = self.grammar['cp'],
                max_level = self.max_level,                      
                ip = self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],
                cp_length = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]],
                target_level = self.target_level - self.cur_len[0] - self.cur_ip[0]
                )    
        
            self.cur_guess.parse_tree = parse_tree
            self.cur_guess.first_guess = first_guess