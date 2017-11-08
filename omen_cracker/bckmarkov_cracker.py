#!/usr/bin/env python3

#########################################################################################################
# Brute force generation of password guesses using Markov probabilities to generate likely guesses first
# This uses the OMEN algorithm for generating guesses
##########################################################################################################


import sys
import os 
import random #--Used for honeywords

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
    def __init__(self, grammar = None):
        
        ##--Store the ruleset
        self.grammar = grammar
        
        ##--This is the maximum level an item can be
        self.max_level = grammar['max_level']
        
        ##--This is the target total level we are looking for
        self.target_level = None
        
        ##--If it should increase the target level or not
        self.increase_target_level = False
        
        ##--Used to say that there are no more guesses to generate
        ##  Initialized to True so it will start looping through the guesses again
        self.done = True
         
        ##--The length of initial prob items, saving it so we don't constantly
        ##  have to calculate ngram - 1
        self.length_ip = grammar['ngram'] - 1
         
        ##--The first valid length pointer
        self.start_length = self._find_first_object(self.grammar['ln'])

        ##--The first valid IP pointer
        self.start_ip = self._find_first_object(self.grammar['ip'])     
        
        ##--The current length pointer
        self.cur_len = None
        
        ##--The current IP pointer
        self.cur_ip = None
        
        ##--The current guess structure
        self.cur_guess = None
         
    
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
        if self.done == True:
            ##--Check to see if it should loop through all the levels automatically
            if level == None:
                self.increase_target_level = True
                ##--Might as well initialize the target level to be the lowest possible level
                self.target_level = self.start_length + self.start_ip
                self.done = False
                
                self.cur_len = [self.start_length, 0]
                self.cur_ip  = [self.start_ip, 0]
                
            ##--Only generate guesses for the current level
            else:
                ##--Quick bail out if the target level is too low to generate any guesses
                if self.start_length + self.start_ip > level:
                    return None
                self.increase_target_level = False
                self.target_level = level
                self.done = False        

                self.cur_len = [self.start_length, 0]
                self.cur_ip  = [self.start_ip, 0]                
        
        ##--Grab the next guess for the current length and current target        
        guess =  self._gen_next_guess_for_length_target()

        ##--If guess is None, then there isn't a guess for the current length so increase the length if possible
        while guess == None:
            
            ##--Attempt to increase the length for the current target level
            if not self._increase_len_for_target():
                
                ##--If we can't, then check if we can increase the target level
                ##  Reset the length and IP back to the starting locations
                if self.increase_target_level == True:
                    self.target_level += 1
                    self.cur_len = [self.start_length, 0]
                    self.cur_ip  = [self.start_ip, 0]  
                    
                ##--Done with all password guesses for this level, and can't increase level, exit
                else:
                    self.done = True
                    return None
                   
            ##--Grab the next guess for the current length and current target        
            guess =  self._gen_next_guess_for_length_target()
            
        return guess
            
    
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
                self.cur_guess = None
                return True
            
            ##--No valid items at this level, check if we can go up a level
            level += 1
            index = 0
            if level > self.max_level:
                return False
            elif level > self.target_level:
                return False
                
    
    ###############################################################################################
    # Generates the next guess for the current length
    # Returns None if there are no more guesses to generate for the current length
    ###############################################################################################
    def _gen_next_guess_for_length_target(self):      
        
        ##--There isn't a current guess ready   
        if self.cur_guess == None:
            working_target = self.target_level - self.cur_len[0] - self.cur_ip[0]
            guess = self._create_guess_for_target(
                working_target = working_target,
                working_guess = [[self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],None]],
                target_len = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]] - self.length_ip
                )
            
            ##--No guess for this IP + len + target level
            while guess == None:
                ##--Increment the IP
                working_target = self.target_level - self.cur_len[0]
                if self._increase_ip_for_target(working_target = working_target):
                    
                    working_target = self.target_level - self.cur_len[0] - self.cur_ip[0]
                    guess = self._create_guess_for_target(
                        working_target = working_target, 
                        working_guess = [[self.grammar['ip'][self.cur_ip[0]][self.cur_ip[1]],None]],
                        target_len = self.grammar['ln'][self.cur_len[0]][self.cur_len[1]] - self.length_ip
                        )
               
                ##--Can't increase the IP for the current target level, back out of this length
                else:
                    return None
            
            ##--We have our first guess, return it
            return guess
        
        ##--Increament the guesses for this IP
        return None
        
        
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
                self.cur_guess = None
                return True
            
            ##--No valid items at this level, check if we can go up a level
            level += 1
            index = 0
            if level > self.max_level:
                return False
            elif level > working_target:
                return False
       
    